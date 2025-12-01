/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: Copyright (c) 2025 Mohamed Elmoncef HAMDI
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "xml_sanitize_internal.h"
#include <stdio.h>
#include <ctype.h>
#include <strings.h>

static const char* error_messages[] = {
    [XML_SAN_OK] = "Success",
    [XML_SAN_ERR_NULL_PTR] = "Null pointer argument",
    [XML_SAN_ERR_INVALID_INPUT] = "Invalid input",
    [XML_SAN_ERR_PARSE_FAILED] = "XML parsing failed",
    [XML_SAN_ERR_MEMORY] = "Memory allocation failed",
    [XML_SAN_ERR_BACKEND_INIT] = "Backend initialization failed",
    [XML_SAN_ERR_NO_BACKEND] = "No backend available",
    [XML_SAN_ERR_BUFFER_TOO_SMALL] = "Buffer too small",
    [XML_SAN_ERR_INVALID_UTF8] = "Invalid UTF-8 encoding",
    [XML_SAN_ERR_UNKNOWN] = "Unknown error"
};

static const xml_san_backend_ops_t* backends[] = {
#ifdef XML_SAN_HAVE_LIBXML2
    [XML_SAN_BACKEND_LIBXML2] = &xml_san_backend_libxml2,
#else
    [XML_SAN_BACKEND_LIBXML2] = NULL,
#endif
#ifdef XML_SAN_HAVE_SCEW
    [XML_SAN_BACKEND_SCEW] = &xml_san_backend_scew,
#else
    [XML_SAN_BACKEND_SCEW] = NULL,
#endif
#ifdef XML_SAN_HAVE_EXPAT
    [XML_SAN_BACKEND_EXPAT] = &xml_san_backend_expat,
#else
    [XML_SAN_BACKEND_EXPAT] = NULL,
#endif
#ifdef XML_SAN_HAVE_MXML
    [XML_SAN_BACKEND_MXML] = &xml_san_backend_mxml,
#else
    [XML_SAN_BACKEND_MXML] = NULL,
#endif
#ifdef XML_SAN_HAVE_YXML
    [XML_SAN_BACKEND_YXML] = &xml_san_backend_yxml,
#else
    [XML_SAN_BACKEND_YXML] = NULL,
#endif
#ifdef XML_SAN_HAVE_EZXML
    [XML_SAN_BACKEND_EZXML] = &xml_san_backend_ezxml,
#else
    [XML_SAN_BACKEND_EZXML] = NULL,
#endif
#ifdef XML_SAN_HAVE_ROXML
    [XML_SAN_BACKEND_ROXML] = &xml_san_backend_roxml,
#else
    [XML_SAN_BACKEND_ROXML] = NULL,
#endif
    [XML_SAN_BACKEND_CUSTOM] = &xml_san_backend_custom,
};

/*
 * Buffer management
 */
int xml_san_buffer_init(xml_san_buffer_t* buf, size_t initial_capacity) {
    if(!buf) {
        return -1;
    }

    buf->data = malloc(initial_capacity);
    if(!buf->data) {
        return -1;
    }

    buf->len = 0;
    buf->capacity = initial_capacity;
    buf->data[0] = '\0';
    return 0;
}

void xml_san_buffer_cleanup(xml_san_buffer_t* buf) {
    if(buf && buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->len = 0;
        buf->capacity = 0;
    }
}

static int xml_san_buffer_grow(xml_san_buffer_t* buf, size_t needed) {
    if(buf->len + needed + 1 <= buf->capacity) {
        return 0;
    }

    size_t new_cap = buf->capacity * 2;
    while(new_cap < buf->len + needed + 1) {
        new_cap *= 2;
    }

    char* new_data = realloc(buf->data, new_cap);
    if(!new_data) {
        return -1;
    }

    buf->data = new_data;
    buf->capacity = new_cap;
    return 0;
}

int xml_san_buffer_append(xml_san_buffer_t* buf, const char* data, size_t len) {
    if(!buf || !data) {
        return -1;
    }

    if(xml_san_buffer_grow(buf, len) != 0) {
        return -1;
    }

    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    buf->data[buf->len] = '\0';
    return 0;
}

int xml_san_buffer_append_char(xml_san_buffer_t* buf, char c) {
    return xml_san_buffer_append(buf, &c, 1);
}

int xml_san_buffer_append_str(xml_san_buffer_t* buf, const char* str) {
    if(!str) {
        return -1;
    }
    return xml_san_buffer_append(buf, str, strlen(str));
}

char* xml_san_buffer_detach(xml_san_buffer_t* buf, size_t* len) {
    if(!buf) {
        return NULL;
    }

    char* data = buf->data;
    if(len) {
        *len = buf->len;
    }

    buf->data = NULL;
    buf->len = 0;
    buf->capacity = 0;
    return data;
}

/*
 * UTF-8 validation
 */
int xml_san_utf8_validate(const char* str, size_t len) {
    const unsigned char* p = (const unsigned char*) str;
    const unsigned char* end = p + len;

    while(p < end) {
        if(*p < 0x80) {
            p++;
        } else if((*p & 0xE0) == 0xC0) {
            if((p + 1 >= end) || ((p[1] & 0xC0) != 0x80)) {
                return -1;
            }
            p += 2;
        } else if((*p & 0xF0) == 0xE0) {
            if((p + 2 >= end) || ((p[1] & 0xC0) != 0x80) || ((p[2] & 0xC0) != 0x80)) {
                return -1;
            }
            p += 3;
        } else if((*p & 0xF8) == 0xF0) {
            if((p + 3 >= end) || ((p[1] & 0xC0) != 0x80) ||
               ((p[2] & 0xC0) != 0x80) || ((p[3] & 0xC0) != 0x80)) {
                return -1;
            }
            p += 4;
        } else {
            return -1;
        }
    }
    return 0;
}

size_t xml_san_utf8_fix(const char* input, size_t input_len,
                        char* output, size_t output_size) {
    const unsigned char* p = (const unsigned char*) input;
    const unsigned char* end = p + input_len;
    size_t out_pos = 0;

    while(p < end && out_pos < output_size - 1) {
        if(*p < 0x80) {
            output[out_pos++] = *p++;
        } else if(((*p & 0xE0) == 0xC0) && (p + 1 < end) && ((p[1] & 0xC0) == 0x80)) {
            if(out_pos + 2 <= output_size - 1) {
                output[out_pos++] = *p++;
                output[out_pos++] = *p++;
            } else {
                break;
            }
        } else if(((*p & 0xF0) == 0xE0) && (p + 2 < end) &&
                  ((p[1] & 0xC0) == 0x80) && ((p[2] & 0xC0) == 0x80)) {
            if(out_pos + 3 <= output_size - 1) {
                output[out_pos++] = *p++;
                output[out_pos++] = *p++;
                output[out_pos++] = *p++;
            } else {
                break;
            }
        } else if(((*p & 0xF8) == 0xF0) && (p + 3 < end) &&
                  ((p[1] & 0xC0) == 0x80) && ((p[2] & 0xC0) == 0x80) &&
                  ((p[3] & 0xC0) == 0x80)) {
            if(out_pos + 4 <= output_size - 1) {
                output[out_pos++] = *p++;
                output[out_pos++] = *p++;
                output[out_pos++] = *p++;
                output[out_pos++] = *p++;
            } else {
                break;
            }
        } else {
            if(out_pos + 3 <= output_size - 1) {
                output[out_pos++] = (char) 0xEF;
                output[out_pos++] = (char) 0xBF;
                output[out_pos++] = (char) 0xBD;
            }
            p++;
        }
    }

    output[out_pos] = '\0';
    return out_pos;
}

/*
 * Tag/attribute filtering helpers
 */
bool xml_san_tag_allowed(const xml_san_ctx_t* ctx, const char* tag) {
    if(!ctx->config.allowed_tags) {
        return true;
    }

    for(const char** t = ctx->config.allowed_tags; *t; t++) {
        if(strcasecmp(*t, tag) == 0) {
            return true;
        }
    }
    return false;
}

bool xml_san_attr_allowed(const xml_san_ctx_t* ctx, const char* attr) {
    if(!ctx->config.allowed_attrs) {
        return true;
    }

    for(const char** a = ctx->config.allowed_attrs; *a; a++) {
        if(strcasecmp(*a, attr) == 0) {
            return true;
        }
    }
    return false;
}

/*
 * Backend selection
 */
static const xml_san_backend_ops_t* select_backend(xml_san_backend_type_t type) {
    if(type == XML_SAN_BACKEND_AUTO) {
#ifdef XML_SAN_HAVE_LIBXML2
        return &xml_san_backend_libxml2;
#elif defined(XML_SAN_HAVE_EXPAT)
        return &xml_san_backend_expat;
#elif defined(XML_SAN_HAVE_ROXML)
        return &xml_san_backend_roxml;
#elif defined(XML_SAN_HAVE_MXML)
        return &xml_san_backend_mxml;
#elif defined(XML_SAN_HAVE_YXML)
        return &xml_san_backend_yxml;
#elif defined(XML_SAN_HAVE_EZXML)
        return &xml_san_backend_ezxml;
#elif defined(XML_SAN_HAVE_SCEW)
        return &xml_san_backend_scew;
#else
        return &xml_san_backend_custom;
#endif
    }

    if((type < XML_SAN_BACKEND_COUNT) && backends[type]) {
        return backends[type];
    }

    return NULL;
}

/*
 * Public API implementation
 */
void xml_san_config_init(xml_san_config_t* config) {
    if(!config) {
        return;
    }

    memset(config, 0, sizeof(*config));
    config->options = XML_SAN_OPT_DEFAULT;
    config->backend = XML_SAN_BACKEND_AUTO;
    config->max_depth = 256;
    config->max_attr_count = 100;
    config->max_attr_len = 65536;
}

xml_san_ctx_t* xml_san_ctx_new(const xml_san_config_t* config) {
    xml_san_ctx_t* ctx = calloc(1, sizeof(*ctx));
    if(!ctx) {
        return NULL;
    }

    if(config) {
        ctx->config = *config;
    } else {
        xml_san_config_init(&ctx->config);
    }

    ctx->ops = select_backend(ctx->config.backend);
    if(!ctx->ops) {
        free(ctx);
        return NULL;
    }

    if(ctx->ops->init && (ctx->ops->init(ctx) != 0)) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

void xml_san_ctx_free(xml_san_ctx_t* ctx) {
    if(!ctx) {
        return;
    }

    if(ctx->ops && ctx->ops->cleanup) {
        ctx->ops->cleanup(ctx);
    }

    free(ctx);
}

xml_san_error_t xml_san_get_error(const xml_san_ctx_t* ctx) {
    if(!ctx) {
        return XML_SAN_ERR_NULL_PTR;
    }
    return ctx->last_error;
}

const char* xml_san_strerror(xml_san_error_t error) {
    if((error < 0) || (error >= XML_SAN_ERR_UNKNOWN)) {
        return error_messages[XML_SAN_ERR_UNKNOWN];
    }
    return error_messages[error];
}

const char* xml_san_get_backend_name(const xml_san_ctx_t* ctx) {
    if(!ctx || !ctx->ops) {
        return "none";
    }
    return ctx->ops->name;
}

xml_san_error_t xml_san_string(xml_san_ctx_t* ctx,
                               const char* input, size_t input_len,
                               char** output, size_t* output_len) {
    if(!ctx) {
        return XML_SAN_ERR_NULL_PTR;
    }
    if(!input || !output) {
        ctx->last_error = XML_SAN_ERR_NULL_PTR;
        return ctx->last_error;
    }

    if(input_len == 0) {
        input_len = strlen(input);
    }

    ctx->stats.input_len = input_len;

    if(!ctx->ops || !ctx->ops->sanitize) {
        ctx->last_error = XML_SAN_ERR_NO_BACKEND;
        return ctx->last_error;
    }

    ctx->last_error = ctx->ops->sanitize(ctx, input, input_len, output, output_len);

    if((ctx->last_error == XML_SAN_OK) && output_len) {
        ctx->stats.output_len = *output_len;
    }

    return ctx->last_error;
}

xml_san_error_t xml_san_string_buf(xml_san_ctx_t* ctx,
                                   const char* input, size_t input_len,
                                   char* output, size_t output_size,
                                   size_t* output_len) {
    char* tmp = NULL;
    size_t tmp_len = 0;

    xml_san_error_t err = xml_san_string(ctx, input, input_len, &tmp, &tmp_len);
    if(err != XML_SAN_OK) {
        return err;
    }

    if(tmp_len >= output_size) {
        free(tmp);
        if(ctx) {
            ctx->last_error = XML_SAN_ERR_BUFFER_TOO_SMALL;
        }
        return XML_SAN_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(output, tmp, tmp_len + 1);
    if(output_len) {
        *output_len = tmp_len;
    }

    free(tmp);
    return XML_SAN_OK;
}

xml_san_error_t xml_san_attr_value(xml_san_ctx_t* ctx,
                                   const char* value,
                                   char** output) {
    if(!ctx) {
        return XML_SAN_ERR_NULL_PTR;
    }
    if(!value || !output) {
        ctx->last_error = XML_SAN_ERR_NULL_PTR;
        return ctx->last_error;
    }

    if(ctx->ops && ctx->ops->escape_attr) {
        return ctx->ops->escape_attr(ctx, value, output);
    }

    return xml_san_text_content(ctx, value, output);
}

xml_san_error_t xml_san_text_content(xml_san_ctx_t* ctx,
                                     const char* text,
                                     char** output) {
    if(!ctx) {
        return XML_SAN_ERR_NULL_PTR;
    }
    if(!text || !output) {
        ctx->last_error = XML_SAN_ERR_NULL_PTR;
        return ctx->last_error;
    }

    if(ctx->ops && ctx->ops->escape_text) {
        return ctx->ops->escape_text(ctx, text, output);
    }

    ctx->last_error = XML_SAN_ERR_NO_BACKEND;
    return ctx->last_error;
}

xml_san_error_t xml_san_validate(xml_san_ctx_t* ctx,
                                 const char* input, size_t input_len) {
    if(!ctx) {
        return XML_SAN_ERR_NULL_PTR;
    }
    if(!input) {
        ctx->last_error = XML_SAN_ERR_NULL_PTR;
        return ctx->last_error;
    }

    if(input_len == 0) {
        input_len = strlen(input);
    }

    if(ctx->ops && ctx->ops->validate) {
        return ctx->ops->validate(ctx, input, input_len);
    }

    if((ctx->config.options & XML_SAN_OPT_VALIDATE_UTF8) &&
       (xml_san_utf8_validate(input, input_len) != 0)) {
        ctx->last_error = XML_SAN_ERR_INVALID_UTF8;
        return ctx->last_error;
    }

    ctx->last_error = XML_SAN_OK;
    return XML_SAN_OK;
}

xml_san_error_t xml_san_get_stats(const xml_san_ctx_t* ctx,
                                  xml_san_stats_t* stats) {
    if(!ctx || !stats) {
        return XML_SAN_ERR_NULL_PTR;
    }

    *stats = ctx->stats;
    return XML_SAN_OK;
}

void xml_san_reset_stats(xml_san_ctx_t* ctx) {
    if(ctx) {
        memset(&ctx->stats, 0, sizeof(ctx->stats));
    }
}

void xml_san_free(void* ptr) {
    free(ptr);
}

bool xml_san_backend_available(xml_san_backend_type_t backend) {
    if(backend == XML_SAN_BACKEND_AUTO) {
        return true;
    }

    if((backend < XML_SAN_BACKEND_COUNT) && backends[backend]) {
        return true;
    }

    return false;
}

size_t xml_san_list_backends(xml_san_backend_type_t* backends_out, size_t max_count) {
    size_t count = 0;

    for(int i = 1; i < XML_SAN_BACKEND_COUNT && count < max_count; i++) {
        if(backends[i]) {
            backends_out[count++] = (xml_san_backend_type_t) i;
        }
    }

    return count;
}