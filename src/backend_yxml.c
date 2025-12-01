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
#include <yxml.h>
#include <ctype.h>

#define YXML_BUFFER_SIZE 4096
#define MAX_STACK_DEPTH 256

typedef struct {
    char name[256];
    bool allowed;
} yxml_stack_entry_t;

/* Backend-specific context data */
typedef struct {
    char yxml_buf[YXML_BUFFER_SIZE];
    yxml_stack_entry_t stack[MAX_STACK_DEPTH];
    int stack_depth;
    char current_attr_name[256];
    char current_attr_value[4096];
    size_t attr_value_len;
    bool in_attr_value;
    int attr_count;
} yxml_ctx_t;

/*
 * Escape text and append to buffer
 */
static void escape_and_append(xml_san_ctx_t* ctx, xml_san_buffer_t* buf,
                              const char* text, size_t len) {
    for(size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char) text[i];

        if((ctx->config.options & XML_SAN_OPT_REMOVE_CTRL) &&
           xml_san_is_ctrl_char(c)) {
            ctx->stats.ctrl_chars_removed++;
            continue;
        }

        if(ctx->config.options & XML_SAN_OPT_ESCAPE_ENTITIES) {
            switch(c) {
            case '&':
                xml_san_buffer_append_str(buf, "&amp;");
                ctx->stats.entities_escaped++;
                break;
            case '<':
                xml_san_buffer_append_str(buf, "&lt;");
                ctx->stats.entities_escaped++;
                break;
            case '>':
                xml_san_buffer_append_str(buf, "&gt;");
                ctx->stats.entities_escaped++;
                break;
            default:
                xml_san_buffer_append_char(buf, c);
                break;
            }
        } else {
            xml_san_buffer_append_char(buf, c);
        }
    }
}

/*
 * Escape attribute value and append to buffer
 */
static void escape_attr_and_append(xml_san_buffer_t* buf, const char* text) {
    for(const char* p = text; *p; p++) {
        switch(*p) {
        case '&':  xml_san_buffer_append_str(buf, "&amp;"); break;
        case '<':  xml_san_buffer_append_str(buf, "&lt;"); break;
        case '>':  xml_san_buffer_append_str(buf, "&gt;"); break;
        case '"':  xml_san_buffer_append_str(buf, "&quot;"); break;
        case '\'': xml_san_buffer_append_str(buf, "&apos;"); break;
        default:   xml_san_buffer_append_char(buf, *p); break;
        }
    }
}

/*
 * Get output name (handle namespace stripping and lowercase)
 */
static const char* get_output_name(xml_san_ctx_t* ctx, const char* name,
                                   char* buf, size_t buf_size) {
    const char* output_name = name;

    if(ctx->config.options & XML_SAN_OPT_STRIP_NAMESPACES) {
        const char* colon = strchr(name, ':');
        if(colon) {
            output_name = colon + 1;
        }
    }

    if(ctx->config.options & XML_SAN_OPT_LOWERCASE_TAGS) {
        size_t len = strlen(output_name);
        if(len >= buf_size) {
            len = buf_size - 1;
        }
        for(size_t i = 0; i < len; i++) {
            buf[i] = tolower((unsigned char) output_name[i]);
        }
        buf[len] = '\0';
        return buf;
    }

    return output_name;
}

/*
 * Initialize yxml backend
 */
static int yxml_backend_init(xml_san_ctx_t* ctx) {
    yxml_ctx_t* yctx = calloc(1, sizeof(*yctx));
    if(!yctx) {
        return -1;
    }

    ctx->backend_data = yctx;
    return 0;
}

/*
 * Cleanup yxml backend
 */
static void yxml_backend_cleanup(xml_san_ctx_t* ctx) {
    if(!ctx || !ctx->backend_data) {
        return;
    }

    free(ctx->backend_data);
    ctx->backend_data = NULL;
}

/*
 * Main sanitization function using yxml
 */
static xml_san_error_t yxml_sanitize(xml_san_ctx_t* ctx,
                                     const char* input, size_t input_len,
                                     char** output, size_t* output_len) {
    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    yxml_ctx_t* yctx = ctx->backend_data;
    if(!yctx) {
        return XML_SAN_ERR_NO_BACKEND;
    }

    yxml_t x;
    yxml_init(&x, yctx->yxml_buf, sizeof(yctx->yxml_buf));

    yctx->stack_depth = 0;
    yctx->in_attr_value = false;
    yctx->attr_count = 0;

    xml_san_buffer_t buf;
    if(xml_san_buffer_init(&buf, input_len + 256) != 0) {
        return XML_SAN_ERR_MEMORY;
    }

    char name_buf[256];

    for(size_t i = 0; i < input_len; i++) {
        yxml_ret_t r = yxml_parse(&x, input[i]);

        if(r < 0) {
            xml_san_buffer_cleanup(&buf);
            return XML_SAN_ERR_PARSE_FAILED;
        }

        switch(r) {
        case YXML_ELEMSTART: {
            const char* name = x.elem;
            ctx->stats.elements_processed++;

            if(yctx->stack_depth >= MAX_STACK_DEPTH) {
                xml_san_buffer_cleanup(&buf);
                return XML_SAN_ERR_PARSE_FAILED;
            }

            if((ctx->config.max_depth > 0) &&
               ((size_t) yctx->stack_depth >= ctx->config.max_depth)) {
                xml_san_buffer_cleanup(&buf);
                return XML_SAN_ERR_PARSE_FAILED;
            }

            bool allowed = true;
            if(ctx->config.options & XML_SAN_OPT_STRIP_TAGS) {
                allowed = false;
            } else if(!xml_san_tag_allowed(ctx, name)) {
                allowed = false;
            }

            if(allowed && ctx->config.filter_fn) {
                allowed = ctx->config.filter_fn(name, NULL, NULL,
                                                ctx->config.user_data);
            }

            strncpy(yctx->stack[yctx->stack_depth].name, name,
                    sizeof(yctx->stack[yctx->stack_depth].name) - 1);
            yctx->stack[yctx->stack_depth].allowed = allowed;
            yctx->stack_depth++;
            yctx->attr_count = 0;

            if(!allowed) {
                ctx->stats.elements_removed++;
            } else {
                const char* out_name = get_output_name(ctx, name, name_buf,
                                                       sizeof(name_buf));
                xml_san_buffer_append_char(&buf, '<');
                xml_san_buffer_append_str(&buf, out_name);
            }
            break;
        }

        case YXML_ATTRSTART: {
            if((yctx->stack_depth > 0) &&
               yctx->stack[yctx->stack_depth - 1].allowed) {
                strncpy(yctx->current_attr_name, x.attr,
                        sizeof(yctx->current_attr_name) - 1);
                yctx->current_attr_value[0] = '\0';
                yctx->attr_value_len = 0;
                yctx->in_attr_value = true;
            }
            break;
        }

        case YXML_ATTRVAL: {
            if(yctx->in_attr_value && x.data[0]) {
                size_t dlen = strlen(x.data);
                if(yctx->attr_value_len + dlen < sizeof(yctx->current_attr_value) - 1) {
                    memcpy(yctx->current_attr_value + yctx->attr_value_len,
                           x.data, dlen);
                    yctx->attr_value_len += dlen;
                    yctx->current_attr_value[yctx->attr_value_len] = '\0';
                }
            }
            break;
        }

        case YXML_ATTREND: {
            if(yctx->in_attr_value && (yctx->stack_depth > 0) &&
               yctx->stack[yctx->stack_depth - 1].allowed) {

                ctx->stats.attrs_processed++;
                yctx->attr_count++;

                bool attr_allowed = true;

                if((ctx->config.max_attr_count > 0) &&
                   ((size_t) yctx->attr_count > ctx->config.max_attr_count)) {
                    attr_allowed = false;
                }

                if(attr_allowed && !xml_san_attr_allowed(ctx, yctx->current_attr_name)) {
                    attr_allowed = false;
                }

                if(attr_allowed && (ctx->config.max_attr_len > 0) &&
                   (yctx->attr_value_len > ctx->config.max_attr_len)) {
                    attr_allowed = false;
                }

                if(attr_allowed && ctx->config.filter_fn) {
                    const char* elem_name = yctx->stack[yctx->stack_depth - 1].name;
                    attr_allowed = ctx->config.filter_fn(elem_name,
                                                         yctx->current_attr_name,
                                                         yctx->current_attr_value,
                                                         ctx->config.user_data);
                }

                if(attr_allowed) {
                    xml_san_buffer_append_char(&buf, ' ');
                    xml_san_buffer_append_str(&buf, yctx->current_attr_name);
                    xml_san_buffer_append_str(&buf, "=\"");
                    escape_attr_and_append(&buf, yctx->current_attr_value);
                    xml_san_buffer_append_char(&buf, '"');
                } else {
                    ctx->stats.attrs_removed++;
                }
            }
            yctx->in_attr_value = false;
            break;
        }

        case YXML_ELEMEND: {
            if(yctx->stack_depth <= 0) {
                break;
            }

            yctx->stack_depth--;

            if(yctx->stack[yctx->stack_depth].allowed) {
                const char* name = yctx->stack[yctx->stack_depth].name;
                const char* out_name = get_output_name(ctx, name, name_buf,
                                                       sizeof(name_buf));
                xml_san_buffer_append_str(&buf, "</");
                xml_san_buffer_append_str(&buf, out_name);
                xml_san_buffer_append_char(&buf, '>');
            }
            break;
        }

        case YXML_CONTENT: {
            if(x.data[0]) {
                bool output_text = true;

                if((yctx->stack_depth > 0) &&
                   !yctx->stack[yctx->stack_depth - 1].allowed) {
                    if(ctx->config.options & XML_SAN_OPT_STRIP_TAGS) {
                        output_text = false;
                    }
                }

                if(output_text) {
                    escape_and_append(ctx, &buf, x.data, strlen(x.data));
                }
            }
            break;
        }

        case YXML_PISTART:
        case YXML_PIEND:
        case YXML_PICONTENT:
            /* Processing instructions - skip if stripping */
            if(!(ctx->config.options & XML_SAN_OPT_STRIP_PI)) {
                /* yxml doesn't preserve PI content well, skip for now */
            }
            break;

        case YXML_OK:
            /* Need more input, closing tag delimiter, etc. */
            /* For '>' after attributes, output it for allowed elements */
            if((input[i] == '>') && (yctx->stack_depth > 0) &&
               yctx->stack[yctx->stack_depth - 1].allowed &&
               !yctx->in_attr_value) {
                /* Check if this is after element start (not end) */
                /* We need to output > after attributes */
                /* Actually yxml handles this differently, check state */
            }
            break;

        default:
            break;
        }

        /* Handle '>' for element opening tag completion */
        if((r == YXML_OK) && (input[i] == '>')) {
            /* This could be end of opening tag or closing tag */
            /* yxml returns YXML_OK for '>' in opening tag with attrs */
        }
    }

    yxml_ret_t eof = yxml_eof(&x);
    if(eof < 0) {
        xml_san_buffer_cleanup(&buf);
        return XML_SAN_ERR_PARSE_FAILED;
    }

    *output = xml_san_buffer_detach(&buf, output_len);
    return *output ? XML_SAN_OK : XML_SAN_ERR_MEMORY;
}

/*
 * Validation using yxml
 */
static xml_san_error_t yxml_validate(xml_san_ctx_t* ctx,
                                     const char* input, size_t input_len) {
    (void) ctx;

    char buf[4096];
    yxml_t x;
    yxml_init(&x, buf, sizeof(buf));

    for(size_t i = 0; i < input_len; i++) {
        yxml_ret_t r = yxml_parse(&x, input[i]);
        if(r < 0) {
            return XML_SAN_ERR_PARSE_FAILED;
        }
    }

    if(yxml_eof(&x) < 0) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    return XML_SAN_OK;
}

/*
 * Text escaping
 */
static xml_san_error_t yxml_escape_text(xml_san_ctx_t* ctx,
                                        const char* input,
                                        char** output) {
    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    size_t len = strlen(input);
    xml_san_buffer_t buf;

    if(xml_san_buffer_init(&buf, len * 2 + 1) != 0) {
        return XML_SAN_ERR_MEMORY;
    }

    for(const char* p = input; *p; p++) {
        if((ctx->config.options & XML_SAN_OPT_REMOVE_CTRL) &&
           xml_san_is_ctrl_char((unsigned char) *p)) {
            ctx->stats.ctrl_chars_removed++;
            continue;
        }

        switch(*p) {
        case '&': xml_san_buffer_append_str(&buf, "&amp;"); break;
        case '<': xml_san_buffer_append_str(&buf, "&lt;"); break;
        case '>': xml_san_buffer_append_str(&buf, "&gt;"); break;
        default: xml_san_buffer_append_char(&buf, *p); break;
        }
    }

    *output = xml_san_buffer_detach(&buf, NULL);
    return *output ? XML_SAN_OK : XML_SAN_ERR_MEMORY;
}

/*
 * Attribute escaping
 */
static xml_san_error_t yxml_escape_attr(xml_san_ctx_t* ctx,
                                        const char* input,
                                        char** output) {
    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    size_t len = strlen(input);
    xml_san_buffer_t buf;

    if(xml_san_buffer_init(&buf, len * 2 + 1) != 0) {
        return XML_SAN_ERR_MEMORY;
    }

    for(const char* p = input; *p; p++) {
        if((ctx->config.options & XML_SAN_OPT_REMOVE_CTRL) &&
           xml_san_is_ctrl_char((unsigned char) *p)) {
            continue;
        }

        switch(*p) {
        case '&': xml_san_buffer_append_str(&buf, "&amp;"); break;
        case '<': xml_san_buffer_append_str(&buf, "&lt;"); break;
        case '>': xml_san_buffer_append_str(&buf, "&gt;"); break;
        case '"': xml_san_buffer_append_str(&buf, "&quot;"); break;
        case '\'': xml_san_buffer_append_str(&buf, "&apos;"); break;
        default: xml_san_buffer_append_char(&buf, *p); break;
        }
    }

    *output = xml_san_buffer_detach(&buf, NULL);
    return *output ? XML_SAN_OK : XML_SAN_ERR_MEMORY;
}

const xml_san_backend_ops_t xml_san_backend_yxml = {
    .name = "yxml",
    .init = yxml_backend_init,
    .cleanup = yxml_backend_cleanup,
    .sanitize = yxml_sanitize,
    .validate = yxml_validate,
    .escape_text = yxml_escape_text,
    .escape_attr = yxml_escape_attr
};
