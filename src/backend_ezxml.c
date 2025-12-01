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
#include <ezxml.h>
#include <ctype.h>

/* Backend-specific context data */
typedef struct {
    int reserved;  /* Placeholder for future use */
} ezxml_ctx_t;

/*
 * Process a single element recursively
 */
static xml_san_error_t process_element(xml_san_ctx_t* ctx, ezxml_t elem,
                                       xml_san_buffer_t* buf, int depth) {
    if(!elem) {
        return XML_SAN_OK;
    }

    if((ctx->config.max_depth > 0) && ((size_t) depth > ctx->config.max_depth)) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    for(ezxml_t cur = elem; cur; cur = cur->next) {
        const char* name = cur->name;
        if(!name) {
            continue;
        }

        ctx->stats.elements_processed++;

        bool allowed = true;
        if(ctx->config.options & XML_SAN_OPT_STRIP_TAGS) {
            allowed = false;
        } else if(!xml_san_tag_allowed(ctx, name)) {
            allowed = false;
        }

        if(ctx->config.filter_fn) {
            allowed = ctx->config.filter_fn(name, NULL, NULL,
                                            ctx->config.user_data);
        }

        if(!allowed) {
            ctx->stats.elements_removed++;
            if(!(ctx->config.options & XML_SAN_OPT_STRIP_TAGS)) {
                if(cur->txt && cur->txt[0]) {
                    for(const char* p = cur->txt; *p; p++) {
                        if((ctx->config.options & XML_SAN_OPT_REMOVE_CTRL) &&
                           xml_san_is_ctrl_char((unsigned char) *p)) {
                            ctx->stats.ctrl_chars_removed++;
                            continue;
                        }
                        if(ctx->config.options & XML_SAN_OPT_ESCAPE_ENTITIES) {
                            switch(*p) {
                            case '&': xml_san_buffer_append_str(buf, "&amp;"); break;
                            case '<': xml_san_buffer_append_str(buf, "&lt;"); break;
                            case '>': xml_san_buffer_append_str(buf, "&gt;"); break;
                            default: xml_san_buffer_append_char(buf, *p); break;
                            }
                        } else {
                            xml_san_buffer_append_char(buf, *p);
                        }
                    }
                }
                if(cur->child) {
                    xml_san_error_t err = process_element(ctx, cur->child, buf, depth + 1);
                    if(err != XML_SAN_OK) {
                        return err;
                    }
                }
            }
            continue;
        }

        const char* output_name = name;
        char* name_copy = NULL;

        if(ctx->config.options & XML_SAN_OPT_STRIP_NAMESPACES) {
            const char* colon = strchr(name, ':');
            if(colon) {
                output_name = colon + 1;
            }
        }

        if(ctx->config.options & XML_SAN_OPT_LOWERCASE_TAGS) {
            name_copy = strdup(output_name);
            if(name_copy) {
                for(char* p = name_copy; *p; p++) {
                    *p = tolower((unsigned char) *p);
                }
                output_name = name_copy;
            }
        }

        bool has_content = (cur->txt && cur->txt[0]) || cur->child;
        bool has_attrs = (cur->attr && cur->attr[0]);

        if((ctx->config.options & XML_SAN_OPT_REMOVE_EMPTY_TAGS) &&
           !has_content && !has_attrs) {
            ctx->stats.elements_removed++;
            free(name_copy);
            continue;
        }

        xml_san_buffer_append_char(buf, '<');
        xml_san_buffer_append_str(buf, output_name);

        /* Process attributes */
        /* ezxml stores attributes as name, value pairs in attr array */
        if(cur->attr) {
            int attr_count = 0;
            for(int i = 0; cur->attr[i]; i += 2) {
                const char* attr_name = cur->attr[i];
                const char* attr_value = cur->attr[i + 1];

                if(!attr_name) {
                    break;
                }

                ctx->stats.attrs_processed++;
                attr_count++;

                bool attr_allowed = true;

                if((ctx->config.max_attr_count > 0) &&
                   ((size_t) attr_count > ctx->config.max_attr_count)) {
                    attr_allowed = false;
                }

                if(attr_allowed && !xml_san_attr_allowed(ctx, attr_name)) {
                    attr_allowed = false;
                }

                if(attr_allowed && (ctx->config.max_attr_len > 0) &&
                   attr_value && (strlen(attr_value) > ctx->config.max_attr_len)) {
                    attr_allowed = false;
                }

                if(attr_allowed && ctx->config.filter_fn) {
                    attr_allowed = ctx->config.filter_fn(name, attr_name, attr_value,
                                                         ctx->config.user_data);
                }

                if(attr_allowed) {
                    xml_san_buffer_append_char(buf, ' ');
                    xml_san_buffer_append_str(buf, attr_name);
                    xml_san_buffer_append_str(buf, "=\"");

                    if(attr_value) {
                        for(const char* vp = attr_value; *vp; vp++) {
                            switch(*vp) {
                            case '&': xml_san_buffer_append_str(buf, "&amp;"); break;
                            case '<': xml_san_buffer_append_str(buf, "&lt;"); break;
                            case '>': xml_san_buffer_append_str(buf, "&gt;"); break;
                            case '"': xml_san_buffer_append_str(buf, "&quot;"); break;
                            default: xml_san_buffer_append_char(buf, *vp); break;
                            }
                        }
                    }
                    xml_san_buffer_append_char(buf, '"');
                } else {
                    ctx->stats.attrs_removed++;
                }
            }
        }

        if(!has_content) {
            xml_san_buffer_append_str(buf, "/>");
        } else {
            xml_san_buffer_append_char(buf, '>');

            if(cur->txt && cur->txt[0]) {
                if(ctx->config.options & XML_SAN_OPT_NORMALIZE_WS) {
                    bool last_was_space = false;
                    for(const char* p = cur->txt; *p; p++) {
                        if(isspace((unsigned char) *p)) {
                            if(!last_was_space) {
                                xml_san_buffer_append_char(buf, ' ');
                                last_was_space = true;
                            }
                        } else {
                            if((ctx->config.options & XML_SAN_OPT_REMOVE_CTRL) &&
                               xml_san_is_ctrl_char((unsigned char) *p)) {
                                ctx->stats.ctrl_chars_removed++;
                                continue;
                            }
                            if(ctx->config.options & XML_SAN_OPT_ESCAPE_ENTITIES) {
                                switch(*p) {
                                case '&': xml_san_buffer_append_str(buf, "&amp;"); break;
                                case '<': xml_san_buffer_append_str(buf, "&lt;"); break;
                                case '>': xml_san_buffer_append_str(buf, "&gt;"); break;
                                default: xml_san_buffer_append_char(buf, *p); break;
                                }
                            } else {
                                xml_san_buffer_append_char(buf, *p);
                            }
                            last_was_space = false;
                        }
                    }
                } else {
                    for(const char* p = cur->txt; *p; p++) {
                        if((ctx->config.options & XML_SAN_OPT_REMOVE_CTRL) &&
                           xml_san_is_ctrl_char((unsigned char) *p)) {
                            ctx->stats.ctrl_chars_removed++;
                            continue;
                        }
                        if(ctx->config.options & XML_SAN_OPT_ESCAPE_ENTITIES) {
                            switch(*p) {
                            case '&': xml_san_buffer_append_str(buf, "&amp;"); break;
                            case '<': xml_san_buffer_append_str(buf, "&lt;"); break;
                            case '>': xml_san_buffer_append_str(buf, "&gt;"); break;
                            default: xml_san_buffer_append_char(buf, *p); break;
                            }
                        } else {
                            xml_san_buffer_append_char(buf, *p);
                        }
                    }
                }
            }
            if(cur->child) {
                xml_san_error_t err = process_element(ctx, cur->child, buf, depth + 1);
                if(err != XML_SAN_OK) {
                    free(name_copy);
                    return err;
                }
            }
            xml_san_buffer_append_str(buf, "</");
            xml_san_buffer_append_str(buf, output_name);
            xml_san_buffer_append_char(buf, '>');
        }

        free(name_copy);

        /* Handle tail text (text after child elements) */
        /* Note: ezxml doesn't track tail text separately, it's in the parent's txt */
    }

    return XML_SAN_OK;
}

/*
 * Initialize ezXML backend
 */
static int ezxml_backend_init(xml_san_ctx_t* ctx) {
    ezxml_ctx_t* ectx = calloc(1, sizeof(*ectx));
    if(!ectx) {
        return -1;
    }

    ctx->backend_data = ectx;
    return 0;
}

/*
 * Cleanup ezXML backend
 */
static void ezxml_backend_cleanup(xml_san_ctx_t* ctx) {
    if(!ctx || !ctx->backend_data) {
        return;
    }

    free(ctx->backend_data);
    ctx->backend_data = NULL;
}

/*
 * Main sanitization function using ezXML
 */
static xml_san_error_t ezxml_sanitize(xml_san_ctx_t* ctx,
                                      const char* input, size_t input_len,
                                      char** output, size_t* output_len) {
    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    char* input_copy = malloc(input_len + 1);
    if(!input_copy) {
        return XML_SAN_ERR_MEMORY;
    }

    memcpy(input_copy, input, input_len);
    input_copy[input_len] = '\0';

    ezxml_t root = ezxml_parse_str(input_copy, input_len);
    if(!root) {
        free(input_copy);
        return XML_SAN_ERR_PARSE_FAILED;
    }

    const char* err = ezxml_error(root);
    if(err && err[0]) {
        ezxml_free(root);
        free(input_copy);
        return XML_SAN_ERR_PARSE_FAILED;
    }

    xml_san_buffer_t buf;
    if(xml_san_buffer_init(&buf, input_len + 256) != 0) {
        ezxml_free(root);
        free(input_copy);
        return XML_SAN_ERR_MEMORY;
    }

    xml_san_error_t result = process_element(ctx, root, &buf, 0);

    ezxml_free(root);
    free(input_copy);

    if(result != XML_SAN_OK) {
        xml_san_buffer_cleanup(&buf);
        return result;
    }

    *output = xml_san_buffer_detach(&buf, output_len);
    return *output ? XML_SAN_OK : XML_SAN_ERR_MEMORY;
}

/*
 * Validation using ezXML
 */
static xml_san_error_t ezxml_validate(xml_san_ctx_t* ctx,
                                      const char* input, size_t input_len) {
    (void) ctx;

    /* Make a copy since ezxml_parse_str modifies input */
    char* input_copy = malloc(input_len + 1);
    if(!input_copy) {
        return XML_SAN_ERR_MEMORY;
    }

    memcpy(input_copy, input, input_len);
    input_copy[input_len] = '\0';

    ezxml_t root = ezxml_parse_str(input_copy, input_len);
    if(!root) {
        free(input_copy);
        return XML_SAN_ERR_PARSE_FAILED;
    }

    const char* err = ezxml_error(root);
    xml_san_error_t result = (err && err[0]) ? XML_SAN_ERR_PARSE_FAILED : XML_SAN_OK;

    ezxml_free(root);
    free(input_copy);

    return result;
}

/*
 * Text escaping
 */
static xml_san_error_t ezxml_escape_text(xml_san_ctx_t* ctx,
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
static xml_san_error_t ezxml_escape_attr(xml_san_ctx_t* ctx,
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

/* Backend operations structure */
const xml_san_backend_ops_t xml_san_backend_ezxml = {
    .name = "ezxml",
    .init = ezxml_backend_init,
    .cleanup = ezxml_backend_cleanup,
    .sanitize = ezxml_sanitize,
    .validate = ezxml_validate,
    .escape_text = ezxml_escape_text,
    .escape_attr = ezxml_escape_attr
};
