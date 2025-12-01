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
#include <scew/scew.h>

typedef struct {
    scew_parser* parser;
} scew_ctx_t;

/*
 * Initialize SCEW backend
 */
static int scew_backend_init(xml_san_ctx_t* ctx) {
    scew_ctx_t* sctx = calloc(1, sizeof(*sctx));
    if(!sctx) {
        return -1;
    }

    sctx->parser = scew_parser_create();
    if(!sctx->parser) {
        free(sctx);
        return -1;
    }

    scew_parser_ignore_whitespaces(sctx->parser, 0);

    ctx->backend_data = sctx;
    return 0;
}

/*
 * Cleanup SCEW backend
 */
static void scew_backend_cleanup(xml_san_ctx_t* ctx) {
    if(!ctx || !ctx->backend_data) {
        return;
    }

    scew_ctx_t* sctx = ctx->backend_data;

    if(sctx->parser) {
        scew_parser_free(sctx->parser);
    }

    free(sctx);
    ctx->backend_data = NULL;
}

/*
 * Escape text content
 */
static void escape_text_to_buffer(xml_san_ctx_t* ctx, const char* text,
                                  xml_san_buffer_t* buf) {
    if(!text) {
        return;
    }

    for(const char* p = text; *p; p++) {
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

/*
 * Process element recursively
 */
static xml_san_error_t process_element(xml_san_ctx_t* ctx, scew_element* element,
                                       xml_san_buffer_t* buf, int depth) {
    if(!element) {
        return XML_SAN_OK;
    }

    if((ctx->config.max_depth > 0) && ((size_t) depth > ctx->config.max_depth)) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    const char* name = scew_element_name(element);
    ctx->stats.elements_processed++;

    bool allowed = true;
    if(ctx->config.options & XML_SAN_OPT_STRIP_TAGS) {
        allowed = false;
    } else if(!xml_san_tag_allowed(ctx, name)) {
        allowed = false;
    }

    if(ctx->config.filter_fn) {
        allowed = ctx->config.filter_fn(name, NULL, NULL, ctx->config.user_data);
    }

    if(!allowed) {
        ctx->stats.elements_removed++;

        if(!(ctx->config.options & XML_SAN_OPT_STRIP_TAGS)) {
            scew_element* child = NULL;
            while((child = scew_element_next(element, child)) != NULL) {
                xml_san_error_t err = process_element(ctx, child, buf, depth + 1);
                if(err != XML_SAN_OK) {
                    return err;
                }
            }
        }
        return XML_SAN_OK;
    }

    unsigned int child_count = scew_element_count(element);
    unsigned int attr_count = scew_attribute_count(element);
    const char* contents = scew_element_contents(element);

    if((ctx->config.options & XML_SAN_OPT_REMOVE_EMPTY_TAGS) &&
       (child_count == 0) && (attr_count == 0) &&
       (!contents || (contents[0] == '\0'))) {
        ctx->stats.elements_removed++;
        return XML_SAN_OK;
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

    xml_san_buffer_append_char(buf, '<');
    xml_san_buffer_append_str(buf, output_name);

    scew_attribute* attr = NULL;
    int processed_attrs = 0;

    while((attr = scew_attribute_next(element, attr)) != NULL) {
        const char* attr_name = scew_attribute_name(attr);
        const char* attr_value = scew_attribute_value(attr);

        ctx->stats.attrs_processed++;
        processed_attrs++;

        if((ctx->config.max_attr_count > 0) &&
           ((size_t) processed_attrs > ctx->config.max_attr_count)) {
            ctx->stats.attrs_removed++;
            continue;
        }

        if(!xml_san_attr_allowed(ctx, attr_name)) {
            ctx->stats.attrs_removed++;
            continue;
        }

        if((ctx->config.max_attr_len > 0) && attr_value &&
           (strlen(attr_value) > ctx->config.max_attr_len)) {
            ctx->stats.attrs_removed++;
            continue;
        }

        if(ctx->config.filter_fn) {
            if(!ctx->config.filter_fn(name, attr_name, attr_value,
                                      ctx->config.user_data)) {
                ctx->stats.attrs_removed++;
                continue;
            }
        }

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
    }

    if((child_count == 0) && (!contents || (contents[0] == '\0'))) {
        xml_san_buffer_append_str(buf, "/>");
    } else {
        xml_san_buffer_append_char(buf, '>');

        if(contents) {
            escape_text_to_buffer(ctx, contents, buf);
        }

        scew_element* child = NULL;
        while((child = scew_element_next(element, child)) != NULL) {
            xml_san_error_t err = process_element(ctx, child, buf, depth + 1);
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
    return XML_SAN_OK;
}

/*
 * Main sanitization function using SCEW
 */
static xml_san_error_t scew_sanitize(xml_san_ctx_t* ctx,
                                     const char* input, size_t input_len,
                                     char** output, size_t* output_len) {
    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    scew_ctx_t* sctx = ctx->backend_data;
    if(!sctx || !sctx->parser) {
        return XML_SAN_ERR_NO_BACKEND;
    }

    if(!scew_parser_load_buffer(sctx->parser, input, input_len)) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    scew_tree* tree = scew_parser_tree(sctx->parser);
    if(!tree) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    scew_element* root = scew_tree_root(tree);
    if(!root) {
        scew_tree_free(tree);
        return XML_SAN_ERR_PARSE_FAILED;
    }

    xml_san_buffer_t buf;
    if(xml_san_buffer_init(&buf, input_len + 256) != 0) {
        scew_tree_free(tree);
        return XML_SAN_ERR_MEMORY;
    }

    xml_san_error_t err = process_element(ctx, root, &buf, 0);

    scew_tree_free(tree);

    if(err != XML_SAN_OK) {
        xml_san_buffer_cleanup(&buf);
        return err;
    }

    *output = xml_san_buffer_detach(&buf, output_len);
    return *output ? XML_SAN_OK : XML_SAN_ERR_MEMORY;
}

/*
 * Validation using SCEW
 */
static xml_san_error_t scew_validate(xml_san_ctx_t* ctx,
                                     const char* input, size_t input_len) {
    scew_ctx_t* sctx = ctx->backend_data;
    if(!sctx || !sctx->parser) {
        return XML_SAN_ERR_NO_BACKEND;
    }

    if(!scew_parser_load_buffer(sctx->parser, input, input_len)) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    scew_tree* tree = scew_parser_tree(sctx->parser);
    if(!tree) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    scew_tree_free(tree);
    return XML_SAN_OK;
}

/*
 * Text escaping
 */
static xml_san_error_t scew_escape_text(xml_san_ctx_t* ctx,
                                        const char* input,
                                        char** output) {
    (void) ctx;

    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    size_t len = strlen(input);
    xml_san_buffer_t buf;

    if(xml_san_buffer_init(&buf, len * 2 + 1) != 0) {
        return XML_SAN_ERR_MEMORY;
    }

    for(const char* p = input; *p; p++) {
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
static xml_san_error_t scew_escape_attr(xml_san_ctx_t* ctx,
                                        const char* input,
                                        char** output) {
    (void) ctx;

    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    size_t len = strlen(input);
    xml_san_buffer_t buf;

    if(xml_san_buffer_init(&buf, len * 2 + 1) != 0) {
        return XML_SAN_ERR_MEMORY;
    }

    for(const char* p = input; *p; p++) {
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

const xml_san_backend_ops_t xml_san_backend_scew = {
    .name = "scew",
    .init = scew_backend_init,
    .cleanup = scew_backend_cleanup,
    .sanitize = scew_sanitize,
    .validate = scew_validate,
    .escape_text = scew_escape_text,
    .escape_attr = scew_escape_attr
};
