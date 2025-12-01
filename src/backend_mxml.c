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
#include <mxml.h>
#include <ctype.h>

typedef struct {
    int reserved;
} mxml_ctx_t;

/*
 * Custom load callback for whitespace handling
 */
static mxml_type_t type_cb(void* cbdata, mxml_node_t* node) {
    (void) cbdata;

    const char* name = mxmlGetElement(node);

    if(name == NULL) {
        return MXML_TYPE_TEXT;
    }

    return MXML_TYPE_TEXT;
}

/*
 * Process a single node recursively
 */
static xml_san_error_t process_node(xml_san_ctx_t* ctx, mxml_node_t* node,
                                    xml_san_buffer_t* buf, int depth) {
    if(!node) {
        return XML_SAN_OK;
    }

    if((ctx->config.max_depth > 0) && ((size_t) depth > ctx->config.max_depth)) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    mxml_node_t* cur;

    for(cur = node; cur; cur = mxmlGetNextSibling(cur)) {
        mxml_type_t type = mxmlGetType(cur);

        switch(type) {
        case MXML_TYPE_ELEMENT: {
            const char* name = mxmlGetElement(cur);
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
                    mxml_node_t* child = mxmlGetFirstChild(cur);
                    if(child) {
                        xml_san_error_t err = process_node(ctx, child, buf, depth + 1);
                        if(err != XML_SAN_OK) {
                            return err;
                        }
                    }
                }
                continue;
            }

            mxml_node_t* first_child = mxmlGetFirstChild(cur);
            int attr_count_check = mxmlElementGetAttrCount(cur);

            if((ctx->config.options & XML_SAN_OPT_REMOVE_EMPTY_TAGS) &&
               !first_child && (attr_count_check == 0)) {
                ctx->stats.elements_removed++;
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

            xml_san_buffer_append_char(buf, '<');
            xml_san_buffer_append_str(buf, output_name);

            int attr_count = mxmlElementGetAttrCount(cur);
            int processed_attrs = 0;

            for(int i = 0; i < attr_count; i++) {
                const char* attr_name;
                const char* attr_value;

                attr_value = mxmlElementGetAttrByIndex(cur, i, &attr_name);
                if(!attr_name) {
                    continue;
                }

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

            if(!first_child) {
                xml_san_buffer_append_str(buf, "/>");
            } else {
                xml_san_buffer_append_char(buf, '>');

                xml_san_error_t err = process_node(ctx, first_child, buf, depth + 1);
                if(err != XML_SAN_OK) {
                    free(name_copy);
                    return err;
                }

                xml_san_buffer_append_str(buf, "</");
                xml_san_buffer_append_str(buf, output_name);
                xml_san_buffer_append_char(buf, '>');
            }

            free(name_copy);
            break;
        }

        case MXML_TYPE_TEXT:
        case MXML_TYPE_OPAQUE: {
            const char* text = NULL;
            bool whitespace = false;

            if(type == MXML_TYPE_TEXT) {
                text = mxmlGetText(cur, &whitespace);
            } else {
                text = mxmlGetOpaque(cur);
            }

            if(!text) {
                break;
            }

            if(ctx->config.options & XML_SAN_OPT_NORMALIZE_WS) {
                bool last_was_space = false;
                for(const char* p = text; *p; p++) {
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
                if(whitespace) {
                    xml_san_buffer_append_char(buf, ' ');
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
            break;
        }

        case MXML_TYPE_CDATA: {
            const char* cdata = mxmlGetCDATA(cur);
            if(!(ctx->config.options & XML_SAN_OPT_STRIP_CDATA) && cdata) {
                xml_san_buffer_append_str(buf, "<![CDATA[");
                xml_san_buffer_append_str(buf, cdata);
                xml_san_buffer_append_str(buf, "]]>");
            }
            break;
        }

        case MXML_TYPE_COMMENT: {
            const char* comment = mxmlGetComment(cur);
            if(!(ctx->config.options & XML_SAN_OPT_STRIP_COMMENTS) && comment) {
                xml_san_buffer_append_str(buf, "<!--");
                xml_san_buffer_append_str(buf, comment);
                xml_san_buffer_append_str(buf, "-->");
            } else if(comment) {
                ctx->stats.comments_removed++;
            }
            break;
        }

        case MXML_TYPE_DIRECTIVE: {
            const char* directive = mxmlGetDirective(cur);
            if(directive) {
                if((strncmp(directive, "DOCTYPE", 7) == 0) ||
                   (strncmp(directive, "doctype", 7) == 0)) {
                    if(!(ctx->config.options & XML_SAN_OPT_STRIP_DTD)) {
                        xml_san_buffer_append_str(buf, "<!");
                        xml_san_buffer_append_str(buf, directive);
                        xml_san_buffer_append_char(buf, '>');
                    }
                } else {
                    if(!(ctx->config.options & XML_SAN_OPT_STRIP_PI)) {
                        xml_san_buffer_append_str(buf, "<?");
                        xml_san_buffer_append_str(buf, directive);
                        xml_san_buffer_append_str(buf, "?>");
                    }
                }
            }
            break;
        }

        default:
            break;
        }
    }

    return XML_SAN_OK;
}

/*
 * Initialize MXML backend
 */
static int mxml_backend_init(xml_san_ctx_t* ctx) {
    mxml_ctx_t* mctx = calloc(1, sizeof(*mctx));
    if(!mctx) {
        return -1;
    }

    ctx->backend_data = mctx;
    return 0;
}

/*
 * Cleanup MXML backend
 */
static void mxml_backend_cleanup(xml_san_ctx_t* ctx) {
    if(!ctx || !ctx->backend_data) {
        return;
    }

    free(ctx->backend_data);
    ctx->backend_data = NULL;
}

/*
 * Main sanitization function using MXML
 */
static xml_san_error_t mxml_sanitize(xml_san_ctx_t* ctx,
                                     const char* input, size_t input_len,
                                     char** output, size_t* output_len) {
    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    (void) input_len;

    mxml_options_t* options = mxmlOptionsNew();
    if(!options) {
        return XML_SAN_ERR_MEMORY;
    }

    mxmlOptionsSetTypeCallback(options, type_cb, NULL);

    mxml_node_t* tree = mxmlLoadString(NULL, options, input);
    mxmlOptionsDelete(options);

    if(!tree) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    xml_san_buffer_t buf;
    if(xml_san_buffer_init(&buf, input_len + 256) != 0) {
        mxmlDelete(tree);
        return XML_SAN_ERR_MEMORY;
    }

    mxml_node_t* first = mxmlGetFirstChild(tree);
    xml_san_error_t err = process_node(ctx, first, &buf, 0);

    mxmlDelete(tree);

    if(err != XML_SAN_OK) {
        xml_san_buffer_cleanup(&buf);
        return err;
    }

    *output = xml_san_buffer_detach(&buf, output_len);
    return *output ? XML_SAN_OK : XML_SAN_ERR_MEMORY;
}

/*
 * Validation using MXML
 */
static xml_san_error_t mxml_validate(xml_san_ctx_t* ctx,
                                     const char* input, size_t input_len) {
    (void) ctx;
    (void) input_len;

    mxml_node_t* tree = mxmlLoadString(NULL, NULL, input);
    if(!tree) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    mxmlDelete(tree);
    return XML_SAN_OK;
}

/*
 * Text escaping
 */
static xml_san_error_t mxml_escape_text(xml_san_ctx_t* ctx,
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
static xml_san_error_t mxml_escape_attr(xml_san_ctx_t* ctx,
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

const xml_san_backend_ops_t xml_san_backend_mxml = {
    .name = "mxml",
    .init = mxml_backend_init,
    .cleanup = mxml_backend_cleanup,
    .sanitize = mxml_sanitize,
    .validate = mxml_validate,
    .escape_text = mxml_escape_text,
    .escape_attr = mxml_escape_attr
};
