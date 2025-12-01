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
#include <roxml.h>
#include <ctype.h>

typedef struct {
    int reserved;
} roxml_ctx_t;

/*
 * Process a single node recursively
 */
static xml_san_error_t process_node(xml_san_ctx_t* ctx, node_t* node,
                                    xml_san_buffer_t* buf, int depth) {
    if(!node) {
        return XML_SAN_OK;
    }

    if((ctx->config.max_depth > 0) && ((size_t) depth > ctx->config.max_depth)) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    int type = roxml_get_type(node);

    switch(type) {
    case ROXML_ELM_NODE: {
        char* name = roxml_get_name(node, NULL, 0);
        if(!name) {
            break;
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
            roxml_release(name);

            if(!(ctx->config.options & XML_SAN_OPT_STRIP_TAGS)) {
                int child_count = roxml_get_chld_nb(node);
                for(int i = 0; i < child_count; i++) {
                    node_t* child = roxml_get_chld(node, NULL, i);
                    if(child) {
                        xml_san_error_t err = process_node(ctx, child, buf, depth + 1);
                        if(err != XML_SAN_OK) {
                            return err;
                        }
                    }
                }
            }
            break;
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

        int child_count = roxml_get_chld_nb(node);
        int attr_count_check = roxml_get_attr_nb(node);
        char* content = roxml_get_content(node, NULL, 0, NULL);
        bool has_content = (child_count > 0) || (content && content[0]);
        roxml_release(content);

        if((ctx->config.options & XML_SAN_OPT_REMOVE_EMPTY_TAGS) &&
           !has_content && (attr_count_check == 0)) {
            ctx->stats.elements_removed++;
            roxml_release(name);
            free(name_copy);
            break;
        }

        xml_san_buffer_append_char(buf, '<');
        xml_san_buffer_append_str(buf, output_name);

        int attr_count = roxml_get_attr_nb(node);
        int processed_attrs = 0;

        for(int i = 0; i < attr_count; i++) {
            node_t* attr = roxml_get_attr(node, NULL, i);
            if(!attr) {
                continue;
            }

            char* attr_name = roxml_get_name(attr, NULL, 0);
            char* attr_value = roxml_get_content(attr, NULL, 0, NULL);

            if(!attr_name) {
                roxml_release(attr_value);
                continue;
            }

            ctx->stats.attrs_processed++;
            processed_attrs++;

            bool attr_allowed = true;

            if((ctx->config.max_attr_count > 0) &&
               ((size_t) processed_attrs > ctx->config.max_attr_count)) {
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

            roxml_release(attr_name);
            roxml_release(attr_value);
        }

        if(!has_content) {
            xml_san_buffer_append_str(buf, "/>");
        } else {
            xml_san_buffer_append_char(buf, '>');

            for(int i = 0; i < child_count; i++) {
                node_t* child = roxml_get_chld(node, NULL, i);
                if(child) {
                    xml_san_error_t err = process_node(ctx, child, buf, depth + 1);
                    if(err != XML_SAN_OK) {
                        roxml_release(name);
                        free(name_copy);
                        return err;
                    }
                }
            }

            xml_san_buffer_append_str(buf, "</");
            xml_san_buffer_append_str(buf, output_name);
            xml_san_buffer_append_char(buf, '>');
        }

        roxml_release(name);
        free(name_copy);
        break;
    }

    case ROXML_TXT_NODE: {
        char* content = roxml_get_content(node, NULL, 0, NULL);
        if(!content) {
            break;
        }

        if(ctx->config.options & XML_SAN_OPT_NORMALIZE_WS) {
            bool last_was_space = false;
            for(const char* p = content; *p; p++) {
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
            for(const char* p = content; *p; p++) {
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

        roxml_release(content);
        break;
    }

    case ROXML_CMT_NODE: {
        if(!(ctx->config.options & XML_SAN_OPT_STRIP_COMMENTS)) {
            char* content = roxml_get_content(node, NULL, 0, NULL);
            if(content) {
                xml_san_buffer_append_str(buf, "<!--");
                xml_san_buffer_append_str(buf, content);
                xml_san_buffer_append_str(buf, "-->");
                roxml_release(content);
            }
        } else {
            ctx->stats.comments_removed++;
        }
        break;
    }

    case ROXML_PI_NODE: {
        if(!(ctx->config.options & XML_SAN_OPT_STRIP_PI)) {
            char* name = roxml_get_name(node, NULL, 0);
            char* content = roxml_get_content(node, NULL, 0, NULL);
            if(name) {
                xml_san_buffer_append_str(buf, "<?");
                xml_san_buffer_append_str(buf, name);
                if(content && content[0]) {
                    xml_san_buffer_append_char(buf, ' ');
                    xml_san_buffer_append_str(buf, content);
                }
                xml_san_buffer_append_str(buf, "?>");
            }
            roxml_release(name);
            roxml_release(content);
        }
        break;
    }

    case ROXML_CDATA_NODE: {
        if(!(ctx->config.options & XML_SAN_OPT_STRIP_CDATA)) {
            char* content = roxml_get_content(node, NULL, 0, NULL);
            if(content) {
                xml_san_buffer_append_str(buf, "<![CDATA[");
                xml_san_buffer_append_str(buf, content);
                xml_san_buffer_append_str(buf, "]]>");
                roxml_release(content);
            }
        }
        break;
    }

    default:
        break;
    }

    return XML_SAN_OK;
}

/*
 * Initialize roxml backend
 */
static int roxml_backend_init(xml_san_ctx_t* ctx) {
    roxml_ctx_t* rctx = calloc(1, sizeof(*rctx));
    if(!rctx) {
        return -1;
    }

    ctx->backend_data = rctx;
    return 0;
}

/*
 * Cleanup roxml backend
 */
static void roxml_backend_cleanup(xml_san_ctx_t* ctx) {
    if(!ctx || !ctx->backend_data) {
        return;
    }

    free(ctx->backend_data);
    ctx->backend_data = NULL;
}

/*
 * Main sanitization function using roxml
 */
static xml_san_error_t roxml_sanitize(xml_san_ctx_t* ctx,
                                      const char* input, size_t input_len,
                                      char** output, size_t* output_len) {
    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    (void) input_len;

    node_t* root = roxml_load_buf((char*) input);
    if(!root) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    xml_san_buffer_t buf;
    if(xml_san_buffer_init(&buf, input_len + 256) != 0) {
        roxml_close(root);
        return XML_SAN_ERR_MEMORY;
    }

    int child_count = roxml_get_chld_nb(root);
    for(int i = 0; i < child_count; i++) {
        node_t* child = roxml_get_chld(root, NULL, i);
        if(child) {
            xml_san_error_t err = process_node(ctx, child, &buf, 0);
            if(err != XML_SAN_OK) {
                xml_san_buffer_cleanup(&buf);
                roxml_close(root);
                return err;
            }
        }
    }

    roxml_close(root);

    *output = xml_san_buffer_detach(&buf, output_len);
    return *output ? XML_SAN_OK : XML_SAN_ERR_MEMORY;
}

/*
 * Validation using roxml
 */
static xml_san_error_t roxml_validate(xml_san_ctx_t* ctx,
                                      const char* input, size_t input_len) {
    (void) ctx;
    (void) input_len;

    node_t* root = roxml_load_buf((char*) input);
    if(!root) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    roxml_close(root);
    return XML_SAN_OK;
}

/*
 * Text escaping
 */
static xml_san_error_t roxml_escape_text(xml_san_ctx_t* ctx,
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
static xml_san_error_t roxml_escape_attr(xml_san_ctx_t* ctx,
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

const xml_san_backend_ops_t xml_san_backend_roxml = {
    .name = "roxml",
    .init = roxml_backend_init,
    .cleanup = roxml_backend_cleanup,
    .sanitize = roxml_sanitize,
    .validate = roxml_validate,
    .escape_text = roxml_escape_text,
    .escape_attr = roxml_escape_attr
};