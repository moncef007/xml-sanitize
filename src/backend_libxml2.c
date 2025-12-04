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
#include <ctype.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/encoding.h>

/* Backend-specific context data */
typedef struct {
    xmlParserCtxtPtr parser_ctx;
} libxml2_ctx_t;

/*
 * Initialize libxml2 backend
 */
static int libxml2_init(xml_san_ctx_t* ctx) {
    libxml2_ctx_t* lctx = calloc(1, sizeof(*lctx));
    if(!lctx) {
        return -1;
    }

    LIBXML_TEST_VERSION

    ctx->backend_data = lctx;
    return 0;
}

/*
 * Cleanup libxml2 backend
 */
static void libxml2_cleanup(xml_san_ctx_t* ctx) {
    if(!ctx || !ctx->backend_data) {
        return;
    }

    libxml2_ctx_t* lctx = ctx->backend_data;

    if(lctx->parser_ctx) {
        xmlFreeParserCtxt(lctx->parser_ctx);
    }

    free(lctx);
    ctx->backend_data = NULL;

    xmlCleanupParser();
}

/*
 * Process a single node recursively
 */
static xml_san_error_t process_node(xml_san_ctx_t* ctx, xmlNodePtr node,
                                    xml_san_buffer_t* buf, int depth) {
    if(!node) {
        return XML_SAN_OK;
    }

    if((ctx->config.max_depth > 0) && ((size_t) depth > ctx->config.max_depth)) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    for(xmlNodePtr cur = node; cur; cur = cur->next) {
        switch(cur->type) {
        case XML_ELEMENT_NODE: {
            const char* name = (const char*) cur->name;
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
                /* Still process children if not stripping all tags */
                if(!(ctx->config.options & XML_SAN_OPT_STRIP_TAGS)) {
                    xml_san_error_t err = process_node(ctx, cur->children, buf, depth + 1);
                    if(err != XML_SAN_OK) {
                        return err;
                    }
                }
                continue;
            }

            if((ctx->config.options & XML_SAN_OPT_REMOVE_EMPTY_TAGS) &&
               !cur->children && !cur->properties) {
                ctx->stats.elements_removed++;
                continue;
            }

            xml_san_buffer_append_char(buf, '<');

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

            xml_san_buffer_append_str(buf, output_name);

            int attr_count = 0;
            for(xmlAttrPtr attr = cur->properties; attr; attr = attr->next) {
                const char* attr_name = (const char*) attr->name;
                ctx->stats.attrs_processed++;
                attr_count++;

                if((ctx->config.max_attr_count > 0) &&
                   ((size_t) attr_count > ctx->config.max_attr_count)) {
                    ctx->stats.attrs_removed++;
                    continue;
                }

                if(!xml_san_attr_allowed(ctx, attr_name)) {
                    ctx->stats.attrs_removed++;
                    continue;
                }

                xmlChar* value = xmlNodeGetContent(attr->children);
                const char* val_str = value ? (const char*) value : "";

                if((ctx->config.max_attr_len > 0) &&
                   (strlen(val_str) > ctx->config.max_attr_len)) {
                    ctx->stats.attrs_removed++;
                    xmlFree(value);
                    continue;
                }

                if(ctx->config.filter_fn) {
                    if(!ctx->config.filter_fn(name, attr_name, val_str,
                                              ctx->config.user_data)) {
                        ctx->stats.attrs_removed++;
                        xmlFree(value);
                        continue;
                    }
                }

                xml_san_buffer_append_char(buf, ' ');
                xml_san_buffer_append_str(buf, attr_name);
                xml_san_buffer_append_str(buf, "=\"");

                for(const char* vp = val_str; *vp; vp++) {
                    switch(*vp) {
                    case '&': xml_san_buffer_append_str(buf, "&amp;"); break;
                    case '<': xml_san_buffer_append_str(buf, "&lt;"); break;
                    case '>': xml_san_buffer_append_str(buf, "&gt;"); break;
                    case '"': xml_san_buffer_append_str(buf, "&quot;"); break;
                    default: xml_san_buffer_append_char(buf, *vp); break;
                    }
                }

                xml_san_buffer_append_char(buf, '"');
                xmlFree(value);
            }

            if(!cur->children) {
                xml_san_buffer_append_str(buf, "/>");
            } else {
                xml_san_buffer_append_char(buf, '>');

                xml_san_error_t err = process_node(ctx, cur->children, buf, depth + 1);
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

        case XML_TEXT_NODE: {
            const char* content = (const char*) cur->content;
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
            break;
        }

        case XML_CDATA_SECTION_NODE:
            if(!(ctx->config.options & XML_SAN_OPT_STRIP_CDATA)) {
                xml_san_buffer_append_str(buf, "<![CDATA[");
                xml_san_buffer_append_str(buf, (const char*) cur->content);
                xml_san_buffer_append_str(buf, "]]>");
            }
            break;

        case XML_COMMENT_NODE:
            if(!(ctx->config.options & XML_SAN_OPT_STRIP_COMMENTS)) {
                xml_san_buffer_append_str(buf, "<!--");
                xml_san_buffer_append_str(buf, (const char*) cur->content);
                xml_san_buffer_append_str(buf, "-->");
            } else {
                ctx->stats.comments_removed++;
            }
            break;

        case XML_PI_NODE:
            if(!(ctx->config.options & XML_SAN_OPT_STRIP_PI)) {
                xml_san_buffer_append_str(buf, "<?");
                xml_san_buffer_append_str(buf, (const char*) cur->name);
                if(cur->content) {
                    xml_san_buffer_append_char(buf, ' ');
                    xml_san_buffer_append_str(buf, (const char*) cur->content);
                }
                xml_san_buffer_append_str(buf, "?>");
            }
            break;

        default:
            break;
        }
    }

    return XML_SAN_OK;
}

/*
 * Main sanitization function using libxml2
 */
static xml_san_error_t libxml2_sanitize(xml_san_ctx_t* ctx,
                                        const char* input, size_t input_len,
                                        char** output, size_t* output_len) {
    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    xmlDocPtr doc = xmlReadMemory(input, input_len, NULL, NULL,
                                  XML_PARSE_NONET | XML_PARSE_NOENT |
                                  XML_PARSE_NOCDATA | XML_PARSE_RECOVER);

    if(!doc) {
        doc = xmlReadMemory(input, input_len, NULL, NULL,
                            XML_PARSE_NONET | XML_PARSE_RECOVER |
                            XML_PARSE_NOERROR | XML_PARSE_NOWARNING);

        if(!doc) {
            return XML_SAN_ERR_PARSE_FAILED;
        }
    }

    xml_san_buffer_t buf;
    if(xml_san_buffer_init(&buf, input_len + 256) != 0) {
        xmlFreeDoc(doc);
        return XML_SAN_ERR_MEMORY;
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    xml_san_error_t err = process_node(ctx, root, &buf, 0);

    xmlFreeDoc(doc);

    if(err != XML_SAN_OK) {
        xml_san_buffer_cleanup(&buf);
        return err;
    }

    *output = xml_san_buffer_detach(&buf, output_len);
    return *output ? XML_SAN_OK : XML_SAN_ERR_MEMORY;
}

/*
 * Validation using libxml2
 */
static xml_san_error_t libxml2_validate(xml_san_ctx_t* ctx,
                                        const char* input, size_t input_len) {
    (void) ctx;

    xmlDocPtr doc = xmlReadMemory(input, input_len, NULL, NULL,
                                  XML_PARSE_NONET | XML_PARSE_NOENT);

    if(!doc) {
        return XML_SAN_ERR_PARSE_FAILED;
    }

    xmlFreeDoc(doc);
    return XML_SAN_OK;
}

/*
 * Text escaping using libxml2
 */
static xml_san_error_t libxml2_escape_text(xml_san_ctx_t* ctx,
                                           const char* input,
                                           char** output) {
    (void) ctx;

    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    xmlChar* escaped = xmlEncodeSpecialChars(NULL, (const xmlChar*) input);
    if(!escaped) {
        return XML_SAN_ERR_MEMORY;
    }

    *output = strdup((const char*) escaped);
    xmlFree(escaped);

    return *output ? XML_SAN_OK : XML_SAN_ERR_MEMORY;
}

/*
 * Attribute escaping using libxml2
 */
static xml_san_error_t libxml2_escape_attr(xml_san_ctx_t* ctx,
                                           const char* input,
                                           char** output) {
    (void) ctx;

    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    /* libxml2 doesn't have a dedicated function for this,
     * so we implement our own */
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

const xml_san_backend_ops_t xml_san_backend_libxml2 = {
    .name = "libxml2",
    .init = libxml2_init,
    .cleanup = libxml2_cleanup,
    .sanitize = libxml2_sanitize,
    .validate = libxml2_validate,
    .escape_text = libxml2_escape_text,
    .escape_attr = libxml2_escape_attr
};
