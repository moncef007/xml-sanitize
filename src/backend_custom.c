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

typedef enum {
    STATE_TEXT,
    STATE_TAG_OPEN,
    STATE_TAG_NAME,
    STATE_TAG_CLOSE,
    STATE_ATTR_NAME,
    STATE_ATTR_EQ,
    STATE_ATTR_VALUE,
    STATE_COMMENT,
    STATE_CDATA,
    STATE_PI,
    STATE_DOCTYPE
} parser_state_t;

/*
 * Escape special characters for XML
 */
static xml_san_error_t custom_escape_text(xml_san_ctx_t* ctx,
                                          const char* input,
                                          char** output) {
    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    size_t input_len = strlen(input);
    xml_san_buffer_t buf;

    if(xml_san_buffer_init(&buf, input_len * 2 + 1) != 0) {
        return XML_SAN_ERR_MEMORY;
    }

    const unsigned char* p = (const unsigned char*) input;

    while(*p) {
        if((ctx->config.options & XML_SAN_OPT_REMOVE_CTRL) &&
           xml_san_is_ctrl_char(*p)) {
            ((xml_san_ctx_t*) ctx)->stats.ctrl_chars_removed++;
            p++;
            continue;
        }

        if(ctx->config.options & XML_SAN_OPT_ESCAPE_ENTITIES) {
            switch(*p) {
            case '&':
                xml_san_buffer_append_str(&buf, "&amp;");
                ((xml_san_ctx_t*) ctx)->stats.entities_escaped++;
                break;
            case '<':
                xml_san_buffer_append_str(&buf, "&lt;");
                ((xml_san_ctx_t*) ctx)->stats.entities_escaped++;
                break;
            case '>':
                xml_san_buffer_append_str(&buf, "&gt;");
                ((xml_san_ctx_t*) ctx)->stats.entities_escaped++;
                break;
            default:
                xml_san_buffer_append_char(&buf, *p);
                break;
            }
        } else {
            xml_san_buffer_append_char(&buf, *p);
        }
        p++;
    }

    *output = xml_san_buffer_detach(&buf, NULL);
    return *output ? XML_SAN_OK : XML_SAN_ERR_MEMORY;
}

/*
 * Escape attribute value (includes quote handling)
 */
static xml_san_error_t custom_escape_attr(xml_san_ctx_t* ctx,
                                          const char* input,
                                          char** output) {
    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    size_t input_len = strlen(input);
    xml_san_buffer_t buf;

    if(xml_san_buffer_init(&buf, input_len * 2 + 1) != 0) {
        return XML_SAN_ERR_MEMORY;
    }

    const unsigned char* p = (const unsigned char*) input;

    while(*p) {
        if((ctx->config.options & XML_SAN_OPT_REMOVE_CTRL) &&
           xml_san_is_ctrl_char(*p)) {
            p++;
            continue;
        }

        switch(*p) {
        case '&':
            xml_san_buffer_append_str(&buf, "&amp;");
            break;
        case '<':
            xml_san_buffer_append_str(&buf, "&lt;");
            break;
        case '>':
            xml_san_buffer_append_str(&buf, "&gt;");
            break;
        case '"':
            xml_san_buffer_append_str(&buf, "&quot;");
            break;
        case '\'':
            xml_san_buffer_append_str(&buf, "&apos;");
            break;
        default:
            xml_san_buffer_append_char(&buf, *p);
            break;
        }
        p++;
    }

    *output = xml_san_buffer_detach(&buf, NULL);
    return *output ? XML_SAN_OK : XML_SAN_ERR_MEMORY;
}

/*
 * Skip whitespace
 */
static const char* skip_ws(const char* p, const char* end) {
    while(p < end && isspace((unsigned char) *p)) {
        p++;
    }
    return p;
}

/*
 * Check if we're at a specific string
 */
static bool at_string(const char* p, const char* end, const char* str) {
    size_t len = strlen(str);
    if((size_t) (end - p) < len) {
        return false;
    }
    return strncmp(p, str, len) == 0;
}

/*
 * Find closing sequence
 */
static const char* find_closing(const char* p, const char* end, const char* seq) {
    size_t len = strlen(seq);
    while(p + len <= end) {
        if(strncmp(p, seq, len) == 0) {
            return p;
        }
        p++;
    }
    return NULL;
}

/*
 * Extract tag name
 */
static size_t extract_name(const char* p, const char* end, char* buf, size_t buf_size) {
    size_t i = 0;
    while(p < end && i < buf_size - 1) {
        char c = *p;
        if(isalnum((unsigned char) c) || (c == '_') || (c == '-') || (c == ':') || (c == '.')) {
            buf[i++] = c;
            p++;
        } else {
            break;
        }
    }
    buf[i] = '\0';
    return i;
}

/*
 * Main sanitization function
 */
static xml_san_error_t custom_sanitize(xml_san_ctx_t* ctx,
                                       const char* input, size_t input_len,
                                       char** output, size_t* output_len) {
    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    xml_san_buffer_t buf;
    if(xml_san_buffer_init(&buf, input_len + 256) != 0) {
        return XML_SAN_ERR_MEMORY;
    }

    const char* p = input;
    const char* end = input + input_len;
    const char* text_start = p;
    char name_buf[256];
    char attr_name[256];
    char attr_value[65536];
    bool is_close_tag = false;
    int depth = 0;

    if(ctx->config.options & XML_SAN_OPT_VALIDATE_UTF8) {
        if(xml_san_utf8_validate(input, input_len) != 0) {
            if(!(ctx->config.options & XML_SAN_OPT_FIX_UTF8)) {
                xml_san_buffer_cleanup(&buf);
                return XML_SAN_ERR_INVALID_UTF8;
            }
        }
    }

    while(p < end) {
        if(at_string(p, end, "<!--")) {
            if(text_start < p) {
                for(const char* tp = text_start; tp < p; tp++) {
                    if((ctx->config.options & XML_SAN_OPT_REMOVE_CTRL) &&
                       xml_san_is_ctrl_char((unsigned char) *tp)) {
                        ctx->stats.ctrl_chars_removed++;
                        continue;
                    }
                    if((ctx->config.options & XML_SAN_OPT_ESCAPE_ENTITIES)) {
                        switch(*tp) {
                        case '&': xml_san_buffer_append_str(&buf, "&amp;"); break;
                        case '<': xml_san_buffer_append_str(&buf, "&lt;"); break;
                        case '>': xml_san_buffer_append_str(&buf, "&gt;"); break;
                        default: xml_san_buffer_append_char(&buf, *tp); break;
                        }
                    } else {
                        xml_san_buffer_append_char(&buf, *tp);
                    }
                }
            }

            const char* comment_end = find_closing(p + 4, end, "-->");
            if(!comment_end) {
                xml_san_buffer_cleanup(&buf);
                return XML_SAN_ERR_PARSE_FAILED;
            }

            if(!(ctx->config.options & XML_SAN_OPT_STRIP_COMMENTS)) {
                xml_san_buffer_append(&buf, p, comment_end + 3 - p);
            } else {
                ctx->stats.comments_removed++;
            }

            p = comment_end + 3;
            text_start = p;
            continue;
        }

        if(at_string(p, end, "<![CDATA[")) {
            if(text_start < p) {
                for(const char* tp = text_start; tp < p; tp++) {
                    if((ctx->config.options & XML_SAN_OPT_REMOVE_CTRL) &&
                       xml_san_is_ctrl_char((unsigned char) *tp)) {
                        continue;
                    }
                    if((ctx->config.options & XML_SAN_OPT_ESCAPE_ENTITIES)) {
                        switch(*tp) {
                        case '&': xml_san_buffer_append_str(&buf, "&amp;"); break;
                        case '<': xml_san_buffer_append_str(&buf, "&lt;"); break;
                        case '>': xml_san_buffer_append_str(&buf, "&gt;"); break;
                        default: xml_san_buffer_append_char(&buf, *tp); break;
                        }
                    } else {
                        xml_san_buffer_append_char(&buf, *tp);
                    }
                }
            }

            const char* cdata_end = find_closing(p + 9, end, "]]>");
            if(!cdata_end) {
                xml_san_buffer_cleanup(&buf);
                return XML_SAN_ERR_PARSE_FAILED;
            }

            if(!(ctx->config.options & XML_SAN_OPT_STRIP_CDATA)) {
                xml_san_buffer_append(&buf, p, cdata_end + 3 - p);
            }

            p = cdata_end + 3;
            text_start = p;
            continue;
        }

        if(at_string(p, end, "<?")) {
            if(text_start < p) {
                for(const char* tp = text_start; tp < p; tp++) {
                    if((ctx->config.options & XML_SAN_OPT_REMOVE_CTRL) &&
                       xml_san_is_ctrl_char((unsigned char) *tp)) {
                        continue;
                    }
                    if((ctx->config.options & XML_SAN_OPT_ESCAPE_ENTITIES)) {
                        switch(*tp) {
                        case '&': xml_san_buffer_append_str(&buf, "&amp;"); break;
                        case '<': xml_san_buffer_append_str(&buf, "&lt;"); break;
                        case '>': xml_san_buffer_append_str(&buf, "&gt;"); break;
                        default: xml_san_buffer_append_char(&buf, *tp); break;
                        }
                    } else {
                        xml_san_buffer_append_char(&buf, *tp);
                    }
                }
            }

            const char* pi_end = find_closing(p + 2, end, "?>");
            if(!pi_end) {
                xml_san_buffer_cleanup(&buf);
                return XML_SAN_ERR_PARSE_FAILED;
            }

            if(!(ctx->config.options & XML_SAN_OPT_STRIP_PI)) {
                xml_san_buffer_append(&buf, p, pi_end + 2 - p);
            }

            p = pi_end + 2;
            text_start = p;
            continue;
        }

        if(at_string(p, end, "<!DOCTYPE") || at_string(p, end, "<!doctype")) {
            if(text_start < p) {
                for(const char* tp = text_start; tp < p; tp++) {
                    if((ctx->config.options & XML_SAN_OPT_ESCAPE_ENTITIES)) {
                        switch(*tp) {
                        case '&': xml_san_buffer_append_str(&buf, "&amp;"); break;
                        case '<': xml_san_buffer_append_str(&buf, "&lt;"); break;
                        case '>': xml_san_buffer_append_str(&buf, "&gt;"); break;
                        default: xml_san_buffer_append_char(&buf, *tp); break;
                        }
                    } else {
                        xml_san_buffer_append_char(&buf, *tp);
                    }
                }
            }

            int bracket_depth = 0;
            const char* dp = p;
            while(dp < end) {
                if(*dp == '[') {
                    bracket_depth++;
                } else if(*dp == ']') {
                    bracket_depth--;
                } else if((*dp == '>') && (bracket_depth == 0)) {
                    break;
                }
                dp++;
            }

            if(dp >= end) {
                xml_san_buffer_cleanup(&buf);
                return XML_SAN_ERR_PARSE_FAILED;
            }

            if(!(ctx->config.options & XML_SAN_OPT_STRIP_DTD)) {
                xml_san_buffer_append(&buf, p, dp + 1 - p);
            }

            p = dp + 1;
            text_start = p;
            continue;
        }

        if(*p == '<') {
            if(text_start < p) {
                for(const char* tp = text_start; tp < p; tp++) {
                    if((ctx->config.options & XML_SAN_OPT_REMOVE_CTRL) &&
                       xml_san_is_ctrl_char((unsigned char) *tp)) {
                        ctx->stats.ctrl_chars_removed++;
                        continue;
                    }
                    if((ctx->config.options & XML_SAN_OPT_ESCAPE_ENTITIES)) {
                        switch(*tp) {
                        case '&': xml_san_buffer_append_str(&buf, "&amp;"); break;
                        case '<': xml_san_buffer_append_str(&buf, "&lt;"); break;
                        case '>': xml_san_buffer_append_str(&buf, "&gt;"); break;
                        default: xml_san_buffer_append_char(&buf, *tp); break;
                        }
                    } else {
                        xml_san_buffer_append_char(&buf, *tp);
                    }
                }
            }

            p++;
            is_close_tag = false;

            if((p < end) && (*p == '/')) {
                is_close_tag = true;
                p++;
            }

            size_t name_len = extract_name(p, end, name_buf, sizeof(name_buf));
            if(name_len == 0) {
                xml_san_buffer_append_str(&buf, "&lt;");
                text_start = p - (is_close_tag ? 2 : 1);
                p = text_start + 1;
                continue;
            }

            p += name_len;
            ctx->stats.elements_processed++;

            bool tag_allowed = true;
            if(ctx->config.options & XML_SAN_OPT_STRIP_TAGS) {
                tag_allowed = false;
            } else if(!xml_san_tag_allowed(ctx, name_buf)) {
                tag_allowed = false;
            }

            if(tag_allowed && ctx->config.filter_fn) {
                tag_allowed = ctx->config.filter_fn(name_buf, NULL, NULL,
                                                    ctx->config.user_data);
            }

            if(!tag_allowed) {
                ctx->stats.elements_removed++;
                while(p < end && *p != '>') {
                    p++;
                }
                if(p < end) {
                    p++;
                }
                text_start = p;
                continue;
            }

            if(ctx->config.options & XML_SAN_OPT_LOWERCASE_TAGS) {
                for(size_t i = 0; name_buf[i]; i++) {
                    name_buf[i] = tolower((unsigned char) name_buf[i]);
                }
            }

            char* tag_output = name_buf;
            if(ctx->config.options & XML_SAN_OPT_STRIP_NAMESPACES) {
                char* colon = strchr(name_buf, ':');
                if(colon) {
                    tag_output = colon + 1;
                }
            }

            xml_san_buffer_append_char(&buf, '<');
            if(is_close_tag) {
                xml_san_buffer_append_char(&buf, '/');
                depth--;
            } else {
                depth++;
            }
            xml_san_buffer_append_str(&buf, tag_output);

            if((ctx->config.max_depth > 0) && (depth > (int) ctx->config.max_depth)) {
                xml_san_buffer_cleanup(&buf);
                return XML_SAN_ERR_PARSE_FAILED;
            }

            int attr_count = 0;
            while(p < end && *p != '>' && *p != '/') {
                p = skip_ws(p, end);
                if((p >= end) || (*p == '>') || (*p == '/')) {
                    break;
                }

                size_t attr_name_len = extract_name(p, end, attr_name, sizeof(attr_name));
                if(attr_name_len == 0) {
                    break;
                }

                p += attr_name_len;
                ctx->stats.attrs_processed++;
                attr_count++;

                if((ctx->config.max_attr_count > 0) &&
                   ((size_t) attr_count > ctx->config.max_attr_count)) {
                    ctx->stats.attrs_removed++;
                    p = skip_ws(p, end);
                    if((p < end) && (*p == '=')) {
                        p++;
                        p = skip_ws(p, end);
                        if((p < end) && ((*p == '"') || (*p == '\''))) {
                            char quote = *p++;
                            while(p < end && *p != quote) {
                                p++;
                            }
                            if(p < end) {
                                p++;
                            }
                        }
                    }
                    continue;
                }

                bool attr_allowed = xml_san_attr_allowed(ctx, attr_name);
                if(attr_allowed && ctx->config.filter_fn) {
                    attr_allowed = ctx->config.filter_fn(name_buf, attr_name, NULL,
                                                         ctx->config.user_data);
                }

                p = skip_ws(p, end);
                if((p < end) && (*p == '=')) {
                    p++;
                    p = skip_ws(p, end);

                    if((p < end) && ((*p == '"') || (*p == '\''))) {
                        char quote = *p++;
                        const char* val_start = p;
                        while(p < end && *p != quote) {
                            p++;
                        }

                        size_t val_len = p - val_start;
                        if(val_len >= sizeof(attr_value)) {
                            val_len = sizeof(attr_value) - 1;
                        }

                        if((ctx->config.max_attr_len > 0) &&
                           (val_len > ctx->config.max_attr_len)) {
                            attr_allowed = false;
                        }

                        memcpy(attr_value, val_start, val_len);
                        attr_value[val_len] = '\0';

                        if(p < end) {
                            p++;
                        }

                        if(attr_allowed && ctx->config.filter_fn) {
                            attr_allowed = ctx->config.filter_fn(name_buf, attr_name,
                                                                 attr_value,
                                                                 ctx->config.user_data);
                        }

                        if(attr_allowed) {
                            xml_san_buffer_append_char(&buf, ' ');
                            xml_san_buffer_append_str(&buf, attr_name);
                            xml_san_buffer_append_str(&buf, "=\"");

                            for(size_t i = 0; attr_value[i]; i++) {
                                switch(attr_value[i]) {
                                case '&': xml_san_buffer_append_str(&buf, "&amp;"); break;
                                case '<': xml_san_buffer_append_str(&buf, "&lt;"); break;
                                case '>': xml_san_buffer_append_str(&buf, "&gt;"); break;
                                case '"': xml_san_buffer_append_str(&buf, "&quot;"); break;
                                default: xml_san_buffer_append_char(&buf, attr_value[i]); break;
                                }
                            }
                            xml_san_buffer_append_char(&buf, '"');
                        } else {
                            ctx->stats.attrs_removed++;
                        }
                    }
                } else if(attr_allowed) {
                    xml_san_buffer_append_char(&buf, ' ');
                    xml_san_buffer_append_str(&buf, attr_name);
                }
            }

            if((p < end) && (*p == '/')) {
                xml_san_buffer_append_str(&buf, "/");
                depth--;
                p++;
            }

            while(p < end && *p != '>') {
                p++;
            }
            if(p < end) {
                xml_san_buffer_append_char(&buf, '>');
                p++;
            }

            text_start = p;
            continue;
        }

        p++;
    }

    if(text_start < end) {
        for(const char* tp = text_start; tp < end; tp++) {
            if((ctx->config.options & XML_SAN_OPT_REMOVE_CTRL) &&
               xml_san_is_ctrl_char((unsigned char) *tp)) {
                ctx->stats.ctrl_chars_removed++;
                continue;
            }
            if((ctx->config.options & XML_SAN_OPT_ESCAPE_ENTITIES)) {
                switch(*tp) {
                case '&': xml_san_buffer_append_str(&buf, "&amp;"); break;
                case '<': xml_san_buffer_append_str(&buf, "&lt;"); break;
                case '>': xml_san_buffer_append_str(&buf, "&gt;"); break;
                default: xml_san_buffer_append_char(&buf, *tp); break;
                }
            } else {
                xml_san_buffer_append_char(&buf, *tp);
            }
        }
    }

    *output = xml_san_buffer_detach(&buf, output_len);
    return *output ? XML_SAN_OK : XML_SAN_ERR_MEMORY;
}

/*
 * Validation function
 */
static xml_san_error_t custom_validate(xml_san_ctx_t* ctx,
                                       const char* input, size_t input_len) {
    if(ctx->config.options & XML_SAN_OPT_VALIDATE_UTF8) {
        if(xml_san_utf8_validate(input, input_len) != 0) {
            return XML_SAN_ERR_INVALID_UTF8;
        }
    }

    int depth = 0;
    const char* p = input;
    const char* end = input + input_len;

    while(p < end) {
        if(*p == '<') {
            if(p + 1 < end) {
                if(p[1] == '/') {
                    depth--;
                } else if((p[1] != '?') && (p[1] != '!')) {
                    depth++;
                }
            }

            const char* tag_end = memchr(p, '>', end - p);
            if(tag_end && (tag_end > p) && (tag_end[-1] == '/')) {
                depth--;
            }
        }
        p++;
    }

    return XML_SAN_OK;
}

const xml_san_backend_ops_t xml_san_backend_custom = {
    .name = "custom",
    .init = NULL,
    .cleanup = NULL,
    .sanitize = custom_sanitize,
    .validate = custom_validate,
    .escape_text = custom_escape_text,
    .escape_attr = custom_escape_attr
};