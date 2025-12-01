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
#include <expat.h>
#include <ctype.h>

#define MAX_STACK_DEPTH 256

/* Element stack entry */
typedef struct {
    char* name;
    bool allowed;
} stack_entry_t;

typedef struct {
    XML_Parser parser;
    xml_san_ctx_t* san_ctx;
    xml_san_buffer_t* output;
    stack_entry_t stack[MAX_STACK_DEPTH];
    int stack_depth;
    xml_san_error_t error;
    bool in_cdata;
} expat_ctx_t;

static void XMLCALL start_element_handler(void* user_data,
                                          const XML_Char* name,
                                          const XML_Char** attrs);
static void XMLCALL end_element_handler(void* user_data,
                                        const XML_Char* name);
static void XMLCALL character_data_handler(void* user_data,
                                           const XML_Char* s,
                                           int len);
static void XMLCALL comment_handler(void* user_data,
                                    const XML_Char* data);
static void XMLCALL start_cdata_handler(void* user_data);
static void XMLCALL end_cdata_handler(void* user_data);
static void XMLCALL processing_instruction_handler(void* user_data,
                                                   const XML_Char* target,
                                                   const XML_Char* data);
static void XMLCALL default_handler(void* user_data,
                                    const XML_Char* s,
                                    int len);

/*
 * Escape text and append to buffer
 */
static void escape_and_append(xml_san_ctx_t* ctx, xml_san_buffer_t* buf,
                              const char* text, int len) {
    for(int i = 0; i < len; i++) {
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
static void escape_attr_and_append(xml_san_buffer_t* buf,
                                   const char* text) {
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
 * Element start handler
 */
static void XMLCALL start_element_handler(void* user_data,
                                          const XML_Char* name,
                                          const XML_Char** attrs) {
    expat_ctx_t* ectx = (expat_ctx_t*) user_data;
    xml_san_ctx_t* ctx = ectx->san_ctx;

    ctx->stats.elements_processed++;

    if(ectx->stack_depth >= MAX_STACK_DEPTH) {
        ectx->error = XML_SAN_ERR_PARSE_FAILED;
        XML_StopParser(ectx->parser, XML_FALSE);
        return;
    }

    if((ctx->config.max_depth > 0) &&
       ((size_t) ectx->stack_depth >= ctx->config.max_depth)) {
        ectx->error = XML_SAN_ERR_PARSE_FAILED;
        XML_StopParser(ectx->parser, XML_FALSE);
        return;
    }

    bool allowed = true;

    if(ctx->config.options & XML_SAN_OPT_STRIP_TAGS) {
        allowed = false;
    } else if(!xml_san_tag_allowed(ctx, name)) {
        allowed = false;
    }

    if(allowed && ctx->config.filter_fn) {
        allowed = ctx->config.filter_fn(name, NULL, NULL, ctx->config.user_data);
    }

    ectx->stack[ectx->stack_depth].name = strdup(name);
    ectx->stack[ectx->stack_depth].allowed = allowed;
    ectx->stack_depth++;

    if(!allowed) {
        ctx->stats.elements_removed++;
        return;
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

    xml_san_buffer_append_char(ectx->output, '<');
    xml_san_buffer_append_str(ectx->output, output_name);

    int attr_count = 0;
    for(int i = 0; attrs[i]; i += 2) {
        const char* attr_name = attrs[i];
        const char* attr_value = attrs[i + 1];

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

        if((ctx->config.max_attr_len > 0) &&
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

        xml_san_buffer_append_char(ectx->output, ' ');
        xml_san_buffer_append_str(ectx->output, attr_name);
        xml_san_buffer_append_str(ectx->output, "=\"");
        escape_attr_and_append(ectx->output, attr_value);
        xml_san_buffer_append_char(ectx->output, '"');
    }

    xml_san_buffer_append_char(ectx->output, '>');

    free(name_copy);
}

/*
 * Element end handler
 */
static void XMLCALL end_element_handler(void* user_data,
                                        const XML_Char* name) {
    expat_ctx_t* ectx = (expat_ctx_t*) user_data;
    xml_san_ctx_t* ctx = ectx->san_ctx;

    (void) name;

    if(ectx->stack_depth <= 0) {
        return;
    }

    ectx->stack_depth--;

    bool allowed = ectx->stack[ectx->stack_depth].allowed;
    char* stack_name = ectx->stack[ectx->stack_depth].name;

    if(allowed) {
        const char* output_name = stack_name;
        char* name_copy = NULL;

        if(ctx->config.options & XML_SAN_OPT_STRIP_NAMESPACES) {
            const char* colon = strchr(stack_name, ':');
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

        xml_san_buffer_append_str(ectx->output, "</");
        xml_san_buffer_append_str(ectx->output, output_name);
        xml_san_buffer_append_char(ectx->output, '>');

        free(name_copy);
    }

    free(stack_name);
}

/*
 * Character data handler
 */
static void XMLCALL character_data_handler(void* user_data,
                                           const XML_Char* s,
                                           int len) {
    expat_ctx_t* ectx = (expat_ctx_t*) user_data;
    xml_san_ctx_t* ctx = ectx->san_ctx;

    if((ectx->stack_depth > 0) && !ectx->stack[ectx->stack_depth - 1].allowed) {
        if(!(ctx->config.options & XML_SAN_OPT_STRIP_TAGS)) {
            escape_and_append(ctx, ectx->output, s, len);
        }
        return;
    }

    if(ectx->in_cdata) {
        if(!(ctx->config.options & XML_SAN_OPT_STRIP_CDATA)) {
            xml_san_buffer_append(ectx->output, s, len);
        }
        return;
    }

    if(ctx->config.options & XML_SAN_OPT_NORMALIZE_WS) {
        bool last_was_space = false;
        for(int i = 0; i < len; i++) {
            if(isspace((unsigned char) s[i])) {
                if(!last_was_space) {
                    xml_san_buffer_append_char(ectx->output, ' ');
                    last_was_space = true;
                }
            } else {
                escape_and_append(ctx, ectx->output, &s[i], 1);
                last_was_space = false;
            }
        }
    } else {
        escape_and_append(ctx, ectx->output, s, len);
    }
}

/*
 * Comment handler
 */
static void XMLCALL comment_handler(void* user_data,
                                    const XML_Char* data) {
    expat_ctx_t* ectx = (expat_ctx_t*) user_data;
    xml_san_ctx_t* ctx = ectx->san_ctx;

    if(!(ctx->config.options & XML_SAN_OPT_STRIP_COMMENTS)) {
        xml_san_buffer_append_str(ectx->output, "<!--");
        xml_san_buffer_append_str(ectx->output, data);
        xml_san_buffer_append_str(ectx->output, "-->");
    } else {
        ctx->stats.comments_removed++;
    }
}

/*
 * CDATA start handler
 */
static void XMLCALL start_cdata_handler(void* user_data) {
    expat_ctx_t* ectx = (expat_ctx_t*) user_data;
    xml_san_ctx_t* ctx = ectx->san_ctx;

    ectx->in_cdata = true;

    if(!(ctx->config.options & XML_SAN_OPT_STRIP_CDATA)) {
        xml_san_buffer_append_str(ectx->output, "<![CDATA[");
    }
}

/*
 * CDATA end handler
 */
static void XMLCALL end_cdata_handler(void* user_data) {
    expat_ctx_t* ectx = (expat_ctx_t*) user_data;
    xml_san_ctx_t* ctx = ectx->san_ctx;

    ectx->in_cdata = false;

    if(!(ctx->config.options & XML_SAN_OPT_STRIP_CDATA)) {
        xml_san_buffer_append_str(ectx->output, "]]>");
    }
}

/*
 * Processing instruction handler
 */
static void XMLCALL processing_instruction_handler(void* user_data,
                                                   const XML_Char* target,
                                                   const XML_Char* data) {
    expat_ctx_t* ectx = (expat_ctx_t*) user_data;
    xml_san_ctx_t* ctx = ectx->san_ctx;

    if(!(ctx->config.options & XML_SAN_OPT_STRIP_PI)) {
        xml_san_buffer_append_str(ectx->output, "<?");
        xml_san_buffer_append_str(ectx->output, target);
        if(data && data[0]) {
            xml_san_buffer_append_char(ectx->output, ' ');
            xml_san_buffer_append_str(ectx->output, data);
        }
        xml_san_buffer_append_str(ectx->output, "?>");
    }
}

/*
 * Default handler (catches DOCTYPE, etc.)
 */
static void XMLCALL default_handler(void* user_data,
                                    const XML_Char* s,
                                    int len) {
    expat_ctx_t* ectx = (expat_ctx_t*) user_data;
    xml_san_ctx_t* ctx = ectx->san_ctx;

    if((len >= 9) && (strncmp(s, "<!DOCTYPE", 9) == 0)) {
        if(!(ctx->config.options & XML_SAN_OPT_STRIP_DTD)) {
            xml_san_buffer_append(ectx->output, s, len);
        }
    }
}

/*
 * Initialize Expat backend
 */
static int expat_init(xml_san_ctx_t* ctx) {
    expat_ctx_t* ectx = calloc(1, sizeof(*ectx));
    if(!ectx) {
        return -1;
    }

    ectx->san_ctx = ctx;
    ctx->backend_data = ectx;
    return 0;
}

/*
 * Cleanup Expat backend
 */
static void expat_cleanup(xml_san_ctx_t* ctx) {
    if(!ctx || !ctx->backend_data) {
        return;
    }

    expat_ctx_t* ectx = ctx->backend_data;

    for(int i = 0; i < ectx->stack_depth; i++) {
        free(ectx->stack[i].name);
    }

    free(ectx);
    ctx->backend_data = NULL;
}

/*
 * Main sanitization function using Expat
 */
static xml_san_error_t expat_sanitize(xml_san_ctx_t* ctx,
                                      const char* input, size_t input_len,
                                      char** output, size_t* output_len) {
    if(!input || !output) {
        return XML_SAN_ERR_NULL_PTR;
    }

    expat_ctx_t* ectx = ctx->backend_data;
    if(!ectx) {
        return XML_SAN_ERR_NO_BACKEND;
    }

    ectx->parser = XML_ParserCreate(NULL);
    if(!ectx->parser) {
        return XML_SAN_ERR_BACKEND_INIT;
    }

    xml_san_buffer_t buf;
    if(xml_san_buffer_init(&buf, input_len + 256) != 0) {
        XML_ParserFree(ectx->parser);
        return XML_SAN_ERR_MEMORY;
    }

    ectx->output = &buf;
    ectx->stack_depth = 0;
    ectx->error = XML_SAN_OK;
    ectx->in_cdata = false;

    /* Set up handlers */
    XML_SetUserData(ectx->parser, ectx);
    XML_SetElementHandler(ectx->parser, start_element_handler, end_element_handler);
    XML_SetCharacterDataHandler(ectx->parser, character_data_handler);
    XML_SetCommentHandler(ectx->parser, comment_handler);
    XML_SetCdataSectionHandler(ectx->parser, start_cdata_handler, end_cdata_handler);
    XML_SetProcessingInstructionHandler(ectx->parser, processing_instruction_handler);
    XML_SetDefaultHandler(ectx->parser, default_handler);

    /* Parse the document */
    enum XML_Status status = XML_Parse(ectx->parser, input, input_len, XML_TRUE);

    XML_ParserFree(ectx->parser);
    ectx->parser = NULL;

    if((status == XML_STATUS_ERROR) && (ectx->error == XML_SAN_OK)) {
        ectx->error = XML_SAN_ERR_PARSE_FAILED;
    }

    if(ectx->error != XML_SAN_OK) {
        xml_san_buffer_cleanup(&buf);
        return ectx->error;
    }

    *output = xml_san_buffer_detach(&buf, output_len);
    return *output ? XML_SAN_OK : XML_SAN_ERR_MEMORY;
}

/*
 * Validation using Expat
 */
static xml_san_error_t expat_validate(xml_san_ctx_t* ctx,
                                      const char* input, size_t input_len) {
    (void) ctx;

    XML_Parser parser = XML_ParserCreate(NULL);
    if(!parser) {
        return XML_SAN_ERR_BACKEND_INIT;
    }

    enum XML_Status status = XML_Parse(parser, input, input_len, XML_TRUE);

    XML_ParserFree(parser);

    return (status == XML_STATUS_OK) ? XML_SAN_OK : XML_SAN_ERR_PARSE_FAILED;
}

/*
 * Text escaping
 */
static xml_san_error_t expat_escape_text(xml_san_ctx_t* ctx,
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
static xml_san_error_t expat_escape_attr(xml_san_ctx_t* ctx,
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

const xml_san_backend_ops_t xml_san_backend_expat = {
    .name = "expat",
    .init = expat_init,
    .cleanup = expat_cleanup,
    .sanitize = expat_sanitize,
    .validate = expat_validate,
    .escape_text = expat_escape_text,
    .escape_attr = expat_escape_attr
};
