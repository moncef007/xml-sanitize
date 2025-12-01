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

/**
 * @file xml_sanitize_internal.h
 * @brief Internal definitions for XML Sanitization Library
 */

#ifndef XML_SANITIZE_INTERNAL_H
#define XML_SANITIZE_INTERNAL_H

#include "xml_sanitize.h"
#include <stdlib.h>
#include <string.h>

typedef struct xml_san_backend_ops {
    const char* name;

    /* Initialize backend-specific data */
    int (* init)(xml_san_ctx_t* ctx);

    /* Cleanup backend-specific data */
    void (* cleanup)(xml_san_ctx_t* ctx);

    /* Parse and sanitize XML document */
    xml_san_error_t (* sanitize)(xml_san_ctx_t* ctx,
                                 const char* input, size_t input_len,
                                 char** output, size_t* output_len);

    /* Validate XML document */
    xml_san_error_t (* validate)(xml_san_ctx_t* ctx,
                                 const char* input, size_t input_len);

    /* Escape text content */
    xml_san_error_t (* escape_text)(xml_san_ctx_t* ctx,
                                    const char* input,
                                    char** output);

    /* Escape attribute value */
    xml_san_error_t (* escape_attr)(xml_san_ctx_t* ctx,
                                    const char* input,
                                    char** output);
} xml_san_backend_ops_t;

struct xml_san_ctx {
    xml_san_config_t config;
    xml_san_error_t last_error;
    xml_san_stats_t stats;
    const xml_san_backend_ops_t* ops;
    void* backend_data;  /* Backend-specific data */
};

extern const xml_san_backend_ops_t xml_san_backend_custom;

#ifdef XML_SAN_HAVE_LIBXML2
extern const xml_san_backend_ops_t xml_san_backend_libxml2;
#endif

#ifdef XML_SAN_HAVE_SCEW
extern const xml_san_backend_ops_t xml_san_backend_scew;
#endif

#ifdef XML_SAN_HAVE_EXPAT
extern const xml_san_backend_ops_t xml_san_backend_expat;
#endif

#ifdef XML_SAN_HAVE_MXML
extern const xml_san_backend_ops_t xml_san_backend_mxml;
#endif

#ifdef XML_SAN_HAVE_YXML
extern const xml_san_backend_ops_t xml_san_backend_yxml;
#endif

#ifdef XML_SAN_HAVE_EZXML
extern const xml_san_backend_ops_t xml_san_backend_ezxml;
#endif

#ifdef XML_SAN_HAVE_ROXML
extern const xml_san_backend_ops_t xml_san_backend_roxml;
#endif

/* Utility functions used by backends */

/**
 * @brief Check if character is a valid XML character
 */
static inline bool xml_san_is_valid_char(unsigned char c) {
    /* XML 1.0 valid characters: #x9 | #xA | #xD | [#x20-#xD7FF] ... */
    if((c == 0x09) || (c == 0x0A) || (c == 0x0D)) {
        return true;
    }
    if(c >= 0x20) {
        return true;
    }
    return false;
}

/**
 * @brief Check if character is a control character to remove
 */
static inline bool xml_san_is_ctrl_char(unsigned char c) {
    return (c < 0x20 && c != 0x09 && c != 0x0A && c != 0x0D);
}

/**
 * @brief Check if tag is in allowed list
 */
bool xml_san_tag_allowed(const xml_san_ctx_t* ctx, const char* tag);

/**
 * @brief Check if attribute is in allowed list
 */
bool xml_san_attr_allowed(const xml_san_ctx_t* ctx, const char* attr);

/**
 * @brief Dynamic buffer for building output */
typedef struct {
    char* data;
    size_t len;
    size_t capacity;
} xml_san_buffer_t;

int xml_san_buffer_init(xml_san_buffer_t* buf, size_t initial_capacity);
void xml_san_buffer_cleanup(xml_san_buffer_t* buf);
int xml_san_buffer_append(xml_san_buffer_t* buf, const char* data, size_t len);
int xml_san_buffer_append_char(xml_san_buffer_t* buf, char c);
int xml_san_buffer_append_str(xml_san_buffer_t* buf, const char* str);
char* xml_san_buffer_detach(xml_san_buffer_t* buf, size_t* len);

/* UTF-8 validation */
int xml_san_utf8_validate(const char* str, size_t len);
size_t xml_san_utf8_fix(const char* input, size_t input_len,
                        char* output, size_t output_size);

#endif /* XML_SANITIZE_INTERNAL_H */