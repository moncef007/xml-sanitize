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

#ifndef XML_SANITIZE_H
#define XML_SANITIZE_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    XML_SAN_OK = 0,
    XML_SAN_ERR_NULL_PTR,
    XML_SAN_ERR_INVALID_INPUT,
    XML_SAN_ERR_PARSE_FAILED,
    XML_SAN_ERR_MEMORY,
    XML_SAN_ERR_BACKEND_INIT,
    XML_SAN_ERR_NO_BACKEND,
    XML_SAN_ERR_BUFFER_TOO_SMALL,
    XML_SAN_ERR_INVALID_UTF8,
    XML_SAN_ERR_UNKNOWN
} xml_san_error_t;

typedef enum {
    XML_SAN_OPT_NONE              = 0,
    XML_SAN_OPT_ESCAPE_ENTITIES   = (1 << 0),  /* Escape &, <, >, ", ' */
    XML_SAN_OPT_STRIP_TAGS        = (1 << 1),  /* Remove all XML tags */
    XML_SAN_OPT_STRIP_CDATA       = (1 << 2),  /* Remove CDATA sections */
    XML_SAN_OPT_STRIP_COMMENTS    = (1 << 3),  /* Remove XML comments */
    XML_SAN_OPT_STRIP_PI          = (1 << 4),  /* Remove processing instructions */
    XML_SAN_OPT_STRIP_DTD         = (1 << 5),  /* Remove DTD declarations */
    XML_SAN_OPT_NORMALIZE_WS      = (1 << 6),  /* Normalize whitespace */
    XML_SAN_OPT_REMOVE_CTRL       = (1 << 7),  /* Remove control characters */
    XML_SAN_OPT_VALIDATE_UTF8     = (1 << 8),  /* Validate UTF-8 encoding */
    XML_SAN_OPT_FIX_UTF8          = (1 << 9),  /* Fix invalid UTF-8 sequences */
    XML_SAN_OPT_STRIP_NAMESPACES  = (1 << 10), /* Remove namespace prefixes */
    XML_SAN_OPT_LOWERCASE_TAGS    = (1 << 11), /* Convert tags to lowercase */
    XML_SAN_OPT_REMOVE_EMPTY_TAGS = (1 << 12), /* Remove empty elements */
    XML_SAN_OPT_STRICT            = (1 << 13), /* Strict mode - fail on any error */
    XML_SAN_OPT_DEFAULT           = (XML_SAN_OPT_ESCAPE_ENTITIES |
                                     XML_SAN_OPT_STRIP_COMMENTS |
                                     XML_SAN_OPT_REMOVE_CTRL |
                                     XML_SAN_OPT_VALIDATE_UTF8)
} xml_san_options_t;

typedef enum {
    XML_SAN_BACKEND_AUTO = 0,     /* Auto-detect best available */
    XML_SAN_BACKEND_LIBXML2,      /* libxml2 backend */
    XML_SAN_BACKEND_SCEW,         /* libscew backend */
    XML_SAN_BACKEND_EXPAT,        /* Expat backend */
    XML_SAN_BACKEND_MXML,         /* Mini-XML backend */
    XML_SAN_BACKEND_YXML,         /* yxml backend */
    XML_SAN_BACKEND_EZXML,        /* ezXML backend */
    XML_SAN_BACKEND_ROXML,        /* libroxml backend */
    XML_SAN_BACKEND_CUSTOM,       /* Custom backend */
    XML_SAN_BACKEND_COUNT
} xml_san_backend_type_t;

typedef struct xml_san_ctx xml_san_ctx_t;
typedef struct xml_san_backend xml_san_backend_t;

/* Callback for custom element filtering */
typedef bool (* xml_san_element_filter_fn)(const char* tag_name,
                                           const char* attr_name,
                                           const char* attr_value,
                                           void* user_data);

/* Callback for custom text transformation */
typedef char*(* xml_san_text_transform_fn)(const char* text,
                                           size_t len,
                                           void* user_data);

typedef struct {
    xml_san_options_t options;
    xml_san_backend_type_t backend;
    size_t max_depth;                       /* Maximum nesting depth (0 = unlimited) */
    size_t max_attr_count;                  /* Maximum attributes per element */
    size_t max_attr_len;                    /* Maximum attribute value length */
    const char** allowed_tags;              /* NULL-terminated list of allowed tags */
    const char** allowed_attrs;             /* NULL-terminated list of allowed attributes */
    xml_san_element_filter_fn filter_fn;    /* Custom element filter callback */
    xml_san_text_transform_fn transform_fn; /* Custom text transform callback */
    void* user_data;                        /* User data for callbacks */
} xml_san_config_t;

typedef struct {
    size_t input_len;
    size_t output_len;
    size_t elements_processed;
    size_t elements_removed;
    size_t attrs_processed;
    size_t attrs_removed;
    size_t entities_escaped;
    size_t ctrl_chars_removed;
    size_t comments_removed;
} xml_san_stats_t;

/**
 * @brief Initialize default configuration
 * @param config Pointer to configuration structure
 */
void xml_san_config_init(xml_san_config_t* config);

/**
 * @brief Create a new sanitization context
 * @param config Configuration (NULL for defaults)
 * @return Context pointer or NULL on error
 */
xml_san_ctx_t* xml_san_ctx_new(const xml_san_config_t* config);

/**
 * @brief Free a sanitization context
 * @param ctx Context to free
 */
void xml_san_ctx_free(xml_san_ctx_t* ctx);

/**
 * @brief Get the last error code
 * @param ctx Context
 * @return Error code
 */
xml_san_error_t xml_san_get_error(const xml_san_ctx_t* ctx);

/**
 * @brief Get error message string
 * @param error Error code
 * @return Human-readable error message
 */
const char* xml_san_strerror(xml_san_error_t error);

/**
 * @brief Get the active backend name
 * @param ctx Context
 * @return Backend name string
 */
const char* xml_san_get_backend_name(const xml_san_ctx_t* ctx);

/**
 * @brief Sanitize XML string (allocates output buffer)
 * @param ctx Context
 * @param input Input XML string
 * @param input_len Input length (0 for strlen)
 * @param output Pointer to receive allocated output
 * @param output_len Pointer to receive output length
 * @return Error code
 */
xml_san_error_t xml_san_string(xml_san_ctx_t* ctx,
                               const char* input, size_t input_len,
                               char** output, size_t* output_len);

/**
 * @brief Sanitize XML string into provided buffer
 * @param ctx Context
 * @param input Input XML string
 * @param input_len Input length (0 for strlen)
 * @param output Output buffer
 * @param output_size Output buffer size
 * @param output_len Pointer to receive actual output length
 * @return Error code
 */
xml_san_error_t xml_san_string_buf(xml_san_ctx_t* ctx,
                                   const char* input, size_t input_len,
                                   char* output, size_t output_size,
                                   size_t* output_len);

/**
 * @brief Sanitize a single XML attribute value
 * @param ctx Context
 * @param value Attribute value
 * @param output Pointer to receive allocated output
 * @return Error code
 */
xml_san_error_t xml_san_attr_value(xml_san_ctx_t* ctx,
                                   const char* value,
                                   char** output);

/**
 * @brief Sanitize text content (escape entities)
 * @param ctx Context
 * @param text Text content
 * @param output Pointer to receive allocated output
 * @return Error code
 */
xml_san_error_t xml_san_text_content(xml_san_ctx_t* ctx,
                                     const char* text,
                                     char** output);

/**
 * @brief Validate XML string without modification
 * @param ctx Context
 * @param input Input XML string
 * @param input_len Input length (0 for strlen)
 * @return XML_SAN_OK if valid, error code otherwise
 */
xml_san_error_t xml_san_validate(xml_san_ctx_t* ctx,
                                 const char* input, size_t input_len);

/**
 * @brief Get sanitization statistics
 * @param ctx Context
 * @param stats Pointer to stats structure
 * @return Error code
 */
xml_san_error_t xml_san_get_stats(const xml_san_ctx_t* ctx,
                                  xml_san_stats_t* stats);

/**
 * @brief Reset statistics counters
 * @param ctx Context
 */
void xml_san_reset_stats(xml_san_ctx_t* ctx);

/**
 * @brief Free allocated output buffer
 * @param ptr Buffer to free
 */
void xml_san_free(void* ptr);

/**
 * @brief Check if a backend is available
 * @param backend Backend type
 * @return true if available
 */
bool xml_san_backend_available(xml_san_backend_type_t backend);

/**
 * @brief List available backends
 * @param backends Array to fill with available backend types
 * @param max_count Maximum entries in array
 * @return Number of available backends
 */
size_t xml_san_list_backends(xml_san_backend_type_t* backends, size_t max_count);

/* Convenience macros */
#define XML_SAN_ESCAPE(ctx, str, out) \
    xml_san_text_content((ctx), (str), (out))

#ifdef __cplusplus
}
#endif

#endif /* XML_SANITIZE_H */