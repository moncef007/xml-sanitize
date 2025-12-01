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

#include "xml_sanitize.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define TEST_PASS(name) printf("  [PASS] %s\n", name)
#define TEST_FAIL(name, msg) do { \
        printf("  [FAIL] %s: %s\n", name, msg); \
        return 1; \
} while(0)


static int test_ctx_creation(void) {
    xml_san_ctx_t* ctx = xml_san_ctx_new(NULL);
    if(!ctx) {
        TEST_FAIL("test_ctx_creation", "Failed to create context");
    }

    const char* backend = xml_san_get_backend_name(ctx);
    if(!backend || (strlen(backend) == 0)) {
        TEST_FAIL("test_ctx_creation", "No backend name");
    }

    printf("    Backend: %s\n", backend);

    xml_san_ctx_free(ctx);
    TEST_PASS("test_ctx_creation");
    return 0;
}


static int test_text_escape(void) {
    xml_san_ctx_t* ctx = xml_san_ctx_new(NULL);
    if(!ctx) {
        TEST_FAIL("test_text_escape", "Failed to create context");
    }

    const char* input = "Hello <World> & \"Friends\" 'All'";
    char* output = NULL;

    xml_san_error_t err = xml_san_text_content(ctx, input, &output);
    if(err != XML_SAN_OK) {
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_text_escape", xml_san_strerror(err));
    }

    if(!strstr(output, "&lt;") || !strstr(output, "&gt;") || !strstr(output, "&amp;")) {
        xml_san_free(output);
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_text_escape", "Entities not properly escaped");
    }

    printf("    Input:  %s\n", input);
    printf("    Output: %s\n", output);

    xml_san_free(output);
    xml_san_ctx_free(ctx);
    TEST_PASS("test_text_escape");
    return 0;
}


static int test_attr_escape(void) {
    xml_san_ctx_t* ctx = xml_san_ctx_new(NULL);
    if(!ctx) {
        TEST_FAIL("test_attr_escape", "Failed to create context");
    }

    const char* input = "value with \"quotes\" and <tags>";
    char* output = NULL;

    xml_san_error_t err = xml_san_attr_value(ctx, input, &output);
    if(err != XML_SAN_OK) {
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_attr_escape", xml_san_strerror(err));
    }

    if(!strstr(output, "&quot;") || !strstr(output, "&lt;")) {
        xml_san_free(output);
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_attr_escape", "Attribute not properly escaped");
    }

    printf("    Input:  %s\n", input);
    printf("    Output: %s\n", output);

    xml_san_free(output);
    xml_san_ctx_free(ctx);
    TEST_PASS("test_attr_escape");
    return 0;
}


static int test_xml_sanitize(void) {
    xml_san_ctx_t* ctx = xml_san_ctx_new(NULL);
    if(!ctx) {
        TEST_FAIL("test_xml_sanitize", "Failed to create context");
    }

    const char* input = "<root><!-- comment --><item attr=\"value\">Hello &amp; World</item></root>";
    char* output = NULL;
    size_t output_len = 0;

    xml_san_error_t err = xml_san_string(ctx, input, 0, &output, &output_len);
    if(err != XML_SAN_OK) {
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_xml_sanitize", xml_san_strerror(err));
    }

    printf("    Input:  %s\n", input);
    printf("    Output: %s\n", output);
    printf("    Length: %zu\n", output_len);

    if(strstr(output, "<!--")) {
        xml_san_free(output);
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_xml_sanitize", "Comment not stripped");
    }

    xml_san_free(output);
    xml_san_ctx_free(ctx);
    TEST_PASS("test_xml_sanitize");
    return 0;
}


static int test_ctrl_removal(void) {
    xml_san_config_t config;
    xml_san_config_init(&config);
    config.options = XML_SAN_OPT_REMOVE_CTRL | XML_SAN_OPT_ESCAPE_ENTITIES;

    xml_san_ctx_t* ctx = xml_san_ctx_new(&config);
    if(!ctx) {
        TEST_FAIL("test_ctrl_removal", "Failed to create context");
    }

    const char input[] = "Hello\x01\x02World\x03";
    char* output = NULL;

    xml_san_error_t err = xml_san_text_content(ctx, input, &output);
    if(err != XML_SAN_OK) {
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_ctrl_removal", xml_san_strerror(err));
    }

    if((strstr(output, "Hello") == NULL) || (strstr(output, "World") == NULL)) {
        xml_san_free(output);
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_ctrl_removal", "Expected text not found");
    }

    printf("    Output: %s\n", output);

    xml_san_stats_t stats;
    xml_san_get_stats(ctx, &stats);
    printf("    Ctrl chars removed: %zu\n", stats.ctrl_chars_removed);

    xml_san_free(output);
    xml_san_ctx_free(ctx);
    TEST_PASS("test_ctrl_removal");
    return 0;
}


static int test_strip_tags(void) {
    xml_san_config_t config;
    xml_san_config_init(&config);
    config.options = XML_SAN_OPT_STRIP_TAGS | XML_SAN_OPT_ESCAPE_ENTITIES;

    xml_san_ctx_t* ctx = xml_san_ctx_new(&config);
    if(!ctx) {
        TEST_FAIL("test_strip_tags", "Failed to create context");
    }

    const char* input = "<root><item>Hello</item><item>World</item></root>";
    char* output = NULL;
    size_t output_len = 0;

    xml_san_error_t err = xml_san_string(ctx, input, 0, &output, &output_len);
    if(err != XML_SAN_OK) {
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_strip_tags", xml_san_strerror(err));
    }

    printf("    Input:  %s\n", input);
    printf("    Output: %s\n", output);

    if(strchr(output, '<') || strchr(output, '>')) {
        xml_san_free(output);
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_strip_tags", "Tags not stripped");
    }

    xml_san_free(output);
    xml_san_ctx_free(ctx);
    TEST_PASS("test_strip_tags");
    return 0;
}

static int test_tag_whitelist(void) {
    const char* allowed[] = {"root", "allowed", NULL};

    xml_san_config_t config;
    xml_san_config_init(&config);
    config.options = XML_SAN_OPT_DEFAULT;
    config.allowed_tags = allowed;

    xml_san_ctx_t* ctx = xml_san_ctx_new(&config);
    if(!ctx) {
        TEST_FAIL("test_tag_whitelist", "Failed to create context");
    }

    const char* input = "<root><allowed>Keep</allowed><blocked>Remove</blocked></root>";
    char* output = NULL;
    size_t output_len = 0;

    xml_san_error_t err = xml_san_string(ctx, input, 0, &output, &output_len);
    if(err != XML_SAN_OK) {
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_tag_whitelist", xml_san_strerror(err));
    }

    printf("    Input:  %s\n", input);
    printf("    Output: %s\n", output);

    if(strstr(output, "<blocked>") || strstr(output, "</blocked>")) {
        xml_san_free(output);
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_tag_whitelist", "Blocked tag not removed");
    }

    if(!strstr(output, "<allowed>")) {
        xml_san_free(output);
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_tag_whitelist", "Allowed tag removed");
    }

    xml_san_free(output);
    xml_san_ctx_free(ctx);
    TEST_PASS("test_tag_whitelist");
    return 0;
}


static int test_buffer_sanitize(void) {
    xml_san_ctx_t* ctx = xml_san_ctx_new(NULL);
    if(!ctx) {
        TEST_FAIL("test_buffer_sanitize", "Failed to create context");
    }

    const char* input = "<root>Hello</root>";
    char output[256];
    size_t output_len = 0;

    xml_san_error_t err = xml_san_string_buf(ctx, input, 0,
                                             output, sizeof(output),
                                             &output_len);
    if(err != XML_SAN_OK) {
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_buffer_sanitize", xml_san_strerror(err));
    }

    printf("    Output: %s (len=%zu)\n", output, output_len);

    xml_san_ctx_free(ctx);
    TEST_PASS("test_buffer_sanitize");
    return 0;
}


static int test_error_handling(void) {
    xml_san_ctx_t* ctx = xml_san_ctx_new(NULL);
    if(!ctx) {
        TEST_FAIL("test_error_handling", "Failed to create context");
    }

    xml_san_error_t err = xml_san_string(ctx, NULL, 0, NULL, NULL);
    if(err != XML_SAN_ERR_NULL_PTR) {
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_error_handling", "Expected NULL_PTR error");
    }

    const char* errmsg = xml_san_strerror(err);
    if(!errmsg || (strlen(errmsg) == 0)) {
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_error_handling", "No error message");
    }

    printf("    Error code %d: %s\n", err, errmsg);

    xml_san_ctx_free(ctx);
    TEST_PASS("test_error_handling");
    return 0;
}


static int test_backend_availability(void) {
    xml_san_backend_type_t backends[XML_SAN_BACKEND_COUNT];
    size_t count = xml_san_list_backends(backends, XML_SAN_BACKEND_COUNT);

    printf("    Available backends (%zu):\n", count);
    for(size_t i = 0; i < count; i++) {
        const char* name = "unknown";
        switch(backends[i]) {
        case XML_SAN_BACKEND_CUSTOM: name = "custom"; break;
        case XML_SAN_BACKEND_LIBXML2: name = "libxml2"; break;
        case XML_SAN_BACKEND_SCEW: name = "scew"; break;
        case XML_SAN_BACKEND_EXPAT: name = "expat"; break;
        case XML_SAN_BACKEND_MXML: name = "mxml"; break;
        case XML_SAN_BACKEND_YXML: name = "yxml"; break;
        case XML_SAN_BACKEND_EZXML: name = "ezxml"; break;
        case XML_SAN_BACKEND_ROXML: name = "roxml"; break;
        default: break;
        }
        printf("      - %s\n", name);
    }

    if(!xml_san_backend_available(XML_SAN_BACKEND_CUSTOM)) {
        TEST_FAIL("test_backend_availability", "Custom backend not available");
    }

    TEST_PASS("test_backend_availability");
    return 0;
}


static int test_statistics(void) {
    xml_san_ctx_t* ctx = xml_san_ctx_new(NULL);
    if(!ctx) {
        TEST_FAIL("test_statistics", "Failed to create context");
    }

    const char* input = "<root><!-- comment --><item>Text</item></root>";
    char* output = NULL;

    xml_san_string(ctx, input, 0, &output, NULL);

    xml_san_stats_t stats;
    xml_san_get_stats(ctx, &stats);

    printf("    Input length:        %zu\n", stats.input_len);
    printf("    Output length:       %zu\n", stats.output_len);
    printf("    Elements processed:  %zu\n", stats.elements_processed);
    printf("    Elements removed:    %zu\n", stats.elements_removed);
    printf("    Attributes processed:%zu\n", stats.attrs_processed);
    printf("    Comments removed:    %zu\n", stats.comments_removed);

    xml_san_free(output);

    xml_san_reset_stats(ctx);
    xml_san_get_stats(ctx, &stats);

    if((stats.input_len != 0) || (stats.output_len != 0)) {
        xml_san_ctx_free(ctx);
        TEST_FAIL("test_statistics", "Stats not reset");
    }

    xml_san_ctx_free(ctx);
    TEST_PASS("test_statistics");
    return 0;
}


int main(void) {
    int failures = 0;

    printf("\n=== XML Sanitize Library Tests ===\n\n");

    printf("Basic Tests:\n");
    failures += test_ctx_creation();
    failures += test_text_escape();
    failures += test_attr_escape();
    failures += test_xml_sanitize();

    printf("\nFeature Tests:\n");
    failures += test_ctrl_removal();
    failures += test_strip_tags();
    failures += test_tag_whitelist();
    failures += test_buffer_sanitize();

    printf("\nUtility Tests:\n");
    failures += test_error_handling();
    failures += test_backend_availability();
    failures += test_statistics();

    printf("\n=================================\n");
    if(failures == 0) {
        printf("All tests passed!\n");
    } else {
        printf("%d test(s) failed!\n", failures);
    }
    printf("=================================\n\n");

    return failures;
}