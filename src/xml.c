/*
 * xml.c - Minimal, secure XML parser for API responses
 *
 * This is a minimal XML parser specifically designed for parsing
 * simple API responses. It does NOT support:
 * - DTDs (disabled for security - XXE prevention)
 * - External entities
 * - CDATA sections
 * - Processing instructions
 * - Comments (skipped)
 * - Namespaces
 *
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "ddns.h"
#include "xml.h"

/* Maximum nesting depth to prevent stack exhaustion */
#define XML_MAX_DEPTH 32

/* Maximum tag name length */
#define XML_MAX_TAG_LEN 64

/* Maximum attribute value length */
#define XML_MAX_VALUE_LEN 1024

/*
 * Find the content between opening and closing tags
 * Returns pointer to allocated string or NULL on error
 *
 * Example: xml_find_element("<root><code>123</code></root>", "code")
 *          returns "123"
 */
char *xml_find_element(const char *xml, const char *tag)
{
    if (!xml || !tag || !*tag) {
        return NULL;
    }

    size_t tag_len = strlen(tag);
    if (tag_len > XML_MAX_TAG_LEN) {
        return NULL;
    }

    /* Build opening tag pattern */
    char open_tag[XML_MAX_TAG_LEN + 4];
    int n = snprintf(open_tag, sizeof(open_tag), "<%s>", tag);
    if (n < 0 || (size_t)n >= sizeof(open_tag)) {
        return NULL;
    }

    /* Build alternative opening tag with attributes */
    char open_tag_attr[XML_MAX_TAG_LEN + 4];
    n = snprintf(open_tag_attr, sizeof(open_tag_attr), "<%s ", tag);
    if (n < 0 || (size_t)n >= sizeof(open_tag_attr)) {
        return NULL;
    }

    /* Build closing tag pattern */
    char close_tag[XML_MAX_TAG_LEN + 4];
    n = snprintf(close_tag, sizeof(close_tag), "</%s>", tag);
    if (n < 0 || (size_t)n >= sizeof(close_tag)) {
        return NULL;
    }

    /* Find opening tag */
    const char *start = strstr(xml, open_tag);
    if (start) {
        start += strlen(open_tag);
    } else {
        /* Try with attributes */
        start = strstr(xml, open_tag_attr);
        if (start) {
            /* Skip to end of opening tag */
            start = strchr(start, '>');
            if (start) {
                start++;
            }
        }
    }

    if (!start) {
        return NULL;
    }

    /* Find closing tag */
    const char *end = strstr(start, close_tag);
    if (!end) {
        return NULL;
    }

    /* Calculate content length */
    size_t content_len = (size_t)(end - start);
    if (content_len > XML_MAX_VALUE_LEN) {
        return NULL;
    }

    /* Allocate and copy content */
    char *content = malloc(content_len + 1);
    if (!content) {
        return NULL;
    }

    memcpy(content, start, content_len);
    content[content_len] = '\0';

    return content;
}

/*
 * Find attribute value within a tag
 * Returns pointer to allocated string or NULL on error
 *
 * Example: xml_find_attribute("<record id=\"123\">", "id")
 *          returns "123"
 */
char *xml_find_attribute(const char *xml, const char *tag, const char *attr)
{
    if (!xml || !tag || !attr || !*tag || !*attr) {
        return NULL;
    }

    size_t tag_len = strlen(tag);
    size_t attr_len = strlen(attr);

    if (tag_len > XML_MAX_TAG_LEN || attr_len > XML_MAX_TAG_LEN) {
        return NULL;
    }

    /* Build opening tag pattern with space for attributes */
    char open_tag[XML_MAX_TAG_LEN + 4];
    int n = snprintf(open_tag, sizeof(open_tag), "<%s ", tag);
    if (n < 0 || (size_t)n >= sizeof(open_tag)) {
        return NULL;
    }

    /* Find the tag */
    const char *tag_start = strstr(xml, open_tag);
    if (!tag_start) {
        return NULL;
    }

    /* Find end of tag */
    const char *tag_end = strchr(tag_start, '>');
    if (!tag_end) {
        return NULL;
    }

    /* Search for attribute within tag bounds */
    char attr_pattern[XML_MAX_TAG_LEN + 4];
    n = snprintf(attr_pattern, sizeof(attr_pattern), "%s=\"", attr);
    if (n < 0 || (size_t)n >= sizeof(attr_pattern)) {
        return NULL;
    }

    const char *attr_start = strstr(tag_start, attr_pattern);
    if (!attr_start || attr_start >= tag_end) {
        return NULL;
    }

    attr_start += strlen(attr_pattern);

    /* Find closing quote */
    const char *attr_end = strchr(attr_start, '"');
    if (!attr_end || attr_end >= tag_end) {
        return NULL;
    }

    /* Calculate value length */
    size_t value_len = (size_t)(attr_end - attr_start);
    if (value_len > XML_MAX_VALUE_LEN) {
        return NULL;
    }

    /* Allocate and copy value */
    char *value = malloc(value_len + 1);
    if (!value) {
        return NULL;
    }

    memcpy(value, attr_start, value_len);
    value[value_len] = '\0';

    return value;
}

/*
 * Decode basic XML entities
 * Returns pointer to allocated string or NULL on error
 */
char *xml_decode_entities(const char *str)
{
    if (!str) {
        return NULL;
    }

    size_t len = strlen(str);
    /* Worst case: no entities to decode */
    char *result = malloc(len + 1);
    if (!result) {
        return NULL;
    }

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '&') {
            if (strncmp(&str[i], "&amp;", 5) == 0) {
                result[j++] = '&';
                i += 4;
            } else if (strncmp(&str[i], "&lt;", 4) == 0) {
                result[j++] = '<';
                i += 3;
            } else if (strncmp(&str[i], "&gt;", 4) == 0) {
                result[j++] = '>';
                i += 3;
            } else if (strncmp(&str[i], "&quot;", 6) == 0) {
                result[j++] = '"';
                i += 5;
            } else if (strncmp(&str[i], "&apos;", 6) == 0) {
                result[j++] = '\'';
                i += 5;
            } else {
                /* Unknown entity, copy as-is */
                result[j++] = str[i];
            }
        } else {
            result[j++] = str[i];
        }
    }

    result[j] = '\0';
    return result;
}

/*
 * Check if XML response indicates success
 * Looks for common success indicators
 */
bool xml_check_success(const char *xml, const char *code_tag, const char *success_code)
{
    if (!xml || !code_tag || !success_code) {
        return false;
    }

    char *code = xml_find_element(xml, code_tag);
    if (!code) {
        return false;
    }

    bool is_success = (strcmp(code, success_code) == 0);
    free(code);

    return is_success;
}
