/*
 * util.c - Utility functions for DDNS updater
 *
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>

#include "ddns.h"

/* Error messages - indexed by ddns_error_t */
static const char *error_messages[] = {
    "Success",
    "Invalid argument",
    "Invalid domain name",
    "Invalid IP address",
    "Invalid API key",
    "API key not found in environment",
    "Network error",
    "API returned an error",
    "Failed to parse API response",
    "DNS record not found",
    "Memory allocation failed",
    "Backend not found",
    "Internal error"
};

_Static_assert(sizeof(error_messages) / sizeof(error_messages[0]) == DDNS_ERR_COUNT,
               "Error message count mismatch");

const char *ddns_error_string(ddns_error_t err)
{
    if (err < 0 || err >= DDNS_ERR_COUNT) {
        return "Unknown error";
    }
    return error_messages[err];
}

/*
 * Validate a domain name according to RFC 1035
 * Returns true if valid, false otherwise
 */
bool ddns_validate_domain(const char *domain)
{
    if (!domain || !*domain) {
        return false;
    }

    size_t len = strlen(domain);
    if (len > DDNS_MAX_DOMAIN_LEN) {
        return false;
    }

    /* Remove trailing dot if present */
    if (domain[len - 1] == '.') {
        len--;
    }

    if (len == 0) {
        return false;
    }

    size_t label_len = 0;
    bool prev_was_hyphen = false;
    bool label_start = true;

    for (size_t i = 0; i < len; i++) {
        char c = domain[i];

        if (c == '.') {
            /* Empty label or label ending with hyphen */
            if (label_len == 0 || prev_was_hyphen) {
                return false;
            }
            label_len = 0;
            label_start = true;
            prev_was_hyphen = false;
            continue;
        }

        label_len++;
        if (label_len > DDNS_MAX_LABEL_LEN) {
            return false;
        }

        if (c == '-') {
            /* Label cannot start with hyphen */
            if (label_start) {
                return false;
            }
            prev_was_hyphen = true;
        } else if (isalnum((unsigned char)c)) {
            prev_was_hyphen = false;
        } else {
            /* Invalid character */
            return false;
        }

        label_start = false;
    }

    /* Final label check */
    if (label_len == 0 || prev_was_hyphen) {
        return false;
    }

    return true;
}

/*
 * Validate an IP address (IPv4 or IPv6)
 * Sets type to detected type if not NULL
 * Returns true if valid, false otherwise
 */
bool ddns_validate_ip(const char *ip, ddns_ip_type_t *type)
{
    if (!ip || !*ip) {
        return false;
    }

    size_t len = strlen(ip);
    if (len > DDNS_MAX_IP_LEN) {
        return false;
    }

    unsigned char buf[sizeof(struct in6_addr)];

    /* Try IPv4 first */
    if (inet_pton(AF_INET, ip, buf) == 1) {
        if (type) {
            *type = DDNS_IP_V4;
        }
        return true;
    }

    /* Try IPv6 */
    if (inet_pton(AF_INET6, ip, buf) == 1) {
        if (type) {
            *type = DDNS_IP_V6;
        }
        return true;
    }

    return false;
}

/*
 * Validate an API key
 * Only allows alphanumeric characters and common separators
 * Returns true if valid, false otherwise
 */
bool ddns_validate_api_key(const char *key)
{
    if (!key || !*key) {
        return false;
    }

    size_t len = strlen(key);
    if (len > DDNS_MAX_API_KEY_LEN) {
        return false;
    }

    /* Minimum reasonable length for an API key */
    if (len < 8) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        char c = key[i];
        /* Allow alphanumeric and common separators used in API keys */
        if (!isalnum((unsigned char)c) && c != '-' && c != '_') {
            return false;
        }
    }

    return true;
}

/*
 * Logging function with timestamp
 */
void ddns_log(ddns_context_t *ctx, ddns_log_level_t level,
              const char *fmt, ...)
{
    if (!ctx || level > ctx->log_level) {
        return;
    }

    if (ctx->quiet && level > DDNS_LOG_ERROR) {
        return;
    }

    FILE *out = ctx->log_file ? ctx->log_file : stderr;

    /* Get current time */
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm = localtime_r(&now, &tm_buf);

    static const char *level_names[] = {
        "ERROR", "WARN", "INFO", "DEBUG"
    };

    /* Print timestamp and level */
    if (tm) {
        fprintf(out, "%04d-%02d-%02d %02d:%02d:%02d [%s] ",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec,
                level_names[level]);
    } else {
        fprintf(out, "[%s] ", level_names[level]);
    }

    /* Print message */
    va_list args;
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);

    fprintf(out, "\n");
    fflush(out);
}

/*
 * Securely zero memory - resistant to compiler optimization
 */
void ddns_secure_zero(void *ptr, size_t len)
{
    if (!ptr || len == 0) {
        return;
    }

    volatile unsigned char *p = ptr;
    while (len--) {
        *p++ = 0;
    }

    /* Memory barrier to prevent reordering */
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

/*
 * Buffer initialization
 */
ddns_error_t ddns_buffer_init(ddns_buffer_t *buf, size_t initial_capacity)
{
    if (!buf) {
        return DDNS_ERR_INVALID_ARG;
    }

    if (initial_capacity == 0) {
        initial_capacity = 4096;
    }

    /* Sanity limit */
    if (initial_capacity > DDNS_MAX_RESPONSE_LEN) {
        initial_capacity = DDNS_MAX_RESPONSE_LEN;
    }

    buf->data = malloc(initial_capacity);
    if (!buf->data) {
        return DDNS_ERR_MEMORY;
    }

    buf->data[0] = '\0';
    buf->size = 0;
    buf->capacity = initial_capacity;

    return DDNS_OK;
}

/*
 * Free buffer memory securely
 */
void ddns_buffer_free(ddns_buffer_t *buf)
{
    if (!buf) {
        return;
    }

    if (buf->data) {
        ddns_secure_zero(buf->data, buf->capacity);
        free(buf->data);
    }

    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;
}

/*
 * Append data to buffer with bounds checking
 */
ddns_error_t ddns_buffer_append(ddns_buffer_t *buf, const char *data, size_t len)
{
    if (!buf || !data) {
        return DDNS_ERR_INVALID_ARG;
    }

    /* Check if we would exceed max response length */
    if (buf->size + len >= DDNS_MAX_RESPONSE_LEN) {
        return DDNS_ERR_MEMORY;
    }

    /* Grow buffer if needed */
    if (buf->size + len + 1 > buf->capacity) {
        size_t new_capacity = buf->capacity * 2;
        while (new_capacity < buf->size + len + 1) {
            new_capacity *= 2;
        }

        if (new_capacity > DDNS_MAX_RESPONSE_LEN) {
            new_capacity = DDNS_MAX_RESPONSE_LEN;
        }

        char *new_data = realloc(buf->data, new_capacity);
        if (!new_data) {
            return DDNS_ERR_MEMORY;
        }

        buf->data = new_data;
        buf->capacity = new_capacity;
    }

    memcpy(buf->data + buf->size, data, len);
    buf->size += len;
    buf->data[buf->size] = '\0';

    return DDNS_OK;
}

/*
 * Clear buffer contents securely
 */
void ddns_buffer_clear(ddns_buffer_t *buf)
{
    if (!buf || !buf->data) {
        return;
    }

    ddns_secure_zero(buf->data, buf->size);
    buf->size = 0;
    buf->data[0] = '\0';
}
