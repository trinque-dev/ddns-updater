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
 * Check if an IP address is in a private/reserved range
 * Returns true if private, false if public
 *
 * Private IPv4 ranges (RFC 1918):
 *   10.0.0.0/8
 *   172.16.0.0/12
 *   192.168.0.0/16
 *
 * Other reserved IPv4 ranges:
 *   127.0.0.0/8     (loopback)
 *   169.254.0.0/16  (link-local)
 *   100.64.0.0/10   (carrier-grade NAT, RFC 6598)
 *   192.0.0.0/24    (IETF protocol assignments)
 *   192.0.2.0/24    (TEST-NET-1)
 *   198.51.100.0/24 (TEST-NET-2)
 *   203.0.113.0/24  (TEST-NET-3)
 *   224.0.0.0/4     (multicast)
 *   240.0.0.0/4     (reserved)
 *   255.255.255.255 (broadcast)
 *
 * Private IPv6 ranges:
 *   ::1/128         (loopback)
 *   fc00::/7        (unique local)
 *   fe80::/10       (link-local)
 *   ff00::/8        (multicast)
 */
bool ddns_is_private_ip(const char *ip)
{
    if (!ip || !*ip) {
        return false;
    }

    unsigned char buf[sizeof(struct in6_addr)];

    /* Try IPv4 */
    if (inet_pton(AF_INET, ip, buf) == 1) {
        uint32_t addr = ((uint32_t)buf[0] << 24) |
                        ((uint32_t)buf[1] << 16) |
                        ((uint32_t)buf[2] << 8) |
                        (uint32_t)buf[3];

        /* 10.0.0.0/8 */
        if ((addr & 0xFF000000) == 0x0A000000) {
            return true;
        }

        /* 172.16.0.0/12 */
        if ((addr & 0xFFF00000) == 0xAC100000) {
            return true;
        }

        /* 192.168.0.0/16 */
        if ((addr & 0xFFFF0000) == 0xC0A80000) {
            return true;
        }

        /* 127.0.0.0/8 (loopback) */
        if ((addr & 0xFF000000) == 0x7F000000) {
            return true;
        }

        /* 169.254.0.0/16 (link-local) */
        if ((addr & 0xFFFF0000) == 0xA9FE0000) {
            return true;
        }

        /* 100.64.0.0/10 (CGNAT) */
        if ((addr & 0xFFC00000) == 0x64400000) {
            return true;
        }

        /* 192.0.0.0/24 (IETF protocol assignments) */
        if ((addr & 0xFFFFFF00) == 0xC0000000) {
            return true;
        }

        /* 192.0.2.0/24 (TEST-NET-1) */
        if ((addr & 0xFFFFFF00) == 0xC0000200) {
            return true;
        }

        /* 198.51.100.0/24 (TEST-NET-2) */
        if ((addr & 0xFFFFFF00) == 0xC6336400) {
            return true;
        }

        /* 203.0.113.0/24 (TEST-NET-3) */
        if ((addr & 0xFFFFFF00) == 0xCB007100) {
            return true;
        }

        /* 224.0.0.0/4 (multicast) */
        if ((addr & 0xF0000000) == 0xE0000000) {
            return true;
        }

        /* 240.0.0.0/4 (reserved) and 255.255.255.255 */
        if ((addr & 0xF0000000) == 0xF0000000) {
            return true;
        }

        /* 0.0.0.0/8 (this network) */
        if ((addr & 0xFF000000) == 0x00000000) {
            return true;
        }

        return false;
    }

    /* Try IPv6 */
    if (inet_pton(AF_INET6, ip, buf) == 1) {
        /* ::1 (loopback) */
        static const unsigned char loopback[16] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        };
        if (memcmp(buf, loopback, 16) == 0) {
            return true;
        }

        /* :: (unspecified) */
        static const unsigned char unspecified[16] = {0};
        if (memcmp(buf, unspecified, 16) == 0) {
            return true;
        }

        /* fc00::/7 (unique local) - first byte is fc or fd */
        if ((buf[0] & 0xFE) == 0xFC) {
            return true;
        }

        /* fe80::/10 (link-local) */
        if (buf[0] == 0xFE && (buf[1] & 0xC0) == 0x80) {
            return true;
        }

        /* ff00::/8 (multicast) */
        if (buf[0] == 0xFF) {
            return true;
        }

        return false;
    }

    /* Invalid IP - treat as not private (will fail validation elsewhere) */
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
