/*
 * http.c - Secure HTTP client using libcurl
 *
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "ddns.h"

/* User-Agent string */
#define DDNS_USER_AGENT "ddns-updater/" DDNS_VERSION_STRING " (POSIX; libcurl)"

/* Connection timeout in seconds */
#define DDNS_CONNECT_TIMEOUT 30

/* Total request timeout in seconds */
#define DDNS_REQUEST_TIMEOUT 60

/* Maximum number of redirects to follow */
#define DDNS_MAX_REDIRECTS 5

/* Curl write callback */
static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    ddns_buffer_t *buf = userdata;
    size_t total = size * nmemb;

    /* Check for overflow */
    if (size != 0 && total / size != nmemb) {
        return 0;
    }

    if (ddns_buffer_append(buf, ptr, total) != DDNS_OK) {
        return 0;
    }

    return total;
}

/*
 * Perform an HTTPS GET request
 * Returns DDNS_OK on success, error code otherwise
 */
ddns_error_t ddns_http_get(ddns_context_t *ctx, const char *url,
                          ddns_buffer_t *response)
{
    if (!ctx || !url || !response) {
        return DDNS_ERR_INVALID_ARG;
    }

    /* Validate URL starts with https:// */
    if (strncmp(url, "https://", 8) != 0) {
        ddns_log(ctx, DDNS_LOG_ERROR, "Only HTTPS URLs are allowed");
        return DDNS_ERR_INVALID_ARG;
    }

    /* Validate URL length */
    if (strlen(url) > DDNS_MAX_URL_LEN) {
        ddns_log(ctx, DDNS_LOG_ERROR, "URL too long");
        return DDNS_ERR_INVALID_ARG;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        ddns_log(ctx, DDNS_LOG_ERROR, "Failed to initialize curl");
        return DDNS_ERR_INTERNAL;
    }

    ddns_error_t result = DDNS_OK;
    CURLcode res;

    /* Set URL */
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* Set write callback */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    /* Security settings */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    /* Use system CA bundle or common paths */
    /* libcurl will use its compiled-in default if not specified */

    /* Timeouts */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)DDNS_CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)DDNS_REQUEST_TIMEOUT);

    /* Follow redirects safely */
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, (long)DDNS_MAX_REDIRECTS);

    /* Only allow HTTPS redirects */
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");

    /* User agent */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, DDNS_USER_AGENT);

    /* Don't include headers in output */
    curl_easy_setopt(curl, CURLOPT_HEADER, 0L);

    /* Fail on HTTP errors */
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0L);

    /* DNS cache timeout (5 minutes) */
    curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, 300L);

    /* TCP keepalive */
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

    /* Disable signal handlers (thread safety) */
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    /* Log URL with sensitive parameters redacted */
    {
        const char *key_param = strstr(url, "key=");
        if (key_param) {
            /* Find end of key parameter */
            const char *key_end = strchr(key_param + 4, '&');
            size_t prefix_len = (size_t)(key_param + 4 - url);
            if (key_end) {
                ddns_log(ctx, DDNS_LOG_DEBUG, "HTTP GET: %.*s[REDACTED]%s",
                        (int)prefix_len, url, key_end);
            } else {
                ddns_log(ctx, DDNS_LOG_DEBUG, "HTTP GET: %.*s[REDACTED]",
                        (int)prefix_len, url);
            }
        } else {
            ddns_log(ctx, DDNS_LOG_DEBUG, "HTTP GET: %s", url);
        }
    }

    /* Perform the request */
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        ddns_log(ctx, DDNS_LOG_ERROR, "HTTP request failed: %s",
                curl_easy_strerror(res));
        result = DDNS_ERR_NETWORK;
        goto cleanup;
    }

    /* Check HTTP status code */
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    ddns_log(ctx, DDNS_LOG_DEBUG, "HTTP response: %ld, %zu bytes",
            http_code, response->size);

    if (http_code >= 400) {
        ddns_log(ctx, DDNS_LOG_ERROR, "HTTP error: %ld", http_code);
        result = DDNS_ERR_API_ERROR;
        goto cleanup;
    }

cleanup:
    curl_easy_cleanup(curl);
    return result;
}

/*
 * URL encode a string
 * Returns newly allocated string that must be freed by caller
 */
char *ddns_url_encode(const char *str)
{
    if (!str) {
        return NULL;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        return NULL;
    }

    char *encoded = curl_easy_escape(curl, str, 0);
    char *result = NULL;

    if (encoded) {
        result = strdup(encoded);
        curl_free(encoded);
    }

    curl_easy_cleanup(curl);
    return result;
}
