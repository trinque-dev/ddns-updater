/*
 * backend_namesilo.c - Namesilo DNS API backend
 *
 * Namesilo API Documentation: https://www.namesilo.com/api-reference
 *
 * Environment variable: NAMESILO_API_KEY
 *
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ddns.h"
#include "xml.h"

/* Namesilo API endpoints */
#define NAMESILO_API_BASE "https://www.namesilo.com/api"

/* API version to use */
#define NAMESILO_API_VERSION "1"

/* Success response code */
#define NAMESILO_SUCCESS_CODE "300"

/*
 * Extract the base domain (SLD + TLD) from a full hostname
 * For example: "home.example.com" -> "example.com"
 *              "example.com" -> "example.com"
 *              "sub.home.example.com" -> "example.com"
 *
 * Note: This is a simplified approach that assumes a single TLD.
 * For complex TLDs like .co.uk, this would need enhancement.
 */
static ddns_error_t extract_domain_parts(const char *full_domain,
                                         char *domain_out, size_t domain_len,
                                         char *host_out, size_t host_len)
{
    if (!full_domain || !domain_out || !host_out) {
        return DDNS_ERR_INVALID_ARG;
    }

    size_t len = strlen(full_domain);
    if (len == 0 || len > DDNS_MAX_DOMAIN_LEN) {
        return DDNS_ERR_INVALID_DOMAIN;
    }

    /* Count dots to determine structure */
    int dot_count = 0;
    const char *last_dot = NULL;
    const char *second_last_dot = NULL;

    for (const char *p = full_domain; *p; p++) {
        if (*p == '.') {
            dot_count++;
            second_last_dot = last_dot;
            last_dot = p;
        }
    }

    if (dot_count == 0) {
        /* No dots - invalid for our purposes */
        return DDNS_ERR_INVALID_DOMAIN;
    }

    if (dot_count == 1) {
        /* Just domain.tld - host is @ (root) */
        if (snprintf(domain_out, domain_len, "%s", full_domain) < 0) {
            return DDNS_ERR_INTERNAL;
        }
        if (snprintf(host_out, host_len, "@") < 0) {
            return DDNS_ERR_INTERNAL;
        }
    } else {
        /* subdomain.domain.tld or deeper */
        /* Find the domain part (everything from second-to-last dot onwards) */
        if (!second_last_dot) {
            return DDNS_ERR_INTERNAL;
        }

        const char *domain_start = second_last_dot + 1;
        if (snprintf(domain_out, domain_len, "%s", domain_start) < 0) {
            return DDNS_ERR_INTERNAL;
        }

        /* Host is everything before the domain */
        size_t host_part_len = (size_t)(second_last_dot - full_domain);
        if (host_part_len >= host_len) {
            return DDNS_ERR_INVALID_DOMAIN;
        }

        memcpy(host_out, full_domain, host_part_len);
        host_out[host_part_len] = '\0';
    }

    return DDNS_OK;
}

/*
 * Find the record ID for a given host in a domain
 */
static ddns_error_t namesilo_get_record_id(ddns_backend_t *backend,
                                           const char *domain,
                                           const char *host,
                                           ddns_ip_type_t ip_type,
                                           char *record_id_out,
                                           size_t record_id_len)
{
    ddns_context_t *ctx = backend->ctx;
    ddns_error_t err;

    /* Build the list records URL */
    char url[DDNS_MAX_URL_LEN];
    int n = snprintf(url, sizeof(url),
                    "%s/dnsListRecords?version=%s&type=xml&key=%s&domain=%s",
                    NAMESILO_API_BASE, NAMESILO_API_VERSION,
                    backend->api_key, domain);

    if (n < 0 || (size_t)n >= sizeof(url)) {
        ddns_log(ctx, DDNS_LOG_ERROR, "URL too long");
        return DDNS_ERR_INTERNAL;
    }

    ddns_log(ctx, DDNS_LOG_DEBUG, "Fetching DNS records for domain: %s", domain);

    /* Fetch the record list */
    ddns_buffer_t response;
    err = ddns_buffer_init(&response, 8192);
    if (err != DDNS_OK) {
        return err;
    }

    err = ddns_http_get(ctx, url, &response);
    if (err != DDNS_OK) {
        ddns_buffer_free(&response);
        return err;
    }

    /* Check for API success */
    if (!xml_check_success(response.data, "code", NAMESILO_SUCCESS_CODE)) {
        char *detail = xml_find_element(response.data, "detail");
        ddns_log(ctx, DDNS_LOG_ERROR, "Namesilo API error: %s",
                detail ? detail : "Unknown error");
        free(detail);
        ddns_buffer_free(&response);
        return DDNS_ERR_API_ERROR;
    }

    /* Determine record type to look for */
    const char *record_type = (ip_type == DDNS_IP_V6) ? "AAAA" : "A";

    ddns_log(ctx, DDNS_LOG_DEBUG, "Looking for %s record with host: %s", record_type, host);

    /* Parse the response to find the matching record
     * Response format:
     * <resource_record>
     *   <record_id>xxx</record_id>
     *   <type>A</type>
     *   <host>subdomain.example.com</host>
     *   <value>1.2.3.4</value>
     *   <ttl>3600</ttl>
     * </resource_record>
     */

    /* Build the full hostname we're looking for */
    char full_host[DDNS_MAX_DOMAIN_LEN + 1];
    if (strcmp(host, "@") == 0) {
        snprintf(full_host, sizeof(full_host), "%s", domain);
    } else {
        snprintf(full_host, sizeof(full_host), "%s.%s", host, domain);
    }

    /* Find each resource_record and check if it matches */
    const char *search_pos = response.data;
    const char *record_start;
    bool found = false;

    while ((record_start = strstr(search_pos, "<resource_record>")) != NULL) {
        const char *record_end = strstr(record_start, "</resource_record>");
        if (!record_end) {
            break;
        }

        /* Extract just this record for parsing */
        size_t record_len = (size_t)(record_end - record_start) + strlen("</resource_record>");
        char *record_xml = malloc(record_len + 1);
        if (!record_xml) {
            ddns_buffer_free(&response);
            return DDNS_ERR_MEMORY;
        }

        memcpy(record_xml, record_start, record_len);
        record_xml[record_len] = '\0';

        /* Check type */
        char *type = xml_find_element(record_xml, "type");
        if (type && strcmp(type, record_type) == 0) {
            /* Check host */
            char *rec_host = xml_find_element(record_xml, "host");
            if (rec_host && strcmp(rec_host, full_host) == 0) {
                /* Found it! Get the record ID */
                char *rec_id = xml_find_element(record_xml, "record_id");
                if (rec_id) {
                    if (strlen(rec_id) < record_id_len) {
                        strcpy(record_id_out, rec_id);
                        found = true;
                    }
                    free(rec_id);
                }
            }
            free(rec_host);
        }
        free(type);
        free(record_xml);

        if (found) {
            break;
        }

        search_pos = record_end + 1;
    }

    ddns_buffer_free(&response);

    if (!found) {
        ddns_log(ctx, DDNS_LOG_ERROR, "Record not found: %s (type: %s)", full_host, record_type);
        return DDNS_ERR_RECORD_NOT_FOUND;
    }

    ddns_log(ctx, DDNS_LOG_DEBUG, "Found record ID: %s", record_id_out);
    return DDNS_OK;
}

/*
 * Update a DNS record using the Namesilo API
 */
static ddns_error_t namesilo_update(ddns_backend_t *backend,
                                    const char *full_domain,
                                    const char *record,
                                    const char *ip,
                                    ddns_ip_type_t ip_type)
{
    ddns_context_t *ctx = backend->ctx;
    ddns_error_t err;

    (void)record; /* Record is derived from full_domain */

    /* Extract domain and host parts */
    char domain[DDNS_MAX_DOMAIN_LEN + 1];
    char host[DDNS_MAX_DOMAIN_LEN + 1];

    err = extract_domain_parts(full_domain, domain, sizeof(domain),
                               host, sizeof(host));
    if (err != DDNS_OK) {
        ddns_log(ctx, DDNS_LOG_ERROR, "Failed to parse domain: %s", full_domain);
        return err;
    }

    ddns_log(ctx, DDNS_LOG_INFO, "Updating %s record for %s.%s -> %s",
            ip_type == DDNS_IP_V6 ? "AAAA" : "A",
            strcmp(host, "@") == 0 ? "@" : host,
            domain, ip);

    /* First, find the record ID */
    char record_id[64];
    err = namesilo_get_record_id(backend, domain, host, ip_type, record_id, sizeof(record_id));
    if (err != DDNS_OK) {
        return err;
    }

    /* Dry run check */
    if (ctx->dry_run) {
        ddns_log(ctx, DDNS_LOG_INFO, "[DRY RUN] Would update record %s to %s", record_id, ip);
        return DDNS_OK;
    }

    /* Build the update URL */
    char url[DDNS_MAX_URL_LEN];
    int n = snprintf(url, sizeof(url),
                    "%s/dnsUpdateRecord?version=%s&type=xml&key=%s&domain=%s&rrid=%s&rrhost=%s&rrvalue=%s&rrttl=%u",
                    NAMESILO_API_BASE, NAMESILO_API_VERSION,
                    backend->api_key, domain, record_id, host, ip, ctx->ttl);

    if (n < 0 || (size_t)n >= sizeof(url)) {
        ddns_log(ctx, DDNS_LOG_ERROR, "URL too long");
        return DDNS_ERR_INTERNAL;
    }

    /* Perform the update */
    ddns_buffer_t response;
    err = ddns_buffer_init(&response, 4096);
    if (err != DDNS_OK) {
        return err;
    }

    err = ddns_http_get(ctx, url, &response);
    if (err != DDNS_OK) {
        ddns_buffer_free(&response);
        return err;
    }

    /* Check for API success */
    if (!xml_check_success(response.data, "code", NAMESILO_SUCCESS_CODE)) {
        char *detail = xml_find_element(response.data, "detail");
        ddns_log(ctx, DDNS_LOG_ERROR, "Namesilo API error: %s",
                detail ? detail : "Unknown error");
        free(detail);
        ddns_buffer_free(&response);
        return DDNS_ERR_API_ERROR;
    }

    ddns_log(ctx, DDNS_LOG_INFO, "Successfully updated DNS record");
    ddns_buffer_free(&response);

    return DDNS_OK;
}

/*
 * Get current IP for a record
 */
static ddns_error_t namesilo_get_current(ddns_backend_t *backend,
                                         const char *full_domain,
                                         const char *record,
                                         char *ip_out,
                                         size_t ip_out_len)
{
    ddns_context_t *ctx = backend->ctx;
    ddns_error_t err;

    (void)record;

    /* Extract domain and host parts */
    char domain[DDNS_MAX_DOMAIN_LEN + 1];
    char host[DDNS_MAX_DOMAIN_LEN + 1];

    err = extract_domain_parts(full_domain, domain, sizeof(domain),
                               host, sizeof(host));
    if (err != DDNS_OK) {
        return err;
    }

    /* Build the list records URL */
    char url[DDNS_MAX_URL_LEN];
    int n = snprintf(url, sizeof(url),
                    "%s/dnsListRecords?version=%s&type=xml&key=%s&domain=%s",
                    NAMESILO_API_BASE, NAMESILO_API_VERSION,
                    backend->api_key, domain);

    if (n < 0 || (size_t)n >= sizeof(url)) {
        return DDNS_ERR_INTERNAL;
    }

    /* Fetch the record list */
    ddns_buffer_t response;
    err = ddns_buffer_init(&response, 8192);
    if (err != DDNS_OK) {
        return err;
    }

    err = ddns_http_get(ctx, url, &response);
    if (err != DDNS_OK) {
        ddns_buffer_free(&response);
        return err;
    }

    /* Check for API success */
    if (!xml_check_success(response.data, "code", NAMESILO_SUCCESS_CODE)) {
        ddns_buffer_free(&response);
        return DDNS_ERR_API_ERROR;
    }

    /* Build the full hostname we're looking for */
    char full_host[DDNS_MAX_DOMAIN_LEN + 1];
    if (strcmp(host, "@") == 0) {
        snprintf(full_host, sizeof(full_host), "%s", domain);
    } else {
        snprintf(full_host, sizeof(full_host), "%s.%s", host, domain);
    }

    /* Find the matching A or AAAA record */
    const char *search_pos = response.data;
    const char *record_start;
    bool found = false;

    while ((record_start = strstr(search_pos, "<resource_record>")) != NULL) {
        const char *record_end = strstr(record_start, "</resource_record>");
        if (!record_end) {
            break;
        }

        size_t record_len = (size_t)(record_end - record_start) + strlen("</resource_record>");
        char *record_xml = malloc(record_len + 1);
        if (!record_xml) {
            ddns_buffer_free(&response);
            return DDNS_ERR_MEMORY;
        }

        memcpy(record_xml, record_start, record_len);
        record_xml[record_len] = '\0';

        /* Check type (A or AAAA) */
        char *type = xml_find_element(record_xml, "type");
        if (type && (strcmp(type, "A") == 0 || strcmp(type, "AAAA") == 0)) {
            /* Check host */
            char *rec_host = xml_find_element(record_xml, "host");
            if (rec_host && strcmp(rec_host, full_host) == 0) {
                /* Found it! Get the value */
                char *value = xml_find_element(record_xml, "value");
                if (value && strlen(value) < ip_out_len) {
                    strcpy(ip_out, value);
                    found = true;
                }
                free(value);
            }
            free(rec_host);
        }
        free(type);
        free(record_xml);

        if (found) {
            break;
        }

        search_pos = record_end + 1;
    }

    ddns_buffer_free(&response);

    if (!found) {
        return DDNS_ERR_RECORD_NOT_FOUND;
    }

    return DDNS_OK;
}

/* Namesilo backend operations */
const ddns_backend_ops_t namesilo_backend = {
    .name = "namesilo",
    .env_var = "NAMESILO_API_KEY",
    .description = "Namesilo DNS API (https://www.namesilo.com)",
    .init = NULL,
    .cleanup = NULL,
    .update = namesilo_update,
    .get_current = namesilo_get_current
};
