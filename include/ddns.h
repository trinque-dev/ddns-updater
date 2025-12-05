/*
 * ddns.h - Dynamic DNS Updater
 *
 * A secure, multi-backend dynamic DNS updater written in POSIX C.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef DDNS_H
#define DDNS_H

#include <stddef.h>
#include <stdbool.h>

/* Version information */
#define DDNS_VERSION_MAJOR 1
#define DDNS_VERSION_MINOR 0
#define DDNS_VERSION_PATCH 0
#define DDNS_VERSION_STRING "1.0.0"

/* Limits - carefully chosen for security */
#define DDNS_MAX_DOMAIN_LEN    253   /* RFC 1035 */
#define DDNS_MAX_LABEL_LEN     63    /* RFC 1035 */
#define DDNS_MAX_API_KEY_LEN   128
#define DDNS_MAX_IP_LEN        45    /* IPv6 max: 39, plus some margin */
#define DDNS_MAX_URL_LEN       2048
#define DDNS_MAX_RESPONSE_LEN  65536
#define DDNS_MAX_BACKEND_NAME  32

/* Error codes */
typedef enum {
    DDNS_OK = 0,
    DDNS_ERR_INVALID_ARG,
    DDNS_ERR_INVALID_DOMAIN,
    DDNS_ERR_INVALID_IP,
    DDNS_ERR_INVALID_API_KEY,
    DDNS_ERR_NO_API_KEY,
    DDNS_ERR_NETWORK,
    DDNS_ERR_API_ERROR,
    DDNS_ERR_PARSE_ERROR,
    DDNS_ERR_RECORD_NOT_FOUND,
    DDNS_ERR_MEMORY,
    DDNS_ERR_BACKEND_NOT_FOUND,
    DDNS_ERR_INTERNAL,
    DDNS_ERR_COUNT
} ddns_error_t;

/* Log levels */
typedef enum {
    DDNS_LOG_ERROR = 0,
    DDNS_LOG_WARN,
    DDNS_LOG_INFO,
    DDNS_LOG_DEBUG
} ddns_log_level_t;

/* IP address type */
typedef enum {
    DDNS_IP_AUTO = 0,    /* Auto-detect */
    DDNS_IP_V4,
    DDNS_IP_V6
} ddns_ip_type_t;

/* Forward declarations */
struct ddns_backend;
struct ddns_context;

/* HTTP response buffer */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} ddns_buffer_t;

/* Backend operations interface */
typedef struct ddns_backend_ops {
    const char *name;
    const char *env_var;       /* Environment variable for API key */
    const char *description;

    /* Initialize backend (optional) */
    ddns_error_t (*init)(struct ddns_backend *backend);

    /* Clean up backend (optional) */
    void (*cleanup)(struct ddns_backend *backend);

    /* Update DNS record */
    ddns_error_t (*update)(struct ddns_backend *backend,
                          const char *domain,
                          const char *record,
                          const char *ip,
                          ddns_ip_type_t ip_type);

    /* Get current IP for record (optional) */
    ddns_error_t (*get_current)(struct ddns_backend *backend,
                               const char *domain,
                               const char *record,
                               char *ip_out,
                               size_t ip_out_len);
} ddns_backend_ops_t;

/* Backend instance */
typedef struct ddns_backend {
    const ddns_backend_ops_t *ops;
    char api_key[DDNS_MAX_API_KEY_LEN + 1];
    void *private_data;
    struct ddns_context *ctx;
} ddns_backend_t;

/* Main context */
typedef struct ddns_context {
    ddns_backend_t *backend;
    ddns_log_level_t log_level;
    bool dry_run;
    bool quiet;
    FILE *log_file;
} ddns_context_t;

/* Core functions */
ddns_error_t ddns_init(ddns_context_t *ctx);
void ddns_cleanup(ddns_context_t *ctx);

/* Backend management */
ddns_error_t ddns_backend_find(const char *name, const ddns_backend_ops_t **ops);
ddns_error_t ddns_backend_init(ddns_context_t *ctx, const char *name);
void ddns_backend_list(FILE *out);

/* DNS operations */
ddns_error_t ddns_update(ddns_context_t *ctx,
                        const char *domain,
                        const char *record,
                        const char *ip,
                        ddns_ip_type_t ip_type);

/* Utility functions */
const char *ddns_error_string(ddns_error_t err);
bool ddns_validate_domain(const char *domain);
bool ddns_validate_ip(const char *ip, ddns_ip_type_t *type);
bool ddns_validate_api_key(const char *key);

/* Logging */
void ddns_log(ddns_context_t *ctx, ddns_log_level_t level,
              const char *fmt, ...) __attribute__((format(printf, 3, 4)));

/* Buffer operations */
ddns_error_t ddns_buffer_init(ddns_buffer_t *buf, size_t initial_capacity);
void ddns_buffer_free(ddns_buffer_t *buf);
ddns_error_t ddns_buffer_append(ddns_buffer_t *buf, const char *data, size_t len);
void ddns_buffer_clear(ddns_buffer_t *buf);

/* HTTP operations */
ddns_error_t ddns_http_get(ddns_context_t *ctx, const char *url,
                          ddns_buffer_t *response);
char *ddns_url_encode(const char *str);

/* Secure memory operations */
void ddns_secure_zero(void *ptr, size_t len);

#endif /* DDNS_H */
