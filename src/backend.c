/*
 * backend.c - Backend registry and management
 *
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "ddns.h"

/* External backend definitions */
extern const ddns_backend_ops_t namesilo_backend;

/* Registry of available backends */
static const ddns_backend_ops_t *backends[] = {
    &namesilo_backend,
    /* Add new backends here */
    NULL
};

/*
 * Find a backend by name
 */
ddns_error_t ddns_backend_find(const char *name, const ddns_backend_ops_t **ops)
{
    if (!name || !ops) {
        return DDNS_ERR_INVALID_ARG;
    }

    for (size_t i = 0; backends[i] != NULL; i++) {
        if (strcasecmp(backends[i]->name, name) == 0) {
            *ops = backends[i];
            return DDNS_OK;
        }
    }

    return DDNS_ERR_BACKEND_NOT_FOUND;
}

/*
 * Initialize a backend for use
 */
ddns_error_t ddns_backend_init(ddns_context_t *ctx, const char *name)
{
    if (!ctx || !name) {
        return DDNS_ERR_INVALID_ARG;
    }

    const ddns_backend_ops_t *ops;
    ddns_error_t err = ddns_backend_find(name, &ops);
    if (err != DDNS_OK) {
        ddns_log(ctx, DDNS_LOG_ERROR, "Backend not found: %s", name);
        return err;
    }

    /* Allocate backend structure */
    ddns_backend_t *backend = calloc(1, sizeof(ddns_backend_t));
    if (!backend) {
        return DDNS_ERR_MEMORY;
    }

    backend->ops = ops;
    backend->ctx = ctx;

    /* Get API key from environment */
    const char *api_key = getenv(ops->env_var);
    if (!api_key || !*api_key) {
        ddns_log(ctx, DDNS_LOG_ERROR,
                "API key not found. Set environment variable: %s", ops->env_var);
        free(backend);
        return DDNS_ERR_NO_API_KEY;
    }

    /* Validate and copy API key */
    if (!ddns_validate_api_key(api_key)) {
        ddns_log(ctx, DDNS_LOG_ERROR, "Invalid API key format");
        free(backend);
        return DDNS_ERR_INVALID_API_KEY;
    }

    size_t key_len = strlen(api_key);
    if (key_len >= sizeof(backend->api_key)) {
        ddns_log(ctx, DDNS_LOG_ERROR, "API key too long");
        free(backend);
        return DDNS_ERR_INVALID_API_KEY;
    }

    memcpy(backend->api_key, api_key, key_len);
    backend->api_key[key_len] = '\0';

    /* Call backend-specific init if provided */
    if (ops->init) {
        err = ops->init(backend);
        if (err != DDNS_OK) {
            ddns_secure_zero(backend->api_key, sizeof(backend->api_key));
            free(backend);
            return err;
        }
    }

    ctx->backend = backend;
    ddns_log(ctx, DDNS_LOG_DEBUG, "Initialized backend: %s", ops->name);

    return DDNS_OK;
}

/*
 * List all available backends
 */
void ddns_backend_list(FILE *out)
{
    if (!out) {
        out = stdout;
    }

    fprintf(out, "Available backends:\n\n");

    for (size_t i = 0; backends[i] != NULL; i++) {
        const ddns_backend_ops_t *ops = backends[i];
        fprintf(out, "  %-12s  %s\n", ops->name, ops->description);
        fprintf(out, "               API key env var: %s\n\n", ops->env_var);
    }
}

/*
 * Perform DNS update using configured backend
 */
ddns_error_t ddns_update(ddns_context_t *ctx,
                        const char *domain,
                        const char *record,
                        const char *ip,
                        ddns_ip_type_t ip_type)
{
    if (!ctx || !ctx->backend || !domain || !ip) {
        return DDNS_ERR_INVALID_ARG;
    }

    const ddns_backend_ops_t *ops = ctx->backend->ops;
    if (!ops->update) {
        ddns_log(ctx, DDNS_LOG_ERROR, "Backend does not support updates");
        return DDNS_ERR_INTERNAL;
    }

    return ops->update(ctx->backend, domain, record, ip, ip_type);
}
