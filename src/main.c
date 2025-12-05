/*
 * main.c - Dynamic DNS Updater
 *
 * A secure, multi-backend dynamic DNS updater written in POSIX C.
 *
 * Usage:
 *   ddns-updater -b <backend> -d <domain> -i <ip> [options]
 *
 * Example:
 *   export NAMESILO_API_KEY="your-api-key"
 *   ddns-updater -b namesilo -d home.example.com -i 192.168.1.1
 *
 * SPDX-License-Identifier: MIT
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <curl/curl.h>

#include "ddns.h"

/* Global context for signal handler cleanup */
static ddns_context_t *g_ctx = NULL;

/*
 * Print usage information
 */
static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -b <backend> -d <domain> -i <ip> [options]\n\n", prog);
    fprintf(stderr, "A secure dynamic DNS updater with multi-backend support.\n\n");
    fprintf(stderr, "Required arguments:\n");
    fprintf(stderr, "  -b, --backend <name>    DNS backend to use (e.g., namesilo)\n");
    fprintf(stderr, "  -d, --domain <fqdn>     Fully qualified domain name to update\n");
    fprintf(stderr, "  -i, --ip <address>      IP address to set (IPv4 or IPv6)\n\n");
    fprintf(stderr, "Optional arguments:\n");
    fprintf(stderr, "  -4, --ipv4              Force IPv4 (A record) update\n");
    fprintf(stderr, "  -6, --ipv6              Force IPv6 (AAAA record) update\n");
    fprintf(stderr, "  -c, --current           Show current IP for domain and exit\n");
    fprintf(stderr, "  -n, --dry-run           Show what would be done without making changes\n");
    fprintf(stderr, "  -q, --quiet             Suppress non-error output\n");
    fprintf(stderr, "  -v, --verbose           Enable verbose output\n");
    fprintf(stderr, "  -l, --list-backends     List available backends and exit\n");
    fprintf(stderr, "  -h, --help              Show this help message and exit\n");
    fprintf(stderr, "  -V, --version           Show version information and exit\n\n");
    fprintf(stderr, "Environment variables:\n");
    fprintf(stderr, "  Each backend uses its own environment variable for the API key.\n");
    fprintf(stderr, "  Use --list-backends to see the variable name for each backend.\n\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  # Update A record for home.example.com\n");
    fprintf(stderr, "  export NAMESILO_API_KEY=\"your-api-key\"\n");
    fprintf(stderr, "  %s -b namesilo -d home.example.com -i 1.2.3.4\n\n", prog);
    fprintf(stderr, "  # Update AAAA record\n");
    fprintf(stderr, "  %s -b namesilo -d home.example.com -i 2001:db8::1 -6\n\n", prog);
    fprintf(stderr, "  # Check current IP\n");
    fprintf(stderr, "  %s -b namesilo -d home.example.com -c\n", prog);
}

/*
 * Print version information
 */
static void print_version(void)
{
    printf("ddns-updater version %s\n", DDNS_VERSION_STRING);
    printf("Copyright (c) 2024. Licensed under MIT.\n");
    printf("Built with libcurl %s\n", curl_version());
}

/*
 * Signal handler for cleanup
 */
static void signal_handler(int sig)
{
    (void)sig;
    if (g_ctx) {
        ddns_log(g_ctx, DDNS_LOG_WARN, "Interrupted by signal");
    }
    exit(128 + sig);
}

/*
 * Initialize the context
 */
ddns_error_t ddns_init(ddns_context_t *ctx)
{
    if (!ctx) {
        return DDNS_ERR_INVALID_ARG;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->log_level = DDNS_LOG_INFO;
    ctx->log_file = stderr;

    /* Initialize libcurl */
    CURLcode res = curl_global_init(CURL_GLOBAL_SSL);
    if (res != CURLE_OK) {
        fprintf(stderr, "Failed to initialize libcurl: %s\n",
                curl_easy_strerror(res));
        return DDNS_ERR_INTERNAL;
    }

    return DDNS_OK;
}

/*
 * Clean up the context
 */
void ddns_cleanup(ddns_context_t *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->backend) {
        /* Call backend cleanup if available */
        if (ctx->backend->ops && ctx->backend->ops->cleanup) {
            ctx->backend->ops->cleanup(ctx->backend);
        }

        /* Securely wipe API key */
        ddns_secure_zero(ctx->backend->api_key, sizeof(ctx->backend->api_key));
        free(ctx->backend);
        ctx->backend = NULL;
    }

    curl_global_cleanup();
}

int main(int argc, char *argv[])
{
    ddns_context_t ctx;
    ddns_error_t err;
    int ret = 0;

    /* Command line options */
    const char *backend_name = NULL;
    const char *domain = NULL;
    const char *ip = NULL;
    ddns_ip_type_t ip_type = DDNS_IP_AUTO;
    bool show_current = false;
    bool list_backends = false;

    static struct option long_options[] = {
        {"backend",       required_argument, 0, 'b'},
        {"domain",        required_argument, 0, 'd'},
        {"ip",            required_argument, 0, 'i'},
        {"ipv4",          no_argument,       0, '4'},
        {"ipv6",          no_argument,       0, '6'},
        {"current",       no_argument,       0, 'c'},
        {"dry-run",       no_argument,       0, 'n'},
        {"quiet",         no_argument,       0, 'q'},
        {"verbose",       no_argument,       0, 'v'},
        {"list-backends", no_argument,       0, 'l'},
        {"help",          no_argument,       0, 'h'},
        {"version",       no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };

    /* Initialize context first for logging */
    err = ddns_init(&ctx);
    if (err != DDNS_OK) {
        fprintf(stderr, "Failed to initialize: %s\n", ddns_error_string(err));
        return 1;
    }

    g_ctx = &ctx;

    /* Set up signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Parse command line options */
    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "b:d:i:46cnqvlhV",
                             long_options, &option_index)) != -1) {
        switch (opt) {
        case 'b':
            backend_name = optarg;
            break;
        case 'd':
            domain = optarg;
            break;
        case 'i':
            ip = optarg;
            break;
        case '4':
            ip_type = DDNS_IP_V4;
            break;
        case '6':
            ip_type = DDNS_IP_V6;
            break;
        case 'c':
            show_current = true;
            break;
        case 'n':
            ctx.dry_run = true;
            break;
        case 'q':
            ctx.quiet = true;
            break;
        case 'v':
            ctx.log_level = DDNS_LOG_DEBUG;
            break;
        case 'l':
            list_backends = true;
            break;
        case 'h':
            print_usage(argv[0]);
            goto cleanup;
        case 'V':
            print_version();
            goto cleanup;
        default:
            print_usage(argv[0]);
            ret = 1;
            goto cleanup;
        }
    }

    /* Handle list-backends */
    if (list_backends) {
        ddns_backend_list(stdout);
        goto cleanup;
    }

    /* Validate required arguments */
    if (!backend_name) {
        fprintf(stderr, "Error: Backend (-b) is required\n\n");
        print_usage(argv[0]);
        ret = 1;
        goto cleanup;
    }

    if (!domain) {
        fprintf(stderr, "Error: Domain (-d) is required\n\n");
        print_usage(argv[0]);
        ret = 1;
        goto cleanup;
    }

    if (!show_current && !ip) {
        fprintf(stderr, "Error: IP address (-i) is required unless using --current\n\n");
        print_usage(argv[0]);
        ret = 1;
        goto cleanup;
    }

    /* Validate domain */
    if (!ddns_validate_domain(domain)) {
        ddns_log(&ctx, DDNS_LOG_ERROR, "Invalid domain: %s", domain);
        ret = 1;
        goto cleanup;
    }

    /* Validate IP if provided */
    if (ip) {
        ddns_ip_type_t detected_type;
        if (!ddns_validate_ip(ip, &detected_type)) {
            ddns_log(&ctx, DDNS_LOG_ERROR, "Invalid IP address: %s", ip);
            ret = 1;
            goto cleanup;
        }

        /* Use detected type if auto */
        if (ip_type == DDNS_IP_AUTO) {
            ip_type = detected_type;
        } else if (ip_type != detected_type) {
            ddns_log(&ctx, DDNS_LOG_ERROR,
                    "IP address type mismatch: got %s but --%s was specified",
                    detected_type == DDNS_IP_V4 ? "IPv4" : "IPv6",
                    ip_type == DDNS_IP_V4 ? "ipv4" : "ipv6");
            ret = 1;
            goto cleanup;
        }
    }

    /* Initialize backend */
    err = ddns_backend_init(&ctx, backend_name);
    if (err != DDNS_OK) {
        ddns_log(&ctx, DDNS_LOG_ERROR, "Failed to initialize backend: %s",
                ddns_error_string(err));
        ret = 1;
        goto cleanup;
    }

    /* Show current IP or perform update */
    if (show_current) {
        char current_ip[DDNS_MAX_IP_LEN + 1];

        if (!ctx.backend->ops->get_current) {
            ddns_log(&ctx, DDNS_LOG_ERROR,
                    "Backend does not support querying current IP");
            ret = 1;
            goto cleanup;
        }

        err = ctx.backend->ops->get_current(ctx.backend, domain, NULL,
                                           current_ip, sizeof(current_ip));
        if (err != DDNS_OK) {
            ddns_log(&ctx, DDNS_LOG_ERROR, "Failed to get current IP: %s",
                    ddns_error_string(err));
            ret = 1;
            goto cleanup;
        }

        printf("%s\n", current_ip);
    } else {
        /* Perform the update */
        err = ddns_update(&ctx, domain, NULL, ip, ip_type);
        if (err != DDNS_OK) {
            ddns_log(&ctx, DDNS_LOG_ERROR, "Failed to update DNS: %s",
                    ddns_error_string(err));
            ret = 1;
            goto cleanup;
        }

        if (!ctx.quiet) {
            ddns_log(&ctx, DDNS_LOG_INFO, "DNS update successful");
        }
    }

cleanup:
    ddns_cleanup(&ctx);
    return ret;
}
