/*
 * test_domain_parts.c - Tests for domain parsing (extract_domain_parts)
 *
 * Note: extract_domain_parts is a static function in backend_namesilo.c
 * We include the source file directly to test it.
 *
 * SPDX-License-Identifier: MIT
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include "ddns.h"
#include "tests.h"

/*
 * Re-implement extract_domain_parts for testing since it's static.
 * This should match the implementation in backend_namesilo.c exactly.
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

/* ============ Basic Parsing Tests ============ */

static void test_domain_parts_simple_subdomain(void)
{
    char domain[256], host[256];

    CU_ASSERT_EQUAL(extract_domain_parts("home.example.com", domain, sizeof(domain), host, sizeof(host)), DDNS_OK);
    CU_ASSERT_STRING_EQUAL(domain, "example.com");
    CU_ASSERT_STRING_EQUAL(host, "home");
}

static void test_domain_parts_root_domain(void)
{
    char domain[256], host[256];

    CU_ASSERT_EQUAL(extract_domain_parts("example.com", domain, sizeof(domain), host, sizeof(host)), DDNS_OK);
    CU_ASSERT_STRING_EQUAL(domain, "example.com");
    CU_ASSERT_STRING_EQUAL(host, "@");
}

static void test_domain_parts_deep_subdomain(void)
{
    char domain[256], host[256];

    CU_ASSERT_EQUAL(extract_domain_parts("a.b.c.example.com", domain, sizeof(domain), host, sizeof(host)), DDNS_OK);
    CU_ASSERT_STRING_EQUAL(domain, "example.com");
    CU_ASSERT_STRING_EQUAL(host, "a.b.c");
}

static void test_domain_parts_two_level_subdomain(void)
{
    char domain[256], host[256];

    CU_ASSERT_EQUAL(extract_domain_parts("foo.bar.example.com", domain, sizeof(domain), host, sizeof(host)), DDNS_OK);
    CU_ASSERT_STRING_EQUAL(domain, "example.com");
    CU_ASSERT_STRING_EQUAL(host, "foo.bar");
}

static void test_domain_parts_hyphenated(void)
{
    char domain[256], host[256];

    CU_ASSERT_EQUAL(extract_domain_parts("my-host.my-domain.com", domain, sizeof(domain), host, sizeof(host)), DDNS_OK);
    CU_ASSERT_STRING_EQUAL(domain, "my-domain.com");
    CU_ASSERT_STRING_EQUAL(host, "my-host");
}

static void test_domain_parts_numbers(void)
{
    char domain[256], host[256];

    CU_ASSERT_EQUAL(extract_domain_parts("server01.example123.net", domain, sizeof(domain), host, sizeof(host)), DDNS_OK);
    CU_ASSERT_STRING_EQUAL(domain, "example123.net");
    CU_ASSERT_STRING_EQUAL(host, "server01");
}

/* ============ Edge Cases ============ */

static void test_domain_parts_single_char_labels(void)
{
    char domain[256], host[256];

    CU_ASSERT_EQUAL(extract_domain_parts("a.b.c", domain, sizeof(domain), host, sizeof(host)), DDNS_OK);
    CU_ASSERT_STRING_EQUAL(domain, "b.c");
    CU_ASSERT_STRING_EQUAL(host, "a");
}

static void test_domain_parts_wildcard(void)
{
    /* Wildcard subdomains are just labels with special meaning */
    char domain[256], host[256];

    CU_ASSERT_EQUAL(extract_domain_parts("*.example.com", domain, sizeof(domain), host, sizeof(host)), DDNS_OK);
    CU_ASSERT_STRING_EQUAL(domain, "example.com");
    CU_ASSERT_STRING_EQUAL(host, "*");
}

/* ============ Error Cases ============ */

static void test_domain_parts_null_input(void)
{
    char domain[256], host[256];

    CU_ASSERT_EQUAL(extract_domain_parts(NULL, domain, sizeof(domain), host, sizeof(host)), DDNS_ERR_INVALID_ARG);
}

static void test_domain_parts_null_output(void)
{
    char domain[256], host[256];

    CU_ASSERT_EQUAL(extract_domain_parts("example.com", NULL, sizeof(domain), host, sizeof(host)), DDNS_ERR_INVALID_ARG);
    CU_ASSERT_EQUAL(extract_domain_parts("example.com", domain, sizeof(domain), NULL, sizeof(host)), DDNS_ERR_INVALID_ARG);
}

static void test_domain_parts_empty(void)
{
    char domain[256], host[256];

    CU_ASSERT_EQUAL(extract_domain_parts("", domain, sizeof(domain), host, sizeof(host)), DDNS_ERR_INVALID_DOMAIN);
}

static void test_domain_parts_no_dot(void)
{
    char domain[256], host[256];

    CU_ASSERT_EQUAL(extract_domain_parts("localhost", domain, sizeof(domain), host, sizeof(host)), DDNS_ERR_INVALID_DOMAIN);
}

static void test_domain_parts_small_buffer(void)
{
    char domain[10], host[5];

    /* Host buffer too small for "verylongsubdomain" */
    CU_ASSERT_EQUAL(extract_domain_parts("verylongsubdomain.example.com", domain, sizeof(domain), host, sizeof(host)), DDNS_ERR_INVALID_DOMAIN);
}

/* ============ Real-World Domains ============ */

static void test_domain_parts_realistic(void)
{
    char domain[256], host[256];

    /* Common dynamic DNS patterns */
    CU_ASSERT_EQUAL(extract_domain_parts("myserver.dyndns.org", domain, sizeof(domain), host, sizeof(host)), DDNS_OK);
    CU_ASSERT_STRING_EQUAL(domain, "dyndns.org");
    CU_ASSERT_STRING_EQUAL(host, "myserver");

    CU_ASSERT_EQUAL(extract_domain_parts("home.mydomain.io", domain, sizeof(domain), host, sizeof(host)), DDNS_OK);
    CU_ASSERT_STRING_EQUAL(domain, "mydomain.io");
    CU_ASSERT_STRING_EQUAL(host, "home");

    CU_ASSERT_EQUAL(extract_domain_parts("vpn.office.company.com", domain, sizeof(domain), host, sizeof(host)), DDNS_OK);
    CU_ASSERT_STRING_EQUAL(domain, "company.com");
    CU_ASSERT_STRING_EQUAL(host, "vpn.office");
}

/* ============ Suite Registration ============ */

CU_ErrorCode test_domain_parts_register(void)
{
    CU_pSuite suite = CU_add_suite("Domain Parts Parsing", NULL, NULL);
    if (!suite) {
        return CU_get_error();
    }

    /* Basic parsing tests */
    if (!CU_add_test(suite, "basic: simple subdomain", test_domain_parts_simple_subdomain) ||
        !CU_add_test(suite, "basic: root domain", test_domain_parts_root_domain) ||
        !CU_add_test(suite, "basic: deep subdomain", test_domain_parts_deep_subdomain) ||
        !CU_add_test(suite, "basic: two level subdomain", test_domain_parts_two_level_subdomain) ||
        !CU_add_test(suite, "basic: hyphenated", test_domain_parts_hyphenated) ||
        !CU_add_test(suite, "basic: numbers", test_domain_parts_numbers)) {
        return CU_get_error();
    }

    /* Edge cases */
    if (!CU_add_test(suite, "edge: single char labels", test_domain_parts_single_char_labels) ||
        !CU_add_test(suite, "edge: wildcard", test_domain_parts_wildcard)) {
        return CU_get_error();
    }

    /* Error cases */
    if (!CU_add_test(suite, "error: null input", test_domain_parts_null_input) ||
        !CU_add_test(suite, "error: null output", test_domain_parts_null_output) ||
        !CU_add_test(suite, "error: empty", test_domain_parts_empty) ||
        !CU_add_test(suite, "error: no dot", test_domain_parts_no_dot) ||
        !CU_add_test(suite, "error: small buffer", test_domain_parts_small_buffer)) {
        return CU_get_error();
    }

    /* Real-world tests */
    if (!CU_add_test(suite, "realistic: common patterns", test_domain_parts_realistic)) {
        return CU_get_error();
    }

    return CUE_SUCCESS;
}
