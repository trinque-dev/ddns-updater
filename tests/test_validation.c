/*
 * test_validation.c - Tests for input validation functions
 *
 * SPDX-License-Identifier: MIT
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include "ddns.h"
#include "tests.h"

/* ============ Domain Validation Tests ============ */

static void test_domain_valid_simple(void)
{
    CU_ASSERT_TRUE(ddns_validate_domain("example.com"));
    CU_ASSERT_TRUE(ddns_validate_domain("foo.example.com"));
    CU_ASSERT_TRUE(ddns_validate_domain("bar.foo.example.com"));
}

static void test_domain_valid_with_numbers(void)
{
    CU_ASSERT_TRUE(ddns_validate_domain("example123.com"));
    CU_ASSERT_TRUE(ddns_validate_domain("123example.com"));
    CU_ASSERT_TRUE(ddns_validate_domain("ex4mpl3.com"));
}

static void test_domain_valid_with_hyphens(void)
{
    CU_ASSERT_TRUE(ddns_validate_domain("my-domain.com"));
    CU_ASSERT_TRUE(ddns_validate_domain("my-cool-domain.example.com"));
    CU_ASSERT_TRUE(ddns_validate_domain("a-b-c.d-e-f.com"));
}

static void test_domain_valid_trailing_dot(void)
{
    /* FQDN with trailing dot is valid */
    CU_ASSERT_TRUE(ddns_validate_domain("example.com."));
    CU_ASSERT_TRUE(ddns_validate_domain("foo.example.com."));
}

static void test_domain_valid_single_char_labels(void)
{
    CU_ASSERT_TRUE(ddns_validate_domain("a.b.c"));
    CU_ASSERT_TRUE(ddns_validate_domain("x.example.com"));
}

static void test_domain_invalid_null(void)
{
    CU_ASSERT_FALSE(ddns_validate_domain(NULL));
}

static void test_domain_invalid_empty(void)
{
    CU_ASSERT_FALSE(ddns_validate_domain(""));
    CU_ASSERT_FALSE(ddns_validate_domain("."));
}

static void test_domain_invalid_leading_hyphen(void)
{
    CU_ASSERT_FALSE(ddns_validate_domain("-example.com"));
    CU_ASSERT_FALSE(ddns_validate_domain("foo.-bar.com"));
}

static void test_domain_invalid_trailing_hyphen(void)
{
    CU_ASSERT_FALSE(ddns_validate_domain("example-.com"));
    CU_ASSERT_FALSE(ddns_validate_domain("foo.bar-.com"));
}

static void test_domain_invalid_double_dot(void)
{
    CU_ASSERT_FALSE(ddns_validate_domain("example..com"));
    CU_ASSERT_FALSE(ddns_validate_domain("foo..bar.com"));
}

static void test_domain_invalid_special_chars(void)
{
    CU_ASSERT_FALSE(ddns_validate_domain("exam_ple.com"));
    CU_ASSERT_FALSE(ddns_validate_domain("exam ple.com"));
    CU_ASSERT_FALSE(ddns_validate_domain("exam@ple.com"));
    CU_ASSERT_FALSE(ddns_validate_domain("exam!ple.com"));
    CU_ASSERT_FALSE(ddns_validate_domain("例え.jp")); /* Non-ASCII */
}

static void test_domain_invalid_label_too_long(void)
{
    /* Label > 63 chars */
    char long_label[70];
    memset(long_label, 'a', 64);
    long_label[64] = '.';
    long_label[65] = 'c';
    long_label[66] = 'o';
    long_label[67] = 'm';
    long_label[68] = '\0';
    CU_ASSERT_FALSE(ddns_validate_domain(long_label));
}

static void test_domain_invalid_too_long(void)
{
    /* Domain > 253 chars */
    char long_domain[300];
    int pos = 0;
    for (int i = 0; i < 50 && pos < 260; i++) {
        memcpy(long_domain + pos, "abcde.", 6);
        pos += 6;
    }
    long_domain[pos - 1] = '\0'; /* Remove trailing dot */
    CU_ASSERT_FALSE(ddns_validate_domain(long_domain));
}

/* ============ IP Validation Tests ============ */

static void test_ip_valid_ipv4(void)
{
    ddns_ip_type_t type;

    CU_ASSERT_TRUE(ddns_validate_ip("1.2.3.4", &type));
    CU_ASSERT_EQUAL(type, DDNS_IP_V4);

    CU_ASSERT_TRUE(ddns_validate_ip("192.168.1.1", &type));
    CU_ASSERT_EQUAL(type, DDNS_IP_V4);

    CU_ASSERT_TRUE(ddns_validate_ip("255.255.255.255", &type));
    CU_ASSERT_EQUAL(type, DDNS_IP_V4);

    CU_ASSERT_TRUE(ddns_validate_ip("0.0.0.0", &type));
    CU_ASSERT_EQUAL(type, DDNS_IP_V4);
}

static void test_ip_valid_ipv6(void)
{
    ddns_ip_type_t type;

    CU_ASSERT_TRUE(ddns_validate_ip("::1", &type));
    CU_ASSERT_EQUAL(type, DDNS_IP_V6);

    CU_ASSERT_TRUE(ddns_validate_ip("2001:db8::1", &type));
    CU_ASSERT_EQUAL(type, DDNS_IP_V6);

    CU_ASSERT_TRUE(ddns_validate_ip("fe80::1", &type));
    CU_ASSERT_EQUAL(type, DDNS_IP_V6);

    CU_ASSERT_TRUE(ddns_validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334", &type));
    CU_ASSERT_EQUAL(type, DDNS_IP_V6);

    CU_ASSERT_TRUE(ddns_validate_ip("::", &type));
    CU_ASSERT_EQUAL(type, DDNS_IP_V6);
}

static void test_ip_valid_null_type(void)
{
    /* Should work without type output */
    CU_ASSERT_TRUE(ddns_validate_ip("1.2.3.4", NULL));
    CU_ASSERT_TRUE(ddns_validate_ip("::1", NULL));
}

static void test_ip_invalid_null(void)
{
    CU_ASSERT_FALSE(ddns_validate_ip(NULL, NULL));
}

static void test_ip_invalid_empty(void)
{
    CU_ASSERT_FALSE(ddns_validate_ip("", NULL));
}

static void test_ip_invalid_garbage(void)
{
    CU_ASSERT_FALSE(ddns_validate_ip("not an ip", NULL));
    CU_ASSERT_FALSE(ddns_validate_ip("example.com", NULL));
    CU_ASSERT_FALSE(ddns_validate_ip("12345", NULL));
}

static void test_ip_invalid_ipv4_out_of_range(void)
{
    CU_ASSERT_FALSE(ddns_validate_ip("256.1.1.1", NULL));
    CU_ASSERT_FALSE(ddns_validate_ip("1.256.1.1", NULL));
    CU_ASSERT_FALSE(ddns_validate_ip("1.1.256.1", NULL));
    CU_ASSERT_FALSE(ddns_validate_ip("1.1.1.256", NULL));
}

static void test_ip_invalid_ipv4_incomplete(void)
{
    CU_ASSERT_FALSE(ddns_validate_ip("1.2.3", NULL));
    CU_ASSERT_FALSE(ddns_validate_ip("1.2", NULL));
    CU_ASSERT_FALSE(ddns_validate_ip("1", NULL));
}

static void test_ip_invalid_ipv4_extra_octets(void)
{
    CU_ASSERT_FALSE(ddns_validate_ip("1.2.3.4.5", NULL));
}

static void test_ip_invalid_ipv6_bad_format(void)
{
    CU_ASSERT_FALSE(ddns_validate_ip("2001:db8:::1", NULL));
    CU_ASSERT_FALSE(ddns_validate_ip("2001:db8:gggg::1", NULL));
}

/* ============ API Key Validation Tests ============ */

static void test_apikey_valid(void)
{
    CU_ASSERT_TRUE(ddns_validate_api_key("abcdef12345678"));
    CU_ASSERT_TRUE(ddns_validate_api_key("ABC-DEF-123-456"));
    CU_ASSERT_TRUE(ddns_validate_api_key("api_key_12345678"));
    CU_ASSERT_TRUE(ddns_validate_api_key("aaaaaaaa")); /* Minimum 8 chars */
}

static void test_apikey_invalid_null(void)
{
    CU_ASSERT_FALSE(ddns_validate_api_key(NULL));
}

static void test_apikey_invalid_empty(void)
{
    CU_ASSERT_FALSE(ddns_validate_api_key(""));
}

static void test_apikey_invalid_too_short(void)
{
    CU_ASSERT_FALSE(ddns_validate_api_key("abc")); /* < 8 chars */
    CU_ASSERT_FALSE(ddns_validate_api_key("1234567")); /* 7 chars */
}

static void test_apikey_invalid_special_chars(void)
{
    CU_ASSERT_FALSE(ddns_validate_api_key("apikey!@#$%"));
    CU_ASSERT_FALSE(ddns_validate_api_key("api key with spaces"));
    CU_ASSERT_FALSE(ddns_validate_api_key("apikey\nnewline"));
}

/* ============ Suite Registration ============ */

CU_ErrorCode test_validation_register(void)
{
    CU_pSuite suite = CU_add_suite("Validation", NULL, NULL);
    if (!suite) {
        return CU_get_error();
    }

    /* Domain tests */
    if (!CU_add_test(suite, "domain: valid simple", test_domain_valid_simple) ||
        !CU_add_test(suite, "domain: valid with numbers", test_domain_valid_with_numbers) ||
        !CU_add_test(suite, "domain: valid with hyphens", test_domain_valid_with_hyphens) ||
        !CU_add_test(suite, "domain: valid trailing dot", test_domain_valid_trailing_dot) ||
        !CU_add_test(suite, "domain: valid single char labels", test_domain_valid_single_char_labels) ||
        !CU_add_test(suite, "domain: invalid null", test_domain_invalid_null) ||
        !CU_add_test(suite, "domain: invalid empty", test_domain_invalid_empty) ||
        !CU_add_test(suite, "domain: invalid leading hyphen", test_domain_invalid_leading_hyphen) ||
        !CU_add_test(suite, "domain: invalid trailing hyphen", test_domain_invalid_trailing_hyphen) ||
        !CU_add_test(suite, "domain: invalid double dot", test_domain_invalid_double_dot) ||
        !CU_add_test(suite, "domain: invalid special chars", test_domain_invalid_special_chars) ||
        !CU_add_test(suite, "domain: invalid label too long", test_domain_invalid_label_too_long) ||
        !CU_add_test(suite, "domain: invalid too long", test_domain_invalid_too_long)) {
        return CU_get_error();
    }

    /* IP tests */
    if (!CU_add_test(suite, "ip: valid ipv4", test_ip_valid_ipv4) ||
        !CU_add_test(suite, "ip: valid ipv6", test_ip_valid_ipv6) ||
        !CU_add_test(suite, "ip: valid null type", test_ip_valid_null_type) ||
        !CU_add_test(suite, "ip: invalid null", test_ip_invalid_null) ||
        !CU_add_test(suite, "ip: invalid empty", test_ip_invalid_empty) ||
        !CU_add_test(suite, "ip: invalid garbage", test_ip_invalid_garbage) ||
        !CU_add_test(suite, "ip: invalid ipv4 out of range", test_ip_invalid_ipv4_out_of_range) ||
        !CU_add_test(suite, "ip: invalid ipv4 incomplete", test_ip_invalid_ipv4_incomplete) ||
        !CU_add_test(suite, "ip: invalid ipv4 extra octets", test_ip_invalid_ipv4_extra_octets) ||
        !CU_add_test(suite, "ip: invalid ipv6 bad format", test_ip_invalid_ipv6_bad_format)) {
        return CU_get_error();
    }

    /* API key tests */
    if (!CU_add_test(suite, "apikey: valid", test_apikey_valid) ||
        !CU_add_test(suite, "apikey: invalid null", test_apikey_invalid_null) ||
        !CU_add_test(suite, "apikey: invalid empty", test_apikey_invalid_empty) ||
        !CU_add_test(suite, "apikey: invalid too short", test_apikey_invalid_too_short) ||
        !CU_add_test(suite, "apikey: invalid special chars", test_apikey_invalid_special_chars)) {
        return CU_get_error();
    }

    return CUE_SUCCESS;
}
