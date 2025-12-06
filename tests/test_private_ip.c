/*
 * test_private_ip.c - Tests for private/reserved IP detection
 *
 * SPDX-License-Identifier: MIT
 */

#include <CUnit/CUnit.h>
#include "ddns.h"
#include "tests.h"

/* ============ IPv4 Private Range Tests ============ */

static void test_private_ipv4_10_block(void)
{
    /* 10.0.0.0/8 */
    CU_ASSERT_TRUE(ddns_is_private_ip("10.0.0.0"));
    CU_ASSERT_TRUE(ddns_is_private_ip("10.0.0.1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("10.255.255.255"));
    CU_ASSERT_TRUE(ddns_is_private_ip("10.123.45.67"));
}

static void test_private_ipv4_172_block(void)
{
    /* 172.16.0.0/12 */
    CU_ASSERT_TRUE(ddns_is_private_ip("172.16.0.0"));
    CU_ASSERT_TRUE(ddns_is_private_ip("172.16.0.1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("172.31.255.255"));
    CU_ASSERT_TRUE(ddns_is_private_ip("172.20.10.5"));

    /* Just outside the range */
    CU_ASSERT_FALSE(ddns_is_private_ip("172.15.255.255"));
    CU_ASSERT_FALSE(ddns_is_private_ip("172.32.0.0"));
}

static void test_private_ipv4_192_168_block(void)
{
    /* 192.168.0.0/16 */
    CU_ASSERT_TRUE(ddns_is_private_ip("192.168.0.0"));
    CU_ASSERT_TRUE(ddns_is_private_ip("192.168.0.1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("192.168.255.255"));
    CU_ASSERT_TRUE(ddns_is_private_ip("192.168.1.100"));

    /* Just outside */
    CU_ASSERT_FALSE(ddns_is_private_ip("192.167.255.255"));
    CU_ASSERT_FALSE(ddns_is_private_ip("192.169.0.0"));
}

static void test_private_ipv4_loopback(void)
{
    /* 127.0.0.0/8 */
    CU_ASSERT_TRUE(ddns_is_private_ip("127.0.0.1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("127.0.0.0"));
    CU_ASSERT_TRUE(ddns_is_private_ip("127.255.255.255"));
    CU_ASSERT_TRUE(ddns_is_private_ip("127.1.2.3"));
}

static void test_private_ipv4_link_local(void)
{
    /* 169.254.0.0/16 */
    CU_ASSERT_TRUE(ddns_is_private_ip("169.254.0.0"));
    CU_ASSERT_TRUE(ddns_is_private_ip("169.254.0.1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("169.254.255.255"));
    CU_ASSERT_TRUE(ddns_is_private_ip("169.254.169.254")); /* AWS metadata */
}

static void test_private_ipv4_cgnat(void)
{
    /* 100.64.0.0/10 (CGNAT) */
    CU_ASSERT_TRUE(ddns_is_private_ip("100.64.0.0"));
    CU_ASSERT_TRUE(ddns_is_private_ip("100.64.0.1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("100.127.255.255"));
    CU_ASSERT_TRUE(ddns_is_private_ip("100.100.100.100"));

    /* Just outside */
    CU_ASSERT_FALSE(ddns_is_private_ip("100.63.255.255"));
    CU_ASSERT_FALSE(ddns_is_private_ip("100.128.0.0"));
}

static void test_private_ipv4_test_nets(void)
{
    /* TEST-NET-1: 192.0.2.0/24 */
    CU_ASSERT_TRUE(ddns_is_private_ip("192.0.2.0"));
    CU_ASSERT_TRUE(ddns_is_private_ip("192.0.2.1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("192.0.2.255"));

    /* TEST-NET-2: 198.51.100.0/24 */
    CU_ASSERT_TRUE(ddns_is_private_ip("198.51.100.0"));
    CU_ASSERT_TRUE(ddns_is_private_ip("198.51.100.1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("198.51.100.255"));

    /* TEST-NET-3: 203.0.113.0/24 */
    CU_ASSERT_TRUE(ddns_is_private_ip("203.0.113.0"));
    CU_ASSERT_TRUE(ddns_is_private_ip("203.0.113.1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("203.0.113.255"));
}

static void test_private_ipv4_multicast(void)
{
    /* 224.0.0.0/4 */
    CU_ASSERT_TRUE(ddns_is_private_ip("224.0.0.0"));
    CU_ASSERT_TRUE(ddns_is_private_ip("224.0.0.1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("239.255.255.255"));
}

static void test_private_ipv4_reserved(void)
{
    /* 240.0.0.0/4 and broadcast */
    CU_ASSERT_TRUE(ddns_is_private_ip("240.0.0.0"));
    CU_ASSERT_TRUE(ddns_is_private_ip("255.255.255.255"));

    /* 0.0.0.0/8 */
    CU_ASSERT_TRUE(ddns_is_private_ip("0.0.0.0"));
    CU_ASSERT_TRUE(ddns_is_private_ip("0.1.2.3"));
}

static void test_public_ipv4(void)
{
    /* Common public IPs */
    CU_ASSERT_FALSE(ddns_is_private_ip("8.8.8.8"));        /* Google DNS */
    CU_ASSERT_FALSE(ddns_is_private_ip("1.1.1.1"));        /* Cloudflare */
    CU_ASSERT_FALSE(ddns_is_private_ip("208.67.222.222")); /* OpenDNS */
    CU_ASSERT_FALSE(ddns_is_private_ip("93.184.216.34")); /* example.com */
    CU_ASSERT_FALSE(ddns_is_private_ip("151.101.1.140")); /* Reddit */

    /* Edge cases near private ranges */
    CU_ASSERT_FALSE(ddns_is_private_ip("9.255.255.255"));
    CU_ASSERT_FALSE(ddns_is_private_ip("11.0.0.0"));
    CU_ASSERT_FALSE(ddns_is_private_ip("126.255.255.255"));
    CU_ASSERT_FALSE(ddns_is_private_ip("128.0.0.0"));
}

/* ============ IPv6 Private Range Tests ============ */

static void test_private_ipv6_loopback(void)
{
    CU_ASSERT_TRUE(ddns_is_private_ip("::1"));
}

static void test_private_ipv6_unspecified(void)
{
    CU_ASSERT_TRUE(ddns_is_private_ip("::"));
}

static void test_private_ipv6_unique_local(void)
{
    /* fc00::/7 */
    CU_ASSERT_TRUE(ddns_is_private_ip("fc00::1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("fd00::1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
}

static void test_private_ipv6_link_local(void)
{
    /* fe80::/10 */
    CU_ASSERT_TRUE(ddns_is_private_ip("fe80::1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("fe80::abcd:1234:5678:9abc"));
    CU_ASSERT_TRUE(ddns_is_private_ip("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
}

static void test_private_ipv6_multicast(void)
{
    /* ff00::/8 */
    CU_ASSERT_TRUE(ddns_is_private_ip("ff00::1"));
    CU_ASSERT_TRUE(ddns_is_private_ip("ff02::1")); /* All nodes */
    CU_ASSERT_TRUE(ddns_is_private_ip("ff05::1")); /* Site-local */
}

static void test_public_ipv6(void)
{
    /* Global unicast addresses */
    CU_ASSERT_FALSE(ddns_is_private_ip("2001:db8::1")); /* Documentation, but parsed as global */
    CU_ASSERT_FALSE(ddns_is_private_ip("2606:4700:4700::1111")); /* Cloudflare */
    CU_ASSERT_FALSE(ddns_is_private_ip("2001:4860:4860::8888")); /* Google */
}

/* ============ Edge Cases ============ */

static void test_private_ip_null(void)
{
    CU_ASSERT_FALSE(ddns_is_private_ip(NULL));
}

static void test_private_ip_empty(void)
{
    CU_ASSERT_FALSE(ddns_is_private_ip(""));
}

static void test_private_ip_invalid(void)
{
    /* Invalid IPs should return false (not private), validation is separate */
    CU_ASSERT_FALSE(ddns_is_private_ip("not an ip"));
    CU_ASSERT_FALSE(ddns_is_private_ip("999.999.999.999"));
}

/* ============ Suite Registration ============ */

CU_ErrorCode test_private_ip_register(void)
{
    CU_pSuite suite = CU_add_suite("Private IP Detection", NULL, NULL);
    if (!suite) {
        return CU_get_error();
    }

    /* IPv4 private ranges */
    if (!CU_add_test(suite, "ipv4: 10/8 block", test_private_ipv4_10_block) ||
        !CU_add_test(suite, "ipv4: 172.16/12 block", test_private_ipv4_172_block) ||
        !CU_add_test(suite, "ipv4: 192.168/16 block", test_private_ipv4_192_168_block) ||
        !CU_add_test(suite, "ipv4: loopback", test_private_ipv4_loopback) ||
        !CU_add_test(suite, "ipv4: link-local", test_private_ipv4_link_local) ||
        !CU_add_test(suite, "ipv4: CGNAT", test_private_ipv4_cgnat) ||
        !CU_add_test(suite, "ipv4: test nets", test_private_ipv4_test_nets) ||
        !CU_add_test(suite, "ipv4: multicast", test_private_ipv4_multicast) ||
        !CU_add_test(suite, "ipv4: reserved", test_private_ipv4_reserved) ||
        !CU_add_test(suite, "ipv4: public", test_public_ipv4)) {
        return CU_get_error();
    }

    /* IPv6 private ranges */
    if (!CU_add_test(suite, "ipv6: loopback", test_private_ipv6_loopback) ||
        !CU_add_test(suite, "ipv6: unspecified", test_private_ipv6_unspecified) ||
        !CU_add_test(suite, "ipv6: unique local", test_private_ipv6_unique_local) ||
        !CU_add_test(suite, "ipv6: link-local", test_private_ipv6_link_local) ||
        !CU_add_test(suite, "ipv6: multicast", test_private_ipv6_multicast) ||
        !CU_add_test(suite, "ipv6: public", test_public_ipv6)) {
        return CU_get_error();
    }

    /* Edge cases */
    if (!CU_add_test(suite, "edge: null", test_private_ip_null) ||
        !CU_add_test(suite, "edge: empty", test_private_ip_empty) ||
        !CU_add_test(suite, "edge: invalid", test_private_ip_invalid)) {
        return CU_get_error();
    }

    return CUE_SUCCESS;
}
