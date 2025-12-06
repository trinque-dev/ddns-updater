/*
 * test_xml.c - Tests for XML parsing functions
 *
 * SPDX-License-Identifier: MIT
 */

#include <CUnit/CUnit.h>
#include <stdlib.h>
#include <string.h>
#include "xml.h"
#include "tests.h"

/* ============ xml_find_element Tests ============ */

static void test_xml_find_element_simple(void)
{
    const char *xml = "<root><code>300</code></root>";
    char *result = xml_find_element(xml, "code");
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, "300");
        free(result);
    }
}

static void test_xml_find_element_nested(void)
{
    const char *xml = "<root><outer><inner>value</inner></outer></root>";
    char *result = xml_find_element(xml, "inner");
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, "value");
        free(result);
    }
}

static void test_xml_find_element_with_attributes(void)
{
    const char *xml = "<root><item id=\"123\">content</item></root>";
    char *result = xml_find_element(xml, "item");
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, "content");
        free(result);
    }
}

static void test_xml_find_element_empty_content(void)
{
    const char *xml = "<root><empty></empty></root>";
    char *result = xml_find_element(xml, "empty");
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, "");
        free(result);
    }
}

static void test_xml_find_element_not_found(void)
{
    const char *xml = "<root><code>300</code></root>";
    char *result = xml_find_element(xml, "notfound");
    CU_ASSERT_PTR_NULL(result);
}

static void test_xml_find_element_null_xml(void)
{
    char *result = xml_find_element(NULL, "code");
    CU_ASSERT_PTR_NULL(result);
}

static void test_xml_find_element_null_tag(void)
{
    const char *xml = "<root><code>300</code></root>";
    char *result = xml_find_element(xml, NULL);
    CU_ASSERT_PTR_NULL(result);
}

static void test_xml_find_element_empty_tag(void)
{
    const char *xml = "<root><code>300</code></root>";
    char *result = xml_find_element(xml, "");
    CU_ASSERT_PTR_NULL(result);
}

static void test_xml_find_element_namesilo_response(void)
{
    /* Real-world Namesilo response structure */
    const char *xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<namesilo>"
        "<request><operation>dnsListRecords</operation></request>"
        "<reply>"
        "<code>300</code>"
        "<detail>success</detail>"
        "<resource_record>"
        "<record_id>abc123</record_id>"
        "<type>A</type>"
        "<host>home.example.com</host>"
        "<value>1.2.3.4</value>"
        "<ttl>3600</ttl>"
        "</resource_record>"
        "</reply>"
        "</namesilo>";

    char *code = xml_find_element(xml, "code");
    CU_ASSERT_PTR_NOT_NULL(code);
    if (code) {
        CU_ASSERT_STRING_EQUAL(code, "300");
        free(code);
    }

    char *detail = xml_find_element(xml, "detail");
    CU_ASSERT_PTR_NOT_NULL(detail);
    if (detail) {
        CU_ASSERT_STRING_EQUAL(detail, "success");
        free(detail);
    }

    char *record_id = xml_find_element(xml, "record_id");
    CU_ASSERT_PTR_NOT_NULL(record_id);
    if (record_id) {
        CU_ASSERT_STRING_EQUAL(record_id, "abc123");
        free(record_id);
    }

    char *host = xml_find_element(xml, "host");
    CU_ASSERT_PTR_NOT_NULL(host);
    if (host) {
        CU_ASSERT_STRING_EQUAL(host, "home.example.com");
        free(host);
    }
}

static void test_xml_find_element_first_match(void)
{
    /* Should return first matching element */
    const char *xml = "<root><item>first</item><item>second</item></root>";
    char *result = xml_find_element(xml, "item");
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, "first");
        free(result);
    }
}

/* ============ xml_find_attribute Tests ============ */

static void test_xml_find_attribute_simple(void)
{
    const char *xml = "<root><item id=\"123\">content</item></root>";
    char *result = xml_find_attribute(xml, "item", "id");
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, "123");
        free(result);
    }
}

static void test_xml_find_attribute_multiple(void)
{
    const char *xml = "<root><item id=\"123\" name=\"test\" type=\"A\">content</item></root>";

    char *id = xml_find_attribute(xml, "item", "id");
    CU_ASSERT_PTR_NOT_NULL(id);
    if (id) {
        CU_ASSERT_STRING_EQUAL(id, "123");
        free(id);
    }

    char *name = xml_find_attribute(xml, "item", "name");
    CU_ASSERT_PTR_NOT_NULL(name);
    if (name) {
        CU_ASSERT_STRING_EQUAL(name, "test");
        free(name);
    }
}

static void test_xml_find_attribute_not_found(void)
{
    const char *xml = "<root><item id=\"123\">content</item></root>";
    char *result = xml_find_attribute(xml, "item", "notfound");
    CU_ASSERT_PTR_NULL(result);
}

static void test_xml_find_attribute_tag_not_found(void)
{
    const char *xml = "<root><item id=\"123\">content</item></root>";
    char *result = xml_find_attribute(xml, "notfound", "id");
    CU_ASSERT_PTR_NULL(result);
}

static void test_xml_find_attribute_null_params(void)
{
    const char *xml = "<root><item id=\"123\">content</item></root>";
    CU_ASSERT_PTR_NULL(xml_find_attribute(NULL, "item", "id"));
    CU_ASSERT_PTR_NULL(xml_find_attribute(xml, NULL, "id"));
    CU_ASSERT_PTR_NULL(xml_find_attribute(xml, "item", NULL));
}

/* ============ xml_decode_entities Tests ============ */

static void test_xml_decode_entities_amp(void)
{
    char *result = xml_decode_entities("foo &amp; bar");
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, "foo & bar");
        free(result);
    }
}

static void test_xml_decode_entities_lt_gt(void)
{
    char *result = xml_decode_entities("&lt;tag&gt;");
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, "<tag>");
        free(result);
    }
}

static void test_xml_decode_entities_quot_apos(void)
{
    char *result = xml_decode_entities("&quot;hello&apos;");
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, "\"hello'");
        free(result);
    }
}

static void test_xml_decode_entities_mixed(void)
{
    char *result = xml_decode_entities("&lt;a href=&quot;test&amp;foo&quot;&gt;");
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, "<a href=\"test&foo\">");
        free(result);
    }
}

static void test_xml_decode_entities_no_entities(void)
{
    char *result = xml_decode_entities("plain text");
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, "plain text");
        free(result);
    }
}

static void test_xml_decode_entities_null(void)
{
    char *result = xml_decode_entities(NULL);
    CU_ASSERT_PTR_NULL(result);
}

static void test_xml_decode_entities_unknown(void)
{
    /* Unknown entities should be passed through as-is */
    char *result = xml_decode_entities("&unknown;");
    CU_ASSERT_PTR_NOT_NULL(result);
    if (result) {
        CU_ASSERT_STRING_EQUAL(result, "&unknown;");
        free(result);
    }
}

/* ============ xml_check_success Tests ============ */

static void test_xml_check_success_true(void)
{
    const char *xml = "<response><code>300</code></response>";
    CU_ASSERT_TRUE(xml_check_success(xml, "code", "300"));
}

static void test_xml_check_success_false(void)
{
    const char *xml = "<response><code>400</code></response>";
    CU_ASSERT_FALSE(xml_check_success(xml, "code", "300"));
}

static void test_xml_check_success_not_found(void)
{
    const char *xml = "<response><error>bad</error></response>";
    CU_ASSERT_FALSE(xml_check_success(xml, "code", "300"));
}

static void test_xml_check_success_null_params(void)
{
    const char *xml = "<response><code>300</code></response>";
    CU_ASSERT_FALSE(xml_check_success(NULL, "code", "300"));
    CU_ASSERT_FALSE(xml_check_success(xml, NULL, "300"));
    CU_ASSERT_FALSE(xml_check_success(xml, "code", NULL));
}

/* ============ Suite Registration ============ */

CU_ErrorCode test_xml_register(void)
{
    CU_pSuite suite = CU_add_suite("XML Parsing", NULL, NULL);
    if (!suite) {
        return CU_get_error();
    }

    /* xml_find_element tests */
    if (!CU_add_test(suite, "find_element: simple", test_xml_find_element_simple) ||
        !CU_add_test(suite, "find_element: nested", test_xml_find_element_nested) ||
        !CU_add_test(suite, "find_element: with attributes", test_xml_find_element_with_attributes) ||
        !CU_add_test(suite, "find_element: empty content", test_xml_find_element_empty_content) ||
        !CU_add_test(suite, "find_element: not found", test_xml_find_element_not_found) ||
        !CU_add_test(suite, "find_element: null xml", test_xml_find_element_null_xml) ||
        !CU_add_test(suite, "find_element: null tag", test_xml_find_element_null_tag) ||
        !CU_add_test(suite, "find_element: empty tag", test_xml_find_element_empty_tag) ||
        !CU_add_test(suite, "find_element: namesilo response", test_xml_find_element_namesilo_response) ||
        !CU_add_test(suite, "find_element: first match", test_xml_find_element_first_match)) {
        return CU_get_error();
    }

    /* xml_find_attribute tests */
    if (!CU_add_test(suite, "find_attribute: simple", test_xml_find_attribute_simple) ||
        !CU_add_test(suite, "find_attribute: multiple", test_xml_find_attribute_multiple) ||
        !CU_add_test(suite, "find_attribute: not found", test_xml_find_attribute_not_found) ||
        !CU_add_test(suite, "find_attribute: tag not found", test_xml_find_attribute_tag_not_found) ||
        !CU_add_test(suite, "find_attribute: null params", test_xml_find_attribute_null_params)) {
        return CU_get_error();
    }

    /* xml_decode_entities tests */
    if (!CU_add_test(suite, "decode_entities: amp", test_xml_decode_entities_amp) ||
        !CU_add_test(suite, "decode_entities: lt/gt", test_xml_decode_entities_lt_gt) ||
        !CU_add_test(suite, "decode_entities: quot/apos", test_xml_decode_entities_quot_apos) ||
        !CU_add_test(suite, "decode_entities: mixed", test_xml_decode_entities_mixed) ||
        !CU_add_test(suite, "decode_entities: no entities", test_xml_decode_entities_no_entities) ||
        !CU_add_test(suite, "decode_entities: null", test_xml_decode_entities_null) ||
        !CU_add_test(suite, "decode_entities: unknown", test_xml_decode_entities_unknown)) {
        return CU_get_error();
    }

    /* xml_check_success tests */
    if (!CU_add_test(suite, "check_success: true", test_xml_check_success_true) ||
        !CU_add_test(suite, "check_success: false", test_xml_check_success_false) ||
        !CU_add_test(suite, "check_success: not found", test_xml_check_success_not_found) ||
        !CU_add_test(suite, "check_success: null params", test_xml_check_success_null_params)) {
        return CU_get_error();
    }

    return CUE_SUCCESS;
}
