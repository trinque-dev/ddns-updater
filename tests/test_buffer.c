/*
 * test_buffer.c - Tests for buffer operations
 *
 * SPDX-License-Identifier: MIT
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include "ddns.h"
#include "tests.h"

/* ============ Buffer Init Tests ============ */

static void test_buffer_init_default(void)
{
    ddns_buffer_t buf;
    CU_ASSERT_EQUAL(ddns_buffer_init(&buf, 0), DDNS_OK);
    CU_ASSERT_PTR_NOT_NULL(buf.data);
    CU_ASSERT_EQUAL(buf.size, 0);
    CU_ASSERT_TRUE(buf.capacity > 0);
    CU_ASSERT_STRING_EQUAL(buf.data, "");
    ddns_buffer_free(&buf);
}

static void test_buffer_init_custom_size(void)
{
    ddns_buffer_t buf;
    CU_ASSERT_EQUAL(ddns_buffer_init(&buf, 1024), DDNS_OK);
    CU_ASSERT_PTR_NOT_NULL(buf.data);
    CU_ASSERT_EQUAL(buf.size, 0);
    CU_ASSERT_EQUAL(buf.capacity, 1024);
    ddns_buffer_free(&buf);
}

static void test_buffer_init_null(void)
{
    CU_ASSERT_EQUAL(ddns_buffer_init(NULL, 0), DDNS_ERR_INVALID_ARG);
}

/* ============ Buffer Append Tests ============ */

static void test_buffer_append_simple(void)
{
    ddns_buffer_t buf;
    ddns_buffer_init(&buf, 100);

    CU_ASSERT_EQUAL(ddns_buffer_append(&buf, "hello", 5), DDNS_OK);
    CU_ASSERT_EQUAL(buf.size, 5);
    CU_ASSERT_STRING_EQUAL(buf.data, "hello");

    ddns_buffer_free(&buf);
}

static void test_buffer_append_multiple(void)
{
    ddns_buffer_t buf;
    ddns_buffer_init(&buf, 100);

    CU_ASSERT_EQUAL(ddns_buffer_append(&buf, "hello", 5), DDNS_OK);
    CU_ASSERT_EQUAL(ddns_buffer_append(&buf, " ", 1), DDNS_OK);
    CU_ASSERT_EQUAL(ddns_buffer_append(&buf, "world", 5), DDNS_OK);

    CU_ASSERT_EQUAL(buf.size, 11);
    CU_ASSERT_STRING_EQUAL(buf.data, "hello world");

    ddns_buffer_free(&buf);
}

static void test_buffer_append_grow(void)
{
    ddns_buffer_t buf;
    ddns_buffer_init(&buf, 8); /* Small initial size */

    const char *data = "this is a longer string that will require buffer growth";
    size_t len = strlen(data);

    CU_ASSERT_EQUAL(ddns_buffer_append(&buf, data, len), DDNS_OK);
    CU_ASSERT_EQUAL(buf.size, len);
    CU_ASSERT_TRUE(buf.capacity >= len + 1);
    CU_ASSERT_STRING_EQUAL(buf.data, data);

    ddns_buffer_free(&buf);
}

static void test_buffer_append_empty(void)
{
    ddns_buffer_t buf;
    ddns_buffer_init(&buf, 100);

    CU_ASSERT_EQUAL(ddns_buffer_append(&buf, "test", 4), DDNS_OK);
    CU_ASSERT_EQUAL(ddns_buffer_append(&buf, "", 0), DDNS_OK);
    CU_ASSERT_EQUAL(buf.size, 4);
    CU_ASSERT_STRING_EQUAL(buf.data, "test");

    ddns_buffer_free(&buf);
}

static void test_buffer_append_null_buf(void)
{
    CU_ASSERT_EQUAL(ddns_buffer_append(NULL, "data", 4), DDNS_ERR_INVALID_ARG);
}

static void test_buffer_append_null_data(void)
{
    ddns_buffer_t buf;
    ddns_buffer_init(&buf, 100);

    CU_ASSERT_EQUAL(ddns_buffer_append(&buf, NULL, 4), DDNS_ERR_INVALID_ARG);

    ddns_buffer_free(&buf);
}

static void test_buffer_append_binary(void)
{
    ddns_buffer_t buf;
    ddns_buffer_init(&buf, 100);

    /* Data with embedded null bytes */
    const char data[] = {'a', 'b', '\0', 'c', 'd'};
    CU_ASSERT_EQUAL(ddns_buffer_append(&buf, data, 5), DDNS_OK);
    CU_ASSERT_EQUAL(buf.size, 5);
    CU_ASSERT_EQUAL(buf.data[0], 'a');
    CU_ASSERT_EQUAL(buf.data[2], '\0');
    CU_ASSERT_EQUAL(buf.data[4], 'd');

    ddns_buffer_free(&buf);
}

/* ============ Buffer Clear Tests ============ */

static void test_buffer_clear(void)
{
    ddns_buffer_t buf;
    ddns_buffer_init(&buf, 100);

    ddns_buffer_append(&buf, "hello world", 11);
    CU_ASSERT_EQUAL(buf.size, 11);

    ddns_buffer_clear(&buf);
    CU_ASSERT_EQUAL(buf.size, 0);
    CU_ASSERT_STRING_EQUAL(buf.data, "");
    CU_ASSERT_TRUE(buf.capacity > 0); /* Capacity preserved */

    ddns_buffer_free(&buf);
}

static void test_buffer_clear_null(void)
{
    /* Should not crash */
    ddns_buffer_clear(NULL);
}

static void test_buffer_clear_reuse(void)
{
    ddns_buffer_t buf;
    ddns_buffer_init(&buf, 100);

    ddns_buffer_append(&buf, "first", 5);
    ddns_buffer_clear(&buf);
    ddns_buffer_append(&buf, "second", 6);

    CU_ASSERT_EQUAL(buf.size, 6);
    CU_ASSERT_STRING_EQUAL(buf.data, "second");

    ddns_buffer_free(&buf);
}

/* ============ Buffer Free Tests ============ */

static void test_buffer_free(void)
{
    ddns_buffer_t buf;
    ddns_buffer_init(&buf, 100);
    ddns_buffer_append(&buf, "test", 4);

    ddns_buffer_free(&buf);

    CU_ASSERT_PTR_NULL(buf.data);
    CU_ASSERT_EQUAL(buf.size, 0);
    CU_ASSERT_EQUAL(buf.capacity, 0);
}

static void test_buffer_free_null(void)
{
    /* Should not crash */
    ddns_buffer_free(NULL);
}

static void test_buffer_double_free(void)
{
    ddns_buffer_t buf;
    ddns_buffer_init(&buf, 100);

    ddns_buffer_free(&buf);
    ddns_buffer_free(&buf); /* Second free should be safe */

    CU_ASSERT_PTR_NULL(buf.data);
}

/* ============ Suite Registration ============ */

CU_ErrorCode test_buffer_register(void)
{
    CU_pSuite suite = CU_add_suite("Buffer Operations", NULL, NULL);
    if (!suite) {
        return CU_get_error();
    }

    /* Init tests */
    if (!CU_add_test(suite, "init: default", test_buffer_init_default) ||
        !CU_add_test(suite, "init: custom size", test_buffer_init_custom_size) ||
        !CU_add_test(suite, "init: null", test_buffer_init_null)) {
        return CU_get_error();
    }

    /* Append tests */
    if (!CU_add_test(suite, "append: simple", test_buffer_append_simple) ||
        !CU_add_test(suite, "append: multiple", test_buffer_append_multiple) ||
        !CU_add_test(suite, "append: grow", test_buffer_append_grow) ||
        !CU_add_test(suite, "append: empty", test_buffer_append_empty) ||
        !CU_add_test(suite, "append: null buf", test_buffer_append_null_buf) ||
        !CU_add_test(suite, "append: null data", test_buffer_append_null_data) ||
        !CU_add_test(suite, "append: binary", test_buffer_append_binary)) {
        return CU_get_error();
    }

    /* Clear tests */
    if (!CU_add_test(suite, "clear: basic", test_buffer_clear) ||
        !CU_add_test(suite, "clear: null", test_buffer_clear_null) ||
        !CU_add_test(suite, "clear: reuse", test_buffer_clear_reuse)) {
        return CU_get_error();
    }

    /* Free tests */
    if (!CU_add_test(suite, "free: basic", test_buffer_free) ||
        !CU_add_test(suite, "free: null", test_buffer_free_null) ||
        !CU_add_test(suite, "free: double", test_buffer_double_free)) {
        return CU_get_error();
    }

    return CUE_SUCCESS;
}
