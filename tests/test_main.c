/*
 * test_main.c - CUnit test runner for ddns-updater
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "tests.h"

int main(void)
{
    unsigned int failures = 1; /* Assume failure unless tests run */
    int result;

    /* Initialize CUnit registry */
    if (CU_initialize_registry() != CUE_SUCCESS) {
        fprintf(stderr, "Failed to initialize CUnit registry\n");
        result = (int)CU_get_error();
        return result;
    }

    /* Register test suites */
    if (test_validation_register() != CUE_SUCCESS) {
        fprintf(stderr, "Failed to register validation tests\n");
        goto cleanup;
    }

    if (test_private_ip_register() != CUE_SUCCESS) {
        fprintf(stderr, "Failed to register private IP tests\n");
        goto cleanup;
    }

    if (test_xml_register() != CUE_SUCCESS) {
        fprintf(stderr, "Failed to register XML tests\n");
        goto cleanup;
    }

    if (test_buffer_register() != CUE_SUCCESS) {
        fprintf(stderr, "Failed to register buffer tests\n");
        goto cleanup;
    }

    if (test_domain_parts_register() != CUE_SUCCESS) {
        fprintf(stderr, "Failed to register domain parts tests\n");
        goto cleanup;
    }

    /* Run tests using basic interface */
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    /* Get failure count before cleanup */
    failures = CU_get_number_of_failures();

cleanup:
    CU_cleanup_registry();
    return (failures > 0) ? 1 : 0;
}
