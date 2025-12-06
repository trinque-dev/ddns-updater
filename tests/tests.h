/*
 * tests.h - Test suite registration declarations
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef TESTS_H
#define TESTS_H

#include <CUnit/CUnit.h>

/* Test suite registration functions */
CU_ErrorCode test_validation_register(void);
CU_ErrorCode test_private_ip_register(void);
CU_ErrorCode test_xml_register(void);
CU_ErrorCode test_buffer_register(void);
CU_ErrorCode test_domain_parts_register(void);

#endif /* TESTS_H */
