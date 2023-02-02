/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * gazelle is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdlib.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>
#include "lstack_test_case.h"

typedef enum {
    LSTACK_SCREEN = 0,
    LSTACK_XMLFILE,
    LSTACK_CONSOLE
} CU_RunMode;

int main(int argc, char **argv)
{
    CU_pSuite suite;
    int num_failures;
    CU_RunMode g_cunit_mode = LSTACK_SCREEN;

    if (argc > 1) {
        g_cunit_mode = atoi(argv[1]);
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    suite = CU_add_suite("lstack", NULL, NULL);
    if (suite == NULL) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    (void)CU_ADD_TEST(suite, test_lstack_normal_param);
    (void)CU_ADD_TEST(suite, test_lstack_bad_params_devices);
    (void)CU_ADD_TEST(suite, test_lstack_bad_params_gateway_addr);
    (void)CU_ADD_TEST(suite, test_lstack_bad_params_mask_addr);
    (void)CU_ADD_TEST(suite, test_lstack_bad_params_host_addr);
    (void)CU_ADD_TEST(suite, test_lstack_bad_params_num_cpus);
    (void)CU_ADD_TEST(suite, test_lstack_bad_params_lowpower);

    switch (g_cunit_mode) {
        case LSTACK_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case LSTACK_XMLFILE:
            CU_set_output_filename("param");
            CU_list_tests_to_file();
            CU_automated_run_tests();
            break;
        case LSTACK_CONSOLE:
            CU_console_run_tests();
            break;
        default:
            (void)printf("not suport cunit mode, only suport: 0 or 1\n");
            CU_cleanup_registry();
            return CU_get_error();
    }

    num_failures = (int)CU_get_number_of_failures();
    CU_cleanup_registry();
    return num_failures;
}
