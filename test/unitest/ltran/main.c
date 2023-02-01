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
#include "ltran_test_case.h"

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} CU_RunMode;

int main(int argc, char **argv)
{
    CU_pSuite suite;
    int num_failures;
    CU_RunMode g_cunit_mode = CUNIT_SCREEN;

    if (argc > 1) {
        g_cunit_mode = atoi(argv[1]);
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    suite = CU_add_suite("ltran", NULL, NULL);
    if (suite == NULL) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    (void)CU_ADD_TEST(suite, test_ltran_instance);
    (void)CU_ADD_TEST(suite, test_ltran_stack);
    (void)CU_ADD_TEST(suite, test_ltran_normal_param);
    (void)CU_ADD_TEST(suite, test_ltran_bad_params_clients);
    (void)CU_ADD_TEST(suite, test_ltran_bad_params_port);
    (void)CU_ADD_TEST(suite, test_ltran_bad_params_subnet);
    (void)CU_ADD_TEST(suite, test_ltran_bad_params_bond_mode);
    (void)CU_ADD_TEST(suite, test_ltran_bad_params_bond_miimon);
    (void)CU_ADD_TEST(suite, test_ltran_bad_params_bond_mtu);
    (void)CU_ADD_TEST(suite, test_ltran_bad_params_macs);
    (void)CU_ADD_TEST(suite, test_tcp_conn);
    (void)CU_ADD_TEST(suite, test_tcp_sock);

    switch (g_cunit_mode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("instance");
            CU_list_tests_to_file();
            CU_automated_run_tests();
            break;
        case CUNIT_CONSOLE:
            CU_console_run_tests();
            break;
        default:
            (void)printf("not suport mode=%d\n", g_cunit_mode);
            CU_cleanup_registry();
            return CU_get_error();
    }

    num_failures = (int)CU_get_number_of_failures();
    CU_cleanup_registry();
    return num_failures;
}
