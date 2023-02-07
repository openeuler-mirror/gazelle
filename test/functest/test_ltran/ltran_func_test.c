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
#include <unistd.h>
#include <securec.h>

#include "utils.h"
#include "common.h"

typedef enum {
    LTRANFUNC_SCREEN = 0,
    LTRANFUNC_XMLFILE,
    LTRANFUNC_CONSOLE
} CU_RunMode;

static void restore_tmp_config(void)
{
    execute_cmd("rm -rf ../test_ltran/config/config_tmp.conf");
    execute_cmd("cp -f ../test_ltran/config/config_example.conf ../test_ltran/config/config_tmp.       conf");
}

static void test_ltran_sys_log_switch(void)
{
    char cmd[MAX_CMD_LEN];
    int ret;

    // 配置log开关
    restore_tmp_config();
    execute_cmd("sed -i 's/map-perfect/map-perfect --syslog daemon/'  ../test_ltran/config/confi       g_tmp.conf;"
        "rm -fr /var/log/messages");
    ret = sprintf_s(cmd, MAX_CMD_LEN, "stdbuf -oL ltran --config-file ../test_ltran/config/confi       g_tmp.conf"
        " > %s 2>&1 &", LTRAN_LOG_PATH);
    CU_ASSERT(ret > 0);

    reset_env();
    execute_cmd(cmd);
    ret = check_journalctl_contains("Runing Process forward", LANTENCY_LOG_TMOUT_S);
    CU_ASSERT(ret == LIBOS_OK);
    restore_tmp_config();
    reset_env();
}

static void test_ltran_cmd_short_help(void)
{
    char cmd[MAX_CMD_LEN];
    // 检验命令行-h参数
    int ret = sprintf_s(cmd, MAX_CMD_LEN, "ltran -h > %s 2>&1 &", LTRAN_LOG_PATH);
    CU_ASSERT(ret > 0);

    execute_cmd(cmd);
    // 期望提示ltran使用方法
    ret = check_if_file_contains(LTRAN_LOG_PATH, "Usage:", CAT_LOG_TMOUT_S);
    CU_ASSERT(ret == LIBOS_OK);
}

static void test_ltran_cmd_long_help(void)
{
    char cmd[MAX_CMD_LEN];
    // 检验命令行-h参数
    int ret = sprintf_s(cmd, MAX_CMD_LEN, "ltran --help > %s 2>&1 &", LTRAN_LOG_PATH);
    CU_ASSERT(ret > 0);

    execute_cmd(cmd);
    // 期望提示ltran使用方法
    ret = check_if_file_contains(LTRAN_LOG_PATH, "Usage:", CAT_LOG_TMOUT_S);
    CU_ASSERT(ret == LIBOS_OK);
}

static void test_ltran_cmd_short_version(void)
{
    char cmd[MAX_CMD_LEN];
    // 检验命令行-h参数
    int ret = sprintf_s(cmd, MAX_CMD_LEN, "ltran -v > %s 2>&1 &", LTRAN_LOG_PATH);
    CU_ASSERT(ret > 0);

    execute_cmd(cmd);
    // 期望提示ltran使用方法
    ret = check_if_file_contains(LTRAN_LOG_PATH, "version:", CAT_LOG_TMOUT_S);
    CU_ASSERT(ret == LIBOS_OK);
}

static void test_ltran_cmd_long_version(void)
{
    char cmd[MAX_CMD_LEN];
    // 检验命令行-h参数
    int ret = sprintf_s(cmd, MAX_CMD_LEN, "ltran --version > %s 2>&1 &", LTRAN_LOG_PATH);
    CU_ASSERT(ret > 0);

    execute_cmd(cmd);
    // 期望提示ltran使用方法
    ret = check_if_file_contains(LTRAN_LOG_PATH, "version:", CAT_LOG_TMOUT_S);
    CU_ASSERT(ret == LIBOS_OK);
}

static void test_ltran_start_default_config_file(void)
{
    char cmd[MAX_CMD_LEN];
    // 使用默认config_file, 且config_file文件存在
    execute_cmd("mkdir -p /etc/gazelle");
    execute_cmd("rm -rf /etc/gazelle/ltran.conf");
    execute_cmd("cp -rf ../test_ltran/config/config_example.conf /etc/gazelle/ltran.conf");
    int ret = sprintf_s(cmd, MAX_CMD_LEN, "stdbuf -oL nohup ltran > %s 2>&1 &", LTRAN_LOG_PATH);
    CU_ASSERT(ret > 0);

    reset_env();
    execute_cmd(cmd);
    // 期望启动成功
    CU_ASSERT(check_if_ltran_start_succeed() == LIBOS_OK);
    reset_env();
}

static void test_ltran_start_none_config_file(void)
{
    char cmd[MAX_CMD_LEN];
    // 使用默认config_file，但是config_file文件不存在
    execute_cmd("rm -rf /etc/gazelle/ltran.conf");
    int ret = sprintf_s(cmd, MAX_CMD_LEN, "ltran > %s 2>&1 &", LTRAN_LOG_PATH);
    CU_ASSERT(ret > 0);

    reset_env();
    execute_cmd(cmd);
    // 期望启动失败
    CU_ASSERT(check_if_ltran_start_succeed() == LIBOS_ERR);
    reset_env();
}

static void suite_ltran_subset_001(CU_pSuite suite)
{
    (void)CU_ADD_TEST(suite, test_ltran_cmd_short_help);
    (void)CU_ADD_TEST(suite, test_ltran_cmd_long_help);
    (void)CU_ADD_TEST(suite, test_ltran_cmd_short_version);
    (void)CU_ADD_TEST(suite, test_ltran_cmd_long_version);
    (void)CU_ADD_TEST(suite, test_ltran_start_default_config_file);
    (void)CU_ADD_TEST(suite, test_ltran_start_none_config_file);
    (void)CU_ADD_TEST(suite, test_ltran_sys_log_switch);
}

int main(int argc, char **argv)
{
    CU_pSuite suite;
    unsigned int num_failures;
    CU_RunMode g_cunit_mode = LTRANFUNC_SCREEN;

    if (argc > 1) {
        g_cunit_mode = atoi(argv[1]);
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    suite = CU_add_suite("test_ltran", NULL, NULL);
    if (suite == NULL) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    suite_ltran_subset_001(suite);

    switch (g_cunit_mode) {
        case LTRANFUNC_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case LTRANFUNC_XMLFILE:
            CU_set_output_filename("test_ltran");
            CU_list_tests_to_file();
            CU_automated_run_tests();
            break;
        case LTRANFUNC_CONSOLE:
            CU_console_run_tests();
            break;
        default:
            (void)printf("not suport mode, only suport: 0 or 1\n");
            CU_cleanup_registry();
            return CU_get_error();
    }

    num_failures = CU_get_number_of_failures();
    CU_cleanup_registry();
    return num_failures;
}
