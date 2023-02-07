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

#ifndef __UTILS_H__
#define __UTILS_H__

#define LIBOS_OK 0
#define LIBOS_ERR 1

#define LIBOS_TRUE 1
#define LIBOS_FALSE 0

#define MAX_TESTCASE_NAME_LEN 128
#define MAX_CMD_RESULT_BUF_LEN 1024
#define SLEPP_CYCLE_S 1
#define MAX_CMD_LEN 512
#define MAX_PATH_LEN 256

void execute_cmd(const char *cmd);

int check_if_cmd_ret_contains(const char *exec_cmd, const char *expect_ret);
int check_journalctl_contains(const char *expect_ret, const unsigned int timeout_s);
int check_if_file_contains(const char *file_path, const char *expect_str, const unsigned int timeout_s);
int check_if_process_exist(const char *process_name);
int check_cpu_uasge(const char *file_path);

void create_dir(const char *dir_path);
void remove_dir(const char *dir_path);
void create_file(const char *file_path);
void remove_file(const char *file_path);
int get_test_ip(const char *path, int offset, char *ip, int ip_maxlen);

#endif
