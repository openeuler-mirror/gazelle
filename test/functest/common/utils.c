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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <securec.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "utils.h"

#define IP_ADD_STEP     0x1000000
/* input path must lstack.conf */
int get_test_ip(const char *path, int offset, char *ip, int ip_maxlen)
{
    FILE *fstream = NULL;
    char cmd[MAX_CMD_LEN] = {0};
    struct in_addr tmp_ip;
    int ret;

    if (access(path, 0) < 0) {
        printf("%s is not exit\n", path);
        return -LIBOS_ERR;
    }

    if (ip == NULL) {
        printf("ip is NULL\n");
        return -LIBOS_ERR;
    }

    ret = sprintf_s(cmd, MAX_CMD_LEN, "cat %s | grep host_addr= | awk -F '\"' '{print $2}'", path);
    if (ret < 0) {
        printf("sprintf_s err ret=%d\n", ret);
        return -LIBOS_ERR;
    }

    fstream = popen(cmd, "r");
    if (fstream == NULL) {
        return -LIBOS_ERR;
    }

    if (fgets(ip, ip_maxlen, fstream) == NULL) {
        pclose(fstream);
        return -LIBOS_ERR;
    }
    pclose(fstream);

    /* delete \n */
    int i = 0;
    while (i < ip_maxlen && ip[i] != '\0') {
        if (ip[i] == '\n') {
            ip[i] = '\0';
            break;
        }
        i++;
    }

    if (inet_pton(AF_INET, ip, &tmp_ip) > 0) {
        tmp_ip.s_addr += offset * IP_ADD_STEP;
        if (inet_ntop(AF_INET, &tmp_ip, ip, ip_maxlen)) {
            return LIBOS_OK;
        }
    }

    return -LIBOS_ERR;
}
void execute_cmd(const char *cmd)
{
    int ret;
#ifdef LLT_DEBUG
    printf("Executing cmd: %s\n", cmd);
#endif
    ret = system(cmd);
    if (ret < 0) {
        printf("Executing cmd: %s error!!!\n", cmd);
        abort();
    }
    return;
}

int check_cmd_ret(const char* cmd)
{
    FILE *fstream = NULL;
    char *gets_ret = NULL;
    char buf[MAX_CMD_RESULT_BUF_LEN];
    (void)memset_s(buf, MAX_CMD_RESULT_BUF_LEN, 0, MAX_CMD_RESULT_BUF_LEN);

    fstream = popen(cmd, "r");
    if (fstream == NULL) {
        return LIBOS_ERR;
    }

    gets_ret = fgets(buf, MAX_CMD_RESULT_BUF_LEN, fstream);
    if (gets_ret != NULL) {
        pclose(fstream);
        return LIBOS_OK;
    }

    pclose(fstream);
    system(cmd);
    return LIBOS_ERR;
}

int check_if_cmd_ret_contains(const char *exec_cmd, const char *expect_ret)
{
    int ret;
    char cmd[MAX_CMD_LEN];
    (void)memset_s(cmd, MAX_CMD_LEN, 0, MAX_CMD_LEN);

    ret = sprintf_s(cmd, MAX_CMD_LEN, "%s | grep \"%s\"", exec_cmd, expect_ret);
    if (ret < 0) {
        return LIBOS_ERR;
    }
#ifdef LLT_DEBUG
    printf("Executing cmd: %s\n", cmd);
#endif
    return check_cmd_ret(cmd);
}

static int check_cmd_contains(const char *subcmd, const char *expect_str, const unsigned int timeout_s)
{
    char cmd[MAX_CMD_LEN];
    unsigned int time_s = 0;
    int ret;

    (void)memset_s(cmd, MAX_CMD_LEN, 0, MAX_CMD_LEN);

    ret = sprintf_s(cmd, MAX_CMD_LEN, "%s | grep --text \"%s\"", subcmd, expect_str);
    if (ret < 0) {
        return LIBOS_ERR;
    }
    while (time_s < timeout_s) {
        sleep(SLEPP_CYCLE_S);
        time_s += SLEPP_CYCLE_S;

#ifdef LLT_DEBUG
        printf("Executing cmd: %s\n", cmd);
#endif
        ret = check_cmd_ret(cmd);
        if (ret == LIBOS_OK) {
            return LIBOS_OK;
        }
    }
    system(subcmd);
    return LIBOS_ERR;
}

int check_cpu_uasge(const char *file_path)
{
    int ret;
    int usage_integer;
    int usage_float;

    FILE *fstream = NULL;
    fstream = fopen(file_path, "r");
    if (fstream == NULL) {
        return LIBOS_ERR;
    }

    ret = fscanf_s(fstream, "%d.%d", &usage_integer, &usage_float);
    if (ret < 1) {
        pclose(fstream);
        return LIBOS_ERR;
    }

    ret = LIBOS_OK;
    if (usage_integer > 40) { /* when low power mode is on, cpu usage should below 40% */
        ret = LIBOS_ERR;
    }
    pclose(fstream);
    return ret;
}

int check_journalctl_contains(const char *expect_str, const unsigned int timeout_s)
{
    return check_cmd_contains("journalctl", expect_str, timeout_s);
}

int check_if_file_contains(const char *filepath, const char *expect_str, const unsigned int timeout_s)
{
    char cmd[MAX_CMD_LEN] = {0};
    int ret = sprintf_s(cmd, MAX_CMD_LEN, "cat %s", filepath);
    if (ret < 0) {
        return LIBOS_ERR;
    }

    return check_cmd_contains(cmd, expect_str, timeout_s);
}

int check_if_process_exist(const char *process_name)
{
    char cmd[MAX_CMD_LEN];
    int ret;

    (void)memset_s(cmd, MAX_CMD_LEN, 0, MAX_CMD_LEN);

    ret = sprintf_s(cmd, MAX_CMD_LEN, "pidof %s", process_name);
    if (ret < 0) {
        return LIBOS_ERR;
    }
#ifdef LLT_DEBUG
    printf("Executing cmd: %s\n", cmd);
#endif

    return check_cmd_ret(cmd);
}

void create_dir(const char *dir_path)
{
    char cmd[MAX_CMD_LEN];
    (void)memset_s(cmd, MAX_CMD_LEN, 0, MAX_CMD_LEN);
    int ret = sprintf_s(cmd, MAX_CMD_LEN, "mkdir -p %s", dir_path);
    if (ret < 0) {
        return;
    }
    execute_cmd(cmd);
}

void remove_dir(const char *dir_path)
{
    char cmd[MAX_CMD_LEN];
    (void)memset_s(cmd, MAX_CMD_LEN, 0, MAX_CMD_LEN);
    int ret = sprintf_s(cmd, MAX_CMD_LEN, "rm -rf %s", dir_path);
    if (ret < 0) {
        return;
    }
    execute_cmd(cmd);
}

void create_file(const char *file_path)
{
    char cmd[MAX_CMD_LEN];
    (void)memset_s(cmd, MAX_CMD_LEN, 0, MAX_CMD_LEN);
    int ret = sprintf_s(cmd, MAX_CMD_LEN, "touch %s", file_path);
    if (ret < 0) {
        return;
    }
    execute_cmd(cmd);
}

void remove_file(const char *file_path)
{
    char cmd[MAX_CMD_LEN];
    (void)memset_s(cmd, MAX_CMD_LEN, 0, MAX_CMD_LEN);
    int ret = sprintf_s(cmd, MAX_CMD_LEN, "rm -f %s", file_path);
    if (ret < 0) {
        return;
    }
    execute_cmd(cmd);
}
