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

#include <CUnit/Basic.h>
#include <stdlib.h>
#include <CUnit/Console.h>
#include <CUnit/Automated.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/un.h>
#include <string.h>
#include <securec.h>

// test header
#include "utils.h"
#include "common.h"

int check_if_socket_server_start_succeed(void)
{
    int ret;
    ret = check_if_process_exist("socket_server");
    if (ret != LIBOS_OK) {
        return LIBOS_ERR;
    }

    return LIBOS_OK;
}

int check_if_socket_client_start_succeed(void)
{
    int ret;
    ret = check_if_process_exist("socket_client");
    if (ret != LIBOS_OK) {
        return LIBOS_ERR;
    }

    return LIBOS_OK;
}

int check_if_socket_ltran_start_succeed(void)
{
    int ret;

    ret = check_if_process_exist("socket_ltran");
    if (ret != LIBOS_OK) {
        return LIBOS_ERR;
    }

    return LIBOS_OK;
}


int check_if_process_start_succeed(const char* proces_name)
{
    int ret;

    ret = check_if_process_exist(proces_name);
    if (ret != LIBOS_OK) {
        return LIBOS_ERR;
    }

    return LIBOS_OK;
}

int check_if_ltran_start_succeed(void)
{
    int ret;

    ret = check_if_process_exist("ltran");
    if (ret != LIBOS_OK) {
        return LIBOS_ERR;
    }

    ret = check_if_file_contains(LTRAN_LOG_PATH, "Runing Process forward", LTRAN_START_TMOUT_S);
    if (ret != LIBOS_OK) {
        return  LIBOS_ERR;
    }
    return LIBOS_OK;
}

int check_if_ltran_quit_succeed(void)
{
    char cmd[MAX_CMD_LEN];

    FILE *fstream = NULL;
    char *gets_ret = NULL;
    char buf[MAX_CMD_RESULT_BUF_LEN];
    (void)memset_s(buf, MAX_CMD_RESULT_BUF_LEN, 0, MAX_CMD_RESULT_BUF_LEN);
    (void)memset_s(cmd, MAX_CMD_LEN, 0, MAX_CMD_LEN);

    (void)sprintf_s(cmd, MAX_CMD_LEN, "ps aux | grep -w ltran | grep -v grep");
#ifdef LLT_DEBUG
    printf("Executing cmd: %s\n", cmd);
#endif

    fstream = popen(cmd, "r");
    if (fstream == NULL) {
        return LIBOS_ERR;
    }

    gets_ret = fgets(buf, MAX_CMD_RESULT_BUF_LEN, fstream);
    if (gets_ret == NULL) {
        pclose(fstream);
        return LIBOS_OK;
    }

    pclose(fstream);
    return LIBOS_ERR;
}


int check_if_lstack_start_succeed(const char *server_name)
{
    int ret;
    ret = check_if_process_exist(server_name);
    if (ret != LIBOS_OK) {
        return LIBOS_ERR;
    }

    // times for lstack online
    sleep(LSTACK_START_TMOUT_S);
    return LIBOS_OK;
}

void test_benchmark_flow(char *ltran_start_cmd, char *server_start_cmd, char *client_start_cmd, const char *ltran_conf,
    const char *lstack_conf)
{
    int ret;

    char ip[MAX_IP_ADDR_LEN];
    CU_ASSERT(get_test_ip(lstack_conf, 0, ip, MAX_IP_ADDR_LEN) == LIBOS_OK);
    ret = sprintf_s(ltran_start_cmd, MAX_CMD_LEN, "ltran --config-file %s > %s 2>&1 &", ltran_conf, LTRAN_LOG_PATH);
    ret |= sprintf_s(server_start_cmd, MAX_CMD_LEN, "export LSTACK_CONF_PATH=%s;"
        "GAZELLE_BIND_PROCNAME=benchmark_usr GAZELLE_BIND_THREADNAME=disp "
        "stdbuf -oL /etc/gazelle/benchmark_usr -sMode dn -pSize 0 -mSize 1024 -pdSize 2 -cFile /etc/gazelle/config.ini"
        " > %s 2>&1 &", lstack_conf, SOCKET_SERVER_LOG_PATH);
    ret |= sprintf_s(client_start_cmd, MAX_CMD_LEN, "stdbuf -oL /etc/gazelle/benchmark_ker -sMode \
        client -mSize 1024 -tNums 5 -cNums 2 -cFile /etc/gazelle/config.ini > %s 2>&1 &", SOCKET_CLIENT_LOG_PATH);
    CU_ASSERT(ret > 0);

    execute_cmd(ltran_start_cmd);
    CU_ASSERT(check_if_ltran_start_succeed() == LIBOS_OK);

    execute_cmd(server_start_cmd);
    ret = check_if_file_contains(SOCKET_SERVER_LOG_PATH, "Packet wrong rate", BENCHMARK_START_TMOUT_S);
    CU_ASSERT(ret == LIBOS_OK);

    execute_cmd(client_start_cmd);
    ret = check_if_file_contains(SOCKET_CLIENT_LOG_PATH, "Packet wrong rate", BENCHMARK_2WCONN_TMOUT_S);
    CU_ASSERT(ret == LIBOS_OK);
}

void test_preload_benchmark_flow_no_ltran(char *server_start_cmd, char *client_start_cmd, const char *lstack_conf)
{
    int ret;

    ret = sprintf_s(server_start_cmd, MAX_CMD_LEN, "export LSTACK_CONF_PATH=%s;"
        "GAZELLE_BIND_PROCNAME=benchmark_ker GAZELLE_BIND_THREADNAME=disp LD_PRELOAD=/lib64/liblstack.so "
        "stdbuf -oL /etc/gazelle/benchmark_ker -sMode dn -pSize 0 -mSize 1024 -pdSize 2 -cFile /etc/gazelle/config.ini"
        " > %s 2>&1 &", lstack_conf, SOCKET_SERVER_LOG_PATH);
    ret |= sprintf_s(client_start_cmd, MAX_CMD_LEN, "stdbuf -oL /etc/gazelle/benchmark_ker -sMode "
        "client -mSize 1024 -tNums 5 -cNums 2 -cFile /etc/gazelle/config.ini > %s 2>&1 &", SOCKET_CLIENT_LOG_PATH);
    CU_ASSERT(ret > 0);

    execute_cmd(server_start_cmd);
    ret = check_if_file_contains(SOCKET_SERVER_LOG_PATH, "Packet wrong rate", BENCHMARK_START_TMOUT_S);
    CU_ASSERT(ret == LIBOS_OK);

    execute_cmd(client_start_cmd);
    ret = check_if_file_contains(SOCKET_CLIENT_LOG_PATH, "Packet wrong rate", BENCHMARK_2WCONN_TMOUT_S);
    CU_ASSERT(ret == LIBOS_OK);
}

void test_preload_benchmark_flow(char *ltran_start_cmd, char *server_start_cmd, char *client_start_cmd,
    const char *ltran_conf, const char *lstack_conf)
{
    int ret;

    ret = sprintf_s(ltran_start_cmd, MAX_CMD_LEN, "ltran --config-file %s > %s 2>&1 &", ltran_conf, LTRAN_LOG_PATH);
    CU_ASSERT(ret > 0);

    execute_cmd(ltran_start_cmd);
    CU_ASSERT(check_if_ltran_start_succeed() == LIBOS_OK);

    test_preload_benchmark_flow_no_ltran(server_start_cmd, client_start_cmd, lstack_conf);
}

void rm_log(void)
{
    execute_cmd("rm -f /tmp/ltran.log         > /dev/null");
    execute_cmd("rm -f /tmp/lstack.log        > /dev/null");
    execute_cmd("rm -f /tmp/libnet_dfx.log    > /dev/null");
    execute_cmd("rm -f /tmp/socket_server.log > /dev/null");
    execute_cmd("rm -f /tmp/socket_client.log > /dev/null");
}

void kill_ltran(void)
{
    execute_cmd("killall -s TERM ltran > /dev/null 2>&1");
    for (;;) {
        if (check_if_ltran_quit_succeed() == LIBOS_OK) {
            break;
        }
        sleep(SLEPP_CYCLE_S);
    }
}

void kill_gazellectl(void)
{
    execute_cmd("killall -s TERM gazellectl > /dev/null 2>&1");
}

void kill_lstack(void)
{
    execute_cmd("killall -s TERM server_user1 > /dev/null 2>&1");
    execute_cmd("killall -s TERM server_user2 > /dev/null 2>&1");
    execute_cmd("killall -s TERM server_user3 > /dev/null 2>&1");
    execute_cmd("killall -s TERM client_user1 > /dev/null 2>&1");
    execute_cmd("killall -s TERM client_user2 > /dev/null 2>&1");
    execute_cmd("killall -s TERM client_user3 > /dev/null 2>&1");
    execute_cmd("killall -s TERM server_poll_user1 > /dev/null 2>&1");
    execute_cmd("killall -s TERM server > /dev/null 2>&1");
    execute_cmd("killall -s TERM client > /dev/null 2>&1");
    execute_cmd("killall -s TERM benchmark_ker > /dev/null 2>&1");
    execute_cmd("killall -s TERM benchmark_usr > /dev/null 2>&1");
}

void reset_env(void)
{
    kill_ltran();
    kill_gazellectl();
    kill_lstack();
    rm_log();
}
