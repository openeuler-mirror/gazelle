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

#ifndef __COMMON_H__
#define __COMMON_H__

#define LTRAN_START_TMOUT_S    5
#define LSTACK_START_TMOUT_S   2
#define LANTENCY_LOG_TMOUT_S   5
#define CAT_LOG_TMOUT_S        5
#define LSTACK_LOGOUT_TMOUT_S  10
#define BENCHMARK_START_TMOUT_S  10
#define BENCHMARK_2WCONN_TMOUT_S 20

#define MAX_BOND_PORT_NUM 8
#define MAX_BOND_MAC_NUM  8

#define MAX_PORT_MASK_LEN 64
#define MAX_MAC_LEN 64
#define MAX_IP_ADDR_LEN 64
#define MAX_FILE_PATH_LEN 128

#define LTRAN_LOG_PATH      "/tmp/ltran.log "
#define LSTACK_LOG_PATH     "/tmp/lstack.log"
#define LIBNET_DFX_LOG_PATH "/tmp/libnet_dfx.log"
#define CP_SOCK_FILE "cp.sock"

#define SOCKET_SERVER_LOG_PATH "/tmp/socket_server.log"
#define SOCKET_CLIENT_LOG_PATH "/tmp/socket_client.log"

#define STUB_LSTACK_LIVE_TIME_S 3

#define SERVERBIN_IP_OFFSET    1
#define KNI_IP_OFFSET          2

void test_benchmark_flow(char *ltran_start_cmd, char *server_start_cmd, char *client_start_cmd, const char *ltran_conf,
    const char *lstack_conf);
void test_preload_benchmark_flow_no_ltran(char *server_start_cmd, char *client_start_cmd, const char *lstack_conf);
void test_preload_benchmark_flow(char *ltran_start_cmd, char *server_start_cmd, char *client_start_cmd,
    const char *ltran_conf, const char *lstack_conf);
int check_if_process_start_succeed(const char* proces_name);
int check_if_socket_server_start_succeed(void);
int check_if_socket_client_start_succeed(void);
int check_if_socket_ltran_start_succeed(void);
int check_if_ltran_start_succeed(void);
int check_if_lstack_start_succeed(const char *ip_addr);


void rm_log(void);
void kill_ltran(void);
void ko_clean(void);
void ko_init(void);

void kill_stub_lstack(void);

void reset_env(void);


#endif
