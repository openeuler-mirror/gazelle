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

#ifndef _TEST_FRAME_H_
#define _TEST_FRAME_H_

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <arpa/inet.h>
#include <cmocka.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lstack_rtc_api.h"
#include "lstack_rtw_api.h"
#include "lwip/lwipgz_sock.h"

#define DIRECTORY_PERMISSIONS 0700
#define LOG_FILE "../log/socket_test.log"  // 日志文件的路径
#define SERVER_PORT 8080                   // 服务器端口
#define SERVER_ADDR "10.64.38.165"         // 服务器地址
#define BACKLOG 10                         // listen的最大监听队列长度
#define BUFFER_SIZE 1024                   // buffer的大小
#define HELLO_STR "hello_world!"  // read相关函数，打桩返回的字符
#define READ_STR "hello"          // 用于读取部分的HELLO_STR
#define LEN_HANDLE 5              // 字符串hello长度
#define CONN_FD 66                // 用于测试accept的socket_fd
#define IOVLEN 1
#define TIMEOUT_POLL 1000
#define TIMEOUT_SELECT 1000
#define MAX_EVENTS 5

#define LOG_ASSERT(cond, message, ...)                         \
    do {                                                       \
        if (cond) {                                            \
            log_message("PASS: " message "\n", ##__VA_ARGS__); \
        } else {                                               \
            log_message("FAIL: " message "\n", ##__VA_ARGS__); \
        }                                                      \
        CU_ASSERT(cond);                                       \
    } while (0)
void log_message(const char* format, ...);

// 声明子目录中的测试函数
void test_socket_success(void);
void test_socket_failure(void);
void test_close_success_failure(void);
void test_shutdown_success_failure(void);
void test_broadcast_bind_success(void);
void test_single_bind_success(void);
void test_bind_failure(void);
void test_getsockname_success(void);
void test_getsockname_failure(void);
void test_broadcast_listen_success(void);
void test_single_listen_success(void);
void test_listen_failure(void);
void test_set_getsockopt_success(void);
void test_set_getsockopt_failure(void);
void test_getpeername_success(void);
void test_getpeername_failure(void);
void test_connect_success(void);
void test_connect_failure(void);
void test_read_success(void);
void test_rec_success(void);
void test_read_recv_failure(void);
void test_accept_success(void);
void test_accept_failure(void);
void test_write_success(void);
void test_send_success(void);
void test_write_send_failure(void);
void test_select_failure(void);
void test_select_success(void);
void test_poll_success(void);
void test_poll_failure(void);
void test_epoll_success(void);
void test_epoll_failure(void);
void test_asynchronous_rtc(void);

#endif /* _TEST_FRAME_H_ */