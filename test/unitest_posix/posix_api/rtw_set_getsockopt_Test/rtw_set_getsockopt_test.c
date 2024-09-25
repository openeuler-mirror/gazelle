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

#include <netinet/tcp.h>
#include "test_frame.h"

struct sock_option {
    int level;
    int option;
    int value;
    const char* name;
} options[] = {
    {SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR"},
    {SOL_SOCKET, SO_KEEPALIVE, 1, "SO_KEEPALIVE"},
    {SOL_SOCKET, SO_RCVBUF, 4096, "SO_RCVBUF"},
    {SOL_SOCKET, SO_SNDBUF, 4096, "SO_SNDBUF"},
    {SOL_SOCKET, SO_OOBINLINE, 1, "SO_OOBINLINE"},
    {SOL_SOCKET, SO_RCVLOWAT, 1, "SO_RCVLOWAT"},
    {IPPROTO_IP, IP_TOS, 1, "IP_TOS"},
    {IPPROTO_IP, IP_TTL, 1, "IP_TTL"},
    {IPPROTO_TCP, TCP_MAXSEG, 536, "TCP_MAXSEG"},
    {IPPROTO_TCP, TCP_NODELAY, 1, "TCP_NODELAY"},
};

void test_set_getsockopt_success(void)
{
    int num_options, socket_fd, result, optval;

    num_options = sizeof(options) / sizeof(options[0]);

    for (int i = 0; i < num_options; i++) {
        socket_fd = rtw_socket(AF_INET, SOCK_STREAM, 0);
        CU_ASSERT_NOT_EQUAL(socket_fd, -1);
        optval = options[i].value;
        socklen_t optlen = sizeof(optval);

        result = rtw_setsockopt(socket_fd, options[i].level, options[i].option,
                                &optval, optlen);
        LOG_ASSERT(result == 0, "Setsockopt with option %s", options[i].name);

        optval = 0; // Reset optval to verify it gets set correctly
        result = rtw_getsockopt(socket_fd, options[i].level, options[i].option,
                                &optval, &optlen);
        LOG_ASSERT(result == 0 && optval == options[i].value,
                   "Getsockopt with opeiton %s", options[i].name);
    }
    if (socket_fd != -1) {
        rtw_close(socket_fd);
    }
}

void test_set_getsockopt_failure(void)
{
    int socket_fd = -1;  // 错误的套接字描述符
    int ip_ttl = 64;
    int retrieved_ip_ttl;
    socklen_t option_len = sizeof(ip_ttl);

    // 设置选项
    int result =
        rtw_setsockopt(socket_fd, IPPROTO_IP, IP_TTL, &ip_ttl, sizeof(ip_ttl));
    LOG_ASSERT(result == -1, "Setsockopt failure for bad file descriptor");
    CU_ASSERT_EQUAL(errno, EBADF);

    // 获取选项
    result = rtw_getsockopt(socket_fd, IPPROTO_IP, IP_TTL, &retrieved_ip_ttl,
                            &option_len);
    LOG_ASSERT(result == -1, "Getsockopt failure for bad file descriptor");
}