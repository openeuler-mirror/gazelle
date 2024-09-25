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

#include "test_frame.h"

int lwip_getpeername(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
    if (addr == NULL || addrlen == NULL ||
        *addrlen < sizeof(struct sockaddr_in)) {
        errno = EINVAL;
        return -1;
    }

    struct sockaddr_in* custom_addr = (struct sockaddr_in*)addr;
    custom_addr->sin_family = AF_INET;
    custom_addr->sin_port = htons(SERVER_PORT);               // 自定义端口
    inet_pton(AF_INET, SERVER_ADDR, &custom_addr->sin_addr);  // 自定义 IP 地址

    *addrlen = sizeof(struct sockaddr_in);
    return 0;
}

void test_getpeername_success(void)
{
    int sockfd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(sockfd, -1);

    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);
    char ip_str[INET_ADDRSTRLEN];

    int result =
        rtw_getpeername(sockfd, (struct sockaddr*)&peer_addr, &peer_addr_len);
    LOG_ASSERT(result == 0, "Getpeername result should be 0");
    LOG_ASSERT(peer_addr.sin_family == AF_INET,
               "Getpeername sin_family should be AF_INET");
    LOG_ASSERT(peer_addr.sin_addr.s_addr == inet_addr(SERVER_ADDR),
               "Getpeername s_addr should be %s",
               inet_ntoa((struct in_addr){peer_addr.sin_addr.s_addr}));
    LOG_ASSERT(peer_addr.sin_port == htons(SERVER_PORT),
               "Getpeername sin_port should be %d", SERVER_PORT);
    if (sockfd != -1) {
        close(sockfd);
    }
}

void test_getpeername_failure(void)
{
    int sockfd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(sockfd, -1);

    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);
    int result = rtw_getpeername(sockfd, NULL, &peer_addr_len);
    LOG_ASSERT(result == -1, "Getpeername failure for addr NULL");
}