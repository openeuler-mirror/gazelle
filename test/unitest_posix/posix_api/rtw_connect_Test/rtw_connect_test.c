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

int lwip_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
    if (addr == NULL || addrlen == 0 || addrlen < sizeof(struct sockaddr_in)) {
        errno = EINVAL;
        return -1;
    }
    struct sockaddr_in* custom_addr = (struct sockaddr_in*)addr;
    LOG_ASSERT(custom_addr->sin_family == AF_INET,
               "Connect sin_family should be AF_INET");
    LOG_ASSERT(custom_addr->sin_addr.s_addr == inet_addr(SERVER_ADDR),
               "Connect s_addr should be %s",
               inet_ntoa((struct in_addr){custom_addr->sin_addr.s_addr}));
    LOG_ASSERT(custom_addr->sin_port == htons(SERVER_PORT),
               "Connect sin_port should be %d", SERVER_PORT);

    //  return -1;// 失败
    return 0;  // 成功
}
void test_connect_success(void)
{
    int sockfd = rtw_socket(AF_INET, SOCK_DGRAM, 0);
    CU_ASSERT_NOT_EQUAL(sockfd, -1);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    server_addr.sin_port = htons(SERVER_PORT);

    int result = rtw_connect(sockfd, (struct sockaddr*)&server_addr,
                             sizeof(server_addr));
    LOG_ASSERT(result == 0, "Connect result should be 0");
    if (sockfd != -1) {
        close(sockfd);
    }
}
void test_connect_failure(void)
{
    int sockfd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(sockfd, -1);

    struct sockaddr_in peer_addr;
    int result = rtw_connect(sockfd, NULL, sizeof(peer_addr));
    LOG_ASSERT(result == -1, "Connect failure for addr NULL");
}