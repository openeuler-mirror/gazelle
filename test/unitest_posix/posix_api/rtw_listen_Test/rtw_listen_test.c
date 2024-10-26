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
#include "lstack_cfg.h"

void test_single_listen_success(void)
{
    int sockfd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(sockfd, -1);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(SERVER_PORT);

    int result = rtw_bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    CU_ASSERT_EQUAL(result, 0);

    result = rtw_listen(sockfd, BACKLOG);
    LOG_ASSERT(result == 0, "Single listen socket Server Port: %d, ADDR: %s",
               SERVER_PORT, inet_ntoa((struct in_addr){INADDR_ANY}));

    if (sockfd != -1) {
        rtw_close(sockfd);
    }
}

void test_broadcast_listen_success(void)
{
    int listen_shadow = get_global_cfg_params()->listen_shadow;
    get_global_cfg_params()->listen_shadow = 1;
    int sockfd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(sockfd, -1);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(SERVER_PORT);

    int result = rtw_bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    CU_ASSERT_EQUAL(result, 0);

    result = rtw_listen(sockfd, BACKLOG);
    LOG_ASSERT(result == 0, "Broadcast listen socket Server Port: %d, ADDR: %s",
               SERVER_PORT, inet_ntoa((struct in_addr){INADDR_ANY}));

    if (sockfd != -1) {
        rtw_close(sockfd);
    }
    get_global_cfg_params()->listen_shadow = listen_shadow;
}

void test_listen_failure(void)
{
    int sockfd = rtw_socket(AF_INET, SOCK_DGRAM, 0);
    CU_ASSERT_NOT_EQUAL(sockfd, -1);

    // 不支持UDP listen，应该失败
    int result = rtw_listen(sockfd, BACKLOG);
    LOG_ASSERT(result == -1, "Listen failure for SOCK_DGRAM");

    // 关闭套接字后再调用 listen，应该失败
    rtw_close(sockfd);
    result = rtw_listen(sockfd, BACKLOG);
    LOG_ASSERT(result == -1, "Listen failure for bad file descriptor");
    CU_ASSERT_EQUAL(errno, EBADF);
}