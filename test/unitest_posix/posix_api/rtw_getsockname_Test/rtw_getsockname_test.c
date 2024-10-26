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

void test_getsockname_success(void)
{
    int sockfd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(sockfd, -1);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(SERVER_PORT);

    // 将 socket 绑定到一个地址
    int result = rtw_bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    CU_ASSERT_EQUAL(result, 0);

    struct sockaddr_in get_addr;
    socklen_t addr_len = sizeof(get_addr);
    result = rtw_getsockname(sockfd, (struct sockaddr*)&get_addr, &addr_len);

    LOG_ASSERT(result == 0, "Getsockname result should be 0");
    LOG_ASSERT(get_addr.sin_family == AF_INET,
               "Getsockname sin_family should be AF_INET");
    LOG_ASSERT(get_addr.sin_port == htons(SERVER_PORT),
               "Getsockname sin_port should be %d", SERVER_PORT);
    LOG_ASSERT(get_addr.sin_addr.s_addr == htonl(INADDR_ANY),
               "Getsockname s_addr should be %s",
               inet_ntoa((struct in_addr){INADDR_ANY}));

    if (sockfd != -1) {
        rtw_close(sockfd);
    }
}

void test_getsockname_failure(void)
{
    int sockfd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(sockfd, -1);

    struct sockaddr_in get_addr;
    socklen_t addr_len = sizeof(get_addr);

    // 关闭套接字后再调用 getsockname
    rtw_close(sockfd);
    int result =
        rtw_getsockname(sockfd, (struct sockaddr*)&get_addr, &addr_len);
    LOG_ASSERT(result == -1, "Getsockname failure for bad file descriptor");
    CU_ASSERT_EQUAL(errno, EBADF);  // 错误的文件描述符
}
