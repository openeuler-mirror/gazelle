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

void test_socket_success(void)
{
    int rtw_sockfd, rtc_sockfd;
    int families[] = {AF_INET, AF_INET6, AF_UNIX};
    int types[] = {SOCK_STREAM, SOCK_DGRAM};
    const char* family_names[] = {"AF_INET", "AF_INET6", "AF_UNIX"};
    const char* type_names[] = {"SOCK_STREAM", "SOCK_DGRAM"};

    for (int i = 0; i < sizeof(families) / sizeof(families[0]); i++) {
        for (int j = 0; j < sizeof(types) / sizeof(types[0]); j++) {
            rtw_sockfd = rtw_socket(families[i], types[j], 0);
            rtc_sockfd = rtc_socket(families[i], types[j], 0);
            LOG_ASSERT(rtw_sockfd >= 0, "Socket_rtw creation for %s with %s",
                       family_names[i], type_names[j]);
            LOG_ASSERT(rtc_sockfd >= 0, "Socket_rtc creation for %s with %s",
                       family_names[i], type_names[j]);
            if (rtw_sockfd != -1) {
                rtw_close(rtw_sockfd);
            }
            if (rtc_sockfd != -1) {
                rtc_close(rtc_sockfd);
            }
        }
    }
}

void test_socket_failure(void)
{
    int rtw_sockfd, rtc_sockfd;

    rtw_sockfd = rtw_socket(AF_INET, -1, 0);
    LOG_ASSERT(rtw_sockfd == -1, "Socket_rtw creation failure for AF_INET with -1");
    if (rtw_sockfd != -1) {
        rtw_close(rtw_sockfd);
    }

    rtc_sockfd = rtc_socket(AF_INET, -1, 0);
    LOG_ASSERT(rtc_sockfd == -1, "Socket_rtc creation failure for AF_INET with -1");
    if (rtc_sockfd != -1) {
        rtc_close(rtc_sockfd);
    }

    // 使用SOCK_RAW时需要指定具体的协议 不可以为0
    rtw_sockfd = rtw_socket(AF_INET, SOCK_RAW, 0);
    LOG_ASSERT(rtw_sockfd == -1,
               "Socket_rtw creation failure for AF_INET with SOCK_RAW");
    if (rtw_sockfd != -1) {
        rtw_close(rtw_sockfd);
    }

    rtc_sockfd = rtc_socket(AF_INET, SOCK_RAW, 0);
    LOG_ASSERT(rtc_sockfd == -1,
               "Socket_rtc creation failure for AF_INET with SOCK_RAW");
    if (rtc_sockfd != -1) {
        rtc_close(rtc_sockfd);
    }
}

void test_close_success_failure(void)
{
    int rtw_sockfd, rtc_sockfd, result;

    rtw_sockfd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(rtw_sockfd, -1);
    if (rtw_sockfd != -1) {
        result = rtw_close(rtw_sockfd);
        LOG_ASSERT(result == 0, "Close result should be 0");
    }

    result = rtw_close(-1);
    LOG_ASSERT(result == -1, "Close failure for bad file descriptor");

    rtc_sockfd = rtc_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(rtc_sockfd, -1);
    if (rtc_sockfd != -1) {
        result = rtc_close(rtc_sockfd);
        LOG_ASSERT(result == 0, "Close_rtc result should be 0");
    }

    result = rtc_close(-1);
    LOG_ASSERT(result == -1, "Close_rtc failure for bad file descriptor");
}

void test_shutdown_success_failure(void)
{
    int how[] = {SHUT_RD, SHUT_RDWR};
    const char *type_names[] = {"SHUT_RD", "SHUT_RDWR"};
    int rtw_sockfd, rtc_sockfd, result;
    rtw_sockfd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(rtw_sockfd, -1);

    rtc_sockfd = rtc_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(rtc_sockfd, -1);

    for (int i = 0; i < sizeof(how) / sizeof(how[0]); i++) {
        result = rtw_shutdown(rtw_sockfd, how[i]);
        LOG_ASSERT(result == 0, "Shutdown_rtw for %s ,result should be 0", type_names[i]);

        result = rtc_shutdown(rtc_sockfd, how[i]);
        LOG_ASSERT(result == 0, "Shutdown_rtc for %s ,result should be 0", type_names[i]);
    }
    /* shutdown for SHUT_WR */
    result = rtw_shutdown(rtw_sockfd, SHUT_WR);
    LOG_ASSERT(result == -1, "Shutdown_rtw for SHUT_WR ,result should be -1");

    result = rtc_shutdown(rtc_sockfd, SHUT_WR);
    LOG_ASSERT(result == -1, "Shutdown_rtc for SHUT_WR ,result should be -1");

    /* shutdown for bad descriptor */
    result = rtw_shutdown(-1, SHUT_RD);
    LOG_ASSERT(result == -1, "Shutdown_rtw failure for bad file descriptor");

    result = rtc_shutdown(-1, SHUT_RD);
    LOG_ASSERT(result == -1, "Shutdown_rtc failure for bad file descriptor");

    rtw_close(rtw_sockfd);
    rtc_close(rtc_sockfd);
}