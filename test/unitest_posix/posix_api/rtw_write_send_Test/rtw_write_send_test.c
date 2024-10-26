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

void test_write_success(void)
{
    char write_data[BUFFER_SIZE] = HELLO_STR;

    /* TCP rtw_write_send test --------------------------------------------- */
    int socket_fd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(socket_fd, -1);
    int result = rtw_write(socket_fd, write_data, strlen(HELLO_STR));
    LOG_ASSERT(result == strlen(HELLO_STR), "Write tcp result should be %d",
               strlen(HELLO_STR));

    result = rtw_send(socket_fd, write_data, strlen(HELLO_STR), 1);
    LOG_ASSERT(result == strlen(HELLO_STR), "Send tcp result should be %d",
               strlen(HELLO_STR));
    if (socket_fd != -1) {
        rtw_close(socket_fd);
    }

    /* UDP rtw_write_send test --------------------------------------------- */
    socket_fd = rtw_socket(AF_INET, SOCK_DGRAM, 0);
    CU_ASSERT_NOT_EQUAL(socket_fd, -1);
    result = rtw_write(socket_fd, write_data, strlen(HELLO_STR));
    LOG_ASSERT(result == strlen(HELLO_STR), "Write udp result should be %d",
               strlen(HELLO_STR));

    result = rtw_send(socket_fd, write_data, strlen(HELLO_STR), 1);
    LOG_ASSERT(result == strlen(HELLO_STR), "Send udp result should be %d",
               strlen(HELLO_STR));
    if (socket_fd != -1) {
        rtw_close(socket_fd);
    }

    /* rtw_writev test --------------------------------------------- */
    socket_fd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(socket_fd, -1);
    struct iovec iov;
    iov.iov_base = write_data;
    iov.iov_len = LEN_HANDLE;
    result = rtw_writev(socket_fd, &iov, 1);
    LOG_ASSERT(result == LEN_HANDLE, "Writev result should be %d", LEN_HANDLE);
    if (socket_fd != -1) {
        rtw_close(socket_fd);
    }
}

void test_send_success(void)
{
    char write_data[BUFFER_SIZE] = HELLO_STR;
    /* send_msg test --------------------------------------------- */
    int socket_fd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(socket_fd, -1);
    struct iovec iov;
    iov.iov_base = write_data;
    iov.iov_len = LEN_HANDLE;

    struct msghdr msg;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = LWIP_CONST_CAST(struct iovec*, &iov);
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    int result = rtw_sendmsg(socket_fd, &msg, 1);
    LOG_ASSERT(result == LEN_HANDLE, "Sendmsg result should be %d", LEN_HANDLE);
    if (socket_fd != -1) {
        rtw_close(socket_fd);
    }

    /* sendto test --------------------------------------------- */
    socket_fd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(socket_fd, -1);

    struct sockaddr_in address;
    struct sockaddr* addr;
    socklen_t addrlen = sizeof(address);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    address.sin_port = htons(SERVER_PORT);
    addr = (struct sockaddr*)&address;

    result =
        rtw_sendto(socket_fd, write_data, strlen(HELLO_STR), 1, addr, addrlen);
    LOG_ASSERT(result == strlen(HELLO_STR), "Sendto result should be %d",
               strlen(HELLO_STR));
    if (socket_fd != -1) {
        rtw_close(socket_fd);
    }
}

void test_write_send_failure(void)
{
    char write_data[BUFFER_SIZE] = HELLO_STR;
    int socket_fd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(socket_fd, -1);
    /* do_lwip_send_to_stack should check the returned sock internally! */
    // int result = rtw_write(socket_fd, write_data, strlen(HELLO_STR));

    int result = rtw_write(socket_fd, NULL, strlen(HELLO_STR));
    LOG_ASSERT(result == -1, "Write failure for bad write_data pointer");
    /* rtw_writev should check the returned sock internally! */
    // result = rtw_writev(socket_fd, NULL, 1);

    struct iovec iov;
    iov.iov_base = NULL;
    iov.iov_len = LEN_HANDLE;
    result = rtw_writev(socket_fd, &iov, 1);
    LOG_ASSERT(result == -1, "Writev failure for write_data pointer");

    result = rtw_sendmsg(socket_fd, NULL, 1);
    LOG_ASSERT(result == -1, "Sendmsg failure for bad message pointer");

    result = rtw_sendto(socket_fd, NULL, 0, 0, NULL, 0);
    LOG_ASSERT(result == -1, "Sendto failure for bad write_data pointer");
}
