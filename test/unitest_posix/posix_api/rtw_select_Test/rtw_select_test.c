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

#include <fcntl.h>
#include "test_frame.h"

void set_non_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return;
    }
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void test_select_readable_fd()
{
    int pipefd[2];
    char buffer[BUFFER_SIZE];
    pipe(pipefd);

    set_non_blocking(pipefd[1]);

    fd_set read_fds;
    struct timeval timeout;
    int result;

    FD_ZERO(&read_fds);
    FD_SET(pipefd[0], &read_fds);

    /* Write something to the pipe */
    write(pipefd[1], HELLO_STR, strlen(HELLO_STR));

    timeout.tv_sec = TIMEOUT_SELECT;
    timeout.tv_usec = 0;

    result = rtw_select(pipefd[0] + 1, &read_fds, NULL, NULL, &timeout);
    LOG_ASSERT(result == 1,
               "Select result should be 1 for there's data to read; If it fails, "
               "check whether the large page memory is 1024.");
    CU_ASSERT_TRUE(FD_ISSET(pipefd[0], &read_fds));

    ssize_t bytes_read = read(pipefd[0], buffer, strlen(HELLO_STR));
    // buffer[bytes_read]='\0';
    CU_ASSERT_EQUAL(bytes_read, strlen(HELLO_STR));

    close(pipefd[0]);
    close(pipefd[1]);
}

void test_select_writable_fd()
{
    int pipefd[2];
    pipe(pipefd);

    fd_set write_fds;
    struct timeval timeout;
    int result;

    FD_ZERO(&write_fds);
    FD_SET(pipefd[1], &write_fds);

    timeout.tv_sec = TIMEOUT_SELECT;
    timeout.tv_usec = 0;

    result = rtw_select(pipefd[1] + 1, NULL, &write_fds, NULL, &timeout);
    LOG_ASSERT(
        result == 1,
        "Select result should be 1 for the pipe's write-end is writable; If it fails, "
        "check whether the large page memory is 1024.");
    CU_ASSERT_TRUE(FD_ISSET(pipefd[1], &write_fds));

    close(pipefd[0]);
    close(pipefd[1]);
}

void test_select_exception_fd()
{
    int pipefd[2];
    pipe(pipefd);

    fd_set except_fds;
    struct timeval timeout;
    int result;

    close(pipefd[0]);

    FD_ZERO(&except_fds);
    FD_SET(pipefd[1], &except_fds);

    timeout.tv_sec = TIMEOUT_SELECT;
    timeout.tv_usec = 0;

    /* This should result in an exception on the write-end */
    write(pipefd[1], HELLO_STR, strlen(HELLO_STR));

    result = rtw_select(pipefd[1] + 1, NULL, NULL, &except_fds, &timeout);
    LOG_ASSERT(result == 1,
               "Select result should be 1 for an exception occur; If it fails, "
               "check whether the large page memory is 1024.");
    CU_ASSERT_TRUE(FD_ISSET(pipefd[1], &except_fds));

    close(pipefd[1]);
}

void test_select_timeout()
{
    fd_set read_fds;
    struct timeval timeout;
    int result;

    FD_ZERO(&read_fds);

    /* We are not setting any file descriptors here */
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    result = rtw_select(0, &read_fds, NULL, NULL, &timeout);
    LOG_ASSERT(result == -1, "select failure for timeout");
}

void test_select_invalid_fd()
{
    fd_set read_fds;
    struct timeval timeout;
    int result;
    /* Invalid file descriptor */
    int invalid_fd = -2;

    FD_ZERO(&read_fds);
    FD_SET(invalid_fd, &read_fds);

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    result = rtw_select(invalid_fd + 1, &read_fds, NULL, NULL, &timeout);
    LOG_ASSERT(result == -1, "select failure for bad file descriptor");
}

void test_select_empty_fdset()
{
    fd_set read_fds;
    struct timeval timeout;
    int result;

    FD_ZERO(&read_fds);

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    result = rtw_select(0, &read_fds, NULL, NULL, &timeout);
    LOG_ASSERT(result == -1,
               "select failure for no file descriptors to monitor");
}

void test_select_success(void)
{
    test_select_readable_fd();
    test_select_writable_fd();
    test_select_exception_fd();
}

void test_select_failure(void)
{
    test_select_empty_fdset();
    test_select_invalid_fd();
    test_select_timeout();
}