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

void test_poll_readable_fd()
{
    int pipefd[2];
    char buffer[BUFFER_SIZE];
    struct pollfd fds[1];
    int result;

    pipe(pipefd);

    write(pipefd[1], HELLO_STR, strlen(HELLO_STR));
    fds[0].fd = pipefd[0];
    fds[0].events = POLLIN;

    result = rtw_poll(fds, 1, TIMEOUT_POLL);
    LOG_ASSERT(result == 1, "poll result is 1 for there's data to read");
    CU_ASSERT(fds[0].revents & POLLIN);

    ssize_t bytes_read = read(pipefd[0], buffer, sizeof(buffer));
    buffer[bytes_read] = '\0';
    CU_ASSERT_STRING_EQUAL(buffer, HELLO_STR);

    close(pipefd[0]);
    close(pipefd[1]);
}

void test_poll_writable_fd()
{
    int pipefd[2];
    struct pollfd fds[1];
    int result;

    pipe(pipefd);
    fcntl(pipefd[1], F_SETFL, O_NONBLOCK);
    fds[0].fd = pipefd[1];
    fds[0].events = POLLOUT;

    result = rtw_poll(fds, 1, TIMEOUT_POLL);
    LOG_ASSERT(result == 1,
               "poll result should be 1 for the pipe's write-end is writable");
    CU_ASSERT(fds[0].revents & POLLOUT);

    close(pipefd[0]);
    close(pipefd[1]);
}

void test_poll_exception_fd()
{
    int pipefd[2];
    struct pollfd fds[1];
    int result;

    pipe(pipefd);
    /* Turn off the reading end, create an exception */
    close(pipefd[0]);
    fds[0].fd = pipefd[1];
    fds[0].events = POLLOUT;

    /* This should result in an exception on the write-end */
    result = write(pipefd[1], HELLO_STR, strlen(HELLO_STR));
    CU_ASSERT_EQUAL(result, -1);

    result = rtw_poll(fds, 1, TIMEOUT_POLL);
    LOG_ASSERT(result == 1, "poll result should be 1 for an exception occur");
    CU_ASSERT(fds[0].revents & POLLERR);

    close(pipefd[1]);
}

void test_poll_timeout()
{
    struct pollfd fds[1];
    int result;

    fds[0].fd = -1;
    fds[0].events = POLLIN;

    result = rtw_poll(fds, 1, TIMEOUT_POLL);
    LOG_ASSERT(result == 0,
               "poll failure for bad file descriptor and time_out");
}

void test_poll_success(void)
{
    test_poll_readable_fd();
    test_poll_writable_fd();
    test_poll_exception_fd();
}

void test_poll_failure(void)
{
    test_poll_timeout();
}
