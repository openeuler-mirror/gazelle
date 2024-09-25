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

void create_nonblocking_pipe(int pipefd[2])
{
    if (pipe(pipefd) == -1) {
        perror("pipe");
        CU_FAIL("Failed to create pipe");
    }

    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
}

void test_epoll_readable()
{
    int epoll_fd = rtw_epoll_create1(0);
    CU_ASSERT(epoll_fd != -1);

    int pipefd[2];
    CU_ASSERT(pipe(pipefd) == 0);

    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = pipefd[0];

    CU_ASSERT(rtw_epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pipefd[0], &event) == 0);

    write(pipefd[1], HELLO_STR, strlen(HELLO_STR));

    struct epoll_event events[1];
    int nfds = rtw_epoll_wait(epoll_fd, events, 1, TIMEOUT_POLL);
    LOG_ASSERT(nfds == 1, "epoll result is 1 for there's data to read");
    CU_ASSERT(events[0].data.fd == pipefd[0]);
    CU_ASSERT(events[0].events & EPOLLIN);

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1);
    CU_ASSERT(bytes_read > 0);
    buffer[bytes_read] = '\0';
    CU_ASSERT_STRING_EQUAL(buffer, HELLO_STR);

    close(pipefd[0]);
    close(pipefd[1]);
    rtw_close(epoll_fd);
}

void test_epoll_writeable()
{
    int epoll_fd = rtw_epoll_create1(0);
    CU_ASSERT(epoll_fd != -1);

    int pipefd[2];
    CU_ASSERT(pipe(pipefd) == 0);

    struct epoll_event event;
    event.events = EPOLLOUT;
    event.data.fd = pipefd[1];

    CU_ASSERT(rtw_epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pipefd[1], &event) == 0);

    struct epoll_event events[1];
    int nfds = rtw_epoll_wait(epoll_fd, events, 1, TIMEOUT_POLL);
    LOG_ASSERT(nfds == 1, "epoll result should be 1 for the pipe's write-end is writable");
    CU_ASSERT(events[0].data.fd == pipefd[1]);
    CU_ASSERT(events[0].events & EPOLLOUT);

    close(pipefd[0]);
    close(pipefd[1]);
    rtw_close(epoll_fd);
}

void test_epoll_create1_invalid_flags()
{
    int epoll_fd = epoll_create1(-1);
    LOG_ASSERT(epoll_fd == -1, "epoll_create1 failure for invalid_flags");
    CU_ASSERT_EQUAL(errno, EINVAL);
}

void test_epoll_wait_invalid_fd()
{
    struct epoll_event events[MAX_EVENTS];
    int result = epoll_wait(-1, events, MAX_EVENTS, TIMEOUT_POLL);
    LOG_ASSERT(result == -1, "epoll_wait failure for invalid_fd");
    CU_ASSERT_EQUAL(errno, EBADF);
}

void test_epoll_ctl_invalid_fd()
{
    int epoll_fd = epoll_create1(0);
    CU_ASSERT(epoll_fd != -1);

    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = -1;

    int result = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, -1, &event);
    LOG_ASSERT(result == -1, "epoll_ctl failure for invalid_fd");
    rtw_close(epoll_fd);
}

void test_epoll_success(void)
{
    test_epoll_readable();
    test_epoll_writeable();
}

void test_epoll_failure(void)
{
    test_epoll_create1_invalid_flags();
    test_epoll_wait_invalid_fd();
    test_epoll_ctl_invalid_fd();
}
