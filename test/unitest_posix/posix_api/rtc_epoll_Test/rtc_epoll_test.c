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

void test_asynchronous_rtc(void)
{
    /* test_epoll_writeable */
    int epoll_fd = rtc_epoll_create1(0);
    CU_ASSERT(epoll_fd != -1);
    int pipefd[2];
    CU_ASSERT(pipe(pipefd) == 0);

    struct epoll_event event;
    event.events = EPOLLOUT;
    event.data.fd = pipefd[1];

    CU_ASSERT(rtc_epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pipefd[1], &event) == 0);

    struct epoll_event events[1];
    int nfds = rtc_epoll_wait(epoll_fd, events, 1, TIMEOUT_POLL);
    LOG_ASSERT(nfds == 1, "rtc_epoll result should be 1 for the pipe's write-end is writable");
    CU_ASSERT(events[0].data.fd == pipefd[1]);
    CU_ASSERT(events[0].events & EPOLLOUT);

    close(pipefd[0]);
    close(pipefd[1]);
    close(epoll_fd);

    /* select and poll */

    int result = rtc_poll(NULL, 0, 0);
    CU_ASSERT(result == -1);

    result = rtc_select(0, NULL, NULL, NULL, NULL);
    CU_ASSERT(result == -1);
}
