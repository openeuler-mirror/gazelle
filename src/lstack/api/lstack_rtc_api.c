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
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <lwip/lwipgz_posix_api.h>
#include <lwip/lwipgz_sock.h>
#include "posix/lstack_epoll.h"
#include "lstack_log.h"
#include "lstack_cfg.h"
#include "lstack_protocol_stack.h"
#include "lstack_thread_rpc.h"
#include "lstack_rtc_api.h"

int rtc_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    LSTACK_LOG(ERR, LSTACK, "rtc_poll: rtc currently does not support poll\n");
    return -1;
}

int rtc_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    LSTACK_LOG(ERR, LSTACK, "rtc_select: rtc currently does not support select\n");
    return -1;
}

int rtc_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout)
{
    return lstack_rtc_epoll_wait(epfd, events, maxevents, timeout);
}

int rtc_socket(int domain, int type, int protocol)
{
    int ret;

    if (stack_setup_app_thread() < 0) {
        exit(1);
    }
    
    /* need call stack thread init function */
    ret = lwip_socket(domain, type, protocol);
    return ret;
}

int rtc_close(int s)
{
    struct lwip_sock *sock = lwip_get_socket(s);
    if (sock != NULL && sock->wakeup != NULL && sock->wakeup->epollfd == s) {
        return lstack_epoll_close(s);
    }

    return lwip_close(s);
}

int rtc_shutdown(int fd, int how)
{
    return lwip_shutdown(fd, how);
}

int rtc_epoll_create(int flags)
{
    if (stack_setup_app_thread() < 0) {
        exit(1);
    }

    return lstack_epoll_create(flags);
}

int rtc_epoll_create1(int flags)
{
    if (stack_setup_app_thread() < 0) {
        exit(1);
    }

    return lstack_epoll_create1(flags);
}

int rtc_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return lstack_rtc_epoll_ctl(epfd, op, fd, event);
}
