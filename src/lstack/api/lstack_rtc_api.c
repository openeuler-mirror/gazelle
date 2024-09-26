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

#include <lwip/lwipgz_sock.h>
#include <lwip/sockets.h>

#include "lstack_epoll.h"
#include "lstack_log.h"
#include "lstack_cfg.h"
#include "lstack_protocol_stack.h"
#include "lstack_rtc_api.h"

static int rtc_socket(int domain, int type, int protocol)
{
    int ret;

    if (stack_setup_app_thread() < 0) {
        exit(1);
    }
    
    /* need call stack thread init function */
    ret = lwip_socket(domain, type, protocol);
    return ret;
}

static int rtc_close(int s)
{
    struct lwip_sock *sock = lwip_get_socket(s);
    if (sock != NULL && sock->wakeup != NULL && sock->wakeup->epollfd == s) {
        return lstack_epoll_close(s);
    }

    return lwip_close(s);
}

static int rtc_epoll_create(int flags)
{
    if (stack_setup_app_thread() < 0) {
        exit(1);
    }

    return lstack_epoll_create(flags);
}

static int rtc_epoll_create1(int flags)
{
    if (stack_setup_app_thread() < 0) {
        exit(1);
    }

    return lstack_epoll_create1(flags);
}

static int rtc_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return lstack_rtc_epoll_ctl(epfd, op, fd, event);
}

static int rtc_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout)
{
    return lstack_rtc_epoll_wait(epfd, events, maxevents, timeout);
}

static int rtc_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    LSTACK_LOG(ERR, LSTACK, "rtc_poll: rtc currently does not support poll\n");
    return -1;
}

static int rtc_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    LSTACK_LOG(ERR, LSTACK, "rtc_select: rtc currently does not support select\n");
    return -1;
}

void rtc_api_init(posix_api_t *api)
{
    api->close_fn         = rtc_close;
    api->shutdown_fn      = lwip_shutdown;
    api->socket_fn        = rtc_socket;
    api->accept_fn        = lwip_accept;
    api->accept4_fn       = lwip_accept4;
    api->bind_fn          = lwip_bind;
    api->listen_fn        = lwip_listen;
    api->connect_fn       = lwip_connect;

    api->setsockopt_fn    = lwip_setsockopt;
    api->getsockopt_fn    = lwip_getsockopt;
    api->getpeername_fn   = lwip_getpeername;
    api->getsockname_fn   = lwip_getsockname;

    api->read_fn          = lwip_read;
    api->readv_fn         = lwip_readv;
    api->write_fn         = lwip_write;
    api->writev_fn        = lwip_writev;
    api->recv_fn          = lwip_recv;
    api->send_fn          = lwip_send;
    api->recvmsg_fn       = (ssize_t (*)(int, const struct msghdr *, int))lwip_recvmsg; // TODO: fix unnecessary 'const' in lwipgz_posix_api.h
    api->sendmsg_fn       = lwip_sendmsg;
    api->recvfrom_fn      = lwip_recvfrom;
    api->sendto_fn        = lwip_sendto;

    api->epoll_ctl_fn     = rtc_epoll_ctl;
    api->epoll_create1_fn = rtc_epoll_create1;
    api->epoll_create_fn  = rtc_epoll_create;
    api->epoll_wait_fn    = rtc_epoll_wait;

    api->poll_fn          = rtc_poll;
    api->select_fn        = rtc_select;
}
