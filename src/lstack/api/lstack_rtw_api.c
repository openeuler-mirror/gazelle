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

#include "lstack_thread_rpc.h"
#include "lstack_epoll.h"
#include "lstack_protocol_stack.h"
#include "lstack_cfg.h"
#include "lstack_lwip.h"
#include "common/gazelle_base_func.h"
#include "lstack_rtw_api.h"

static int rtw_socket(int domain, int type, int protocol)
{
    struct protocol_stack *stack = get_bind_protocol_stack();
    if (stack == NULL) {
        GAZELLE_RETURN(EINVAL);
    }
    return rpc_call_socket(&stack->rpc_queue, domain, type, protocol);
}

static int rtw_accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
    return stack_broadcast_accept(s, addr, addrlen);
}

static int rtw_accept4(int s, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    return stack_broadcast_accept4(s, addr, addrlen, flags);
}

static int rtw_bind(int s, const struct sockaddr *name, socklen_t namelen)
{
    struct lwip_sock *sock = lwip_get_socket(s);

    if (NETCONN_IS_UDP(sock) && get_global_cfg_params()->listen_shadow) {
        return stack_broadcast_bind(s, name, namelen);
    } else {
        return stack_single_bind(s, name, namelen);
    }
}

static int rtw_listen(int s, int backlog)
{
    if (!get_global_cfg_params()->tuple_filter &&
        !get_global_cfg_params()->listen_shadow) {
        return stack_single_listen(s, backlog);
    } else {
        return stack_broadcast_listen(s, backlog);
    }
}

static int rtw_connect(int s, const struct sockaddr *name, socklen_t namelen)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(s);
    if (stack == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    return rpc_call_connect(&stack->rpc_queue, s, name, namelen);
}

static int rtw_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(s);
    if (stack == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    return rpc_call_setsockopt(&stack->rpc_queue, s, level, optname, optval, optlen);
}

static int rtw_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(s);
    if (stack == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    return rpc_call_getsockopt(&stack->rpc_queue, s, level, optname, optval, optlen);
}

static int rtw_getpeername(int s, struct sockaddr *name, socklen_t *namelen)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(s);
    if (stack == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    return rpc_call_getpeername(&stack->rpc_queue, s, name, namelen);
}

static int rtw_getsockname(int s, struct sockaddr *name, socklen_t *namelen)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(s);
    if (stack == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    return rpc_call_getsockname(&stack->rpc_queue, s, name, namelen);
}

static ssize_t rtw_read(int s, void *mem, size_t len)
{
    return do_lwip_read_from_stack(s, mem, len, 0, NULL, NULL);
}

static ssize_t rtw_readv(int s, const struct iovec *iov, int iovcnt)
{
    struct msghdr msg;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = LWIP_CONST_CAST(struct iovec *, iov);
    msg.msg_iovlen = iovcnt;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    return do_lwip_recvmsg_from_stack(s, &msg, 0);
}

static ssize_t rtw_write(int s, const void *mem, size_t size)
{
    return do_lwip_send_to_stack(s, mem, size, 0, NULL, 0);
}

static ssize_t rtw_writev(int s, const struct iovec *iov, int iovcnt)
{
    struct lwip_sock *sock = lwip_get_socket(s);
    struct msghdr msg;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = LWIP_CONST_CAST(struct iovec *, iov);
    msg.msg_iovlen = iovcnt;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    return do_lwip_sendmsg_to_stack(sock, s, &msg, 0);
}

static ssize_t rtw_recv(int sockfd, void *buf, size_t len, int flags)
{
    return do_lwip_read_from_stack(sockfd, buf, len, flags, NULL, NULL);
}

static ssize_t rtw_send(int sockfd, const void *buf, size_t len, int flags)
{
    return do_lwip_send_to_stack(sockfd, buf, len, flags, NULL, 0);
}

static ssize_t rtw_recvmsg(int s, struct msghdr *message, int flags)
{
    return do_lwip_recvmsg_from_stack(s, message, flags);
}

static ssize_t rtw_sendmsg(int s, const struct msghdr *message, int flags)
{
    struct lwip_sock *sock = lwip_get_socket(s);
    return do_lwip_sendmsg_to_stack(sock, s, message, flags);
}

static ssize_t rtw_udp_recvfrom(int sockfd, void *buf, size_t len, int flags,
                                struct sockaddr *addr, socklen_t *addrlen)
{
    struct lwip_sock *sock = lwip_get_socket(sockfd);
    int ret;

    while (1) {
        ret = do_lwip_read_from_stack(sockfd, buf, len, flags, addr, addrlen);
        if (ret >= 0) {
            return ret;
        }
        if (ret < 0 && errno != EAGAIN) {
            return -1;
        }
        sock = sock->listen_next;
        if (!POSIX_IS_CLOSED(sock)) {
            sockfd = sock->conn->callback_arg.socket;
        } else {
            if (sock == NULL) {
                errno = EAGAIN;
                return -1;
            } else {
                errno = ENOTCONN;
                return -1;
            }
        }
    }
}

static inline ssize_t rtw_tcp_recvfrom(int sockfd, void *buf, size_t len, int flags,
                                       struct sockaddr *addr, socklen_t *addrlen)
{
    return do_lwip_read_from_stack(sockfd, buf, len, flags, addr, addrlen);
}


static ssize_t rtw_recvfrom(int sockfd, void *buf, size_t len, int flags,
                            struct sockaddr *addr, socklen_t *addrlen)
{
    struct lwip_sock *sock = lwip_get_socket(sockfd);
    if (NETCONN_IS_UDP(sock)) {
        return rtw_udp_recvfrom(sockfd, buf, len, flags, addr, addrlen);
    } else {
        return rtw_tcp_recvfrom(sockfd, buf, len, flags, addr, addrlen);
    }
}

static ssize_t rtw_sendto(int sockfd, const void *buf, size_t len, int flags,
                          const struct sockaddr *addr, socklen_t addrlen)
{
    return do_lwip_send_to_stack(sockfd, buf, len, flags, addr, addrlen);
}

static int rtw_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout)
{
    return lstack_rtw_epoll_wait(epfd, events, maxevents, timeout);
}

static int rtw_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    return lstack_poll(fds, nfds, timeout);
}

static int rtw_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    return lstack_select(nfds, readfds, writefds, exceptfds, timeout);
}

static int rtw_close(int s)
{
    struct lwip_sock *sock = lwip_get_socket(s);
    if (sock && sock->wakeup && sock->wakeup->epollfd == s) {
        return lstack_epoll_close(s);
    }
    return stack_broadcast_close(s);
}

static int rtw_shutdown(int fd, int how)
{
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock && sock->wakeup && sock->wakeup->epollfd == fd) {
        GAZELLE_RETURN(ENOTSOCK);
    }

    return stack_broadcast_shutdown(fd, how);
}

static int rtw_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return lstack_rtw_epoll_ctl(epfd, op, fd, event);
}

static int rtw_epoll_create1(int flags)
{
    return lstack_epoll_create1(flags);
}

static int rtw_epoll_create(int flags)
{
    return lstack_epoll_create(flags);
}

void rtw_api_init(posix_api_t *api)
{
    api->close_fn         = rtw_close;
    api->shutdown_fn      = rtw_shutdown;
    api->socket_fn        = rtw_socket;
    api->accept_fn        = rtw_accept;
    api->accept4_fn       = rtw_accept4;
    api->bind_fn          = rtw_bind;
    api->listen_fn        = rtw_listen;
    api->connect_fn       = rtw_connect;

    api->setsockopt_fn    = rtw_setsockopt;
    api->getsockopt_fn    = rtw_getsockopt;
    api->getpeername_fn   = rtw_getpeername;
    api->getsockname_fn   = rtw_getsockname;

    api->read_fn          = rtw_read;
    api->readv_fn         = rtw_readv;
    api->write_fn         = rtw_write;
    api->writev_fn        = rtw_writev;
    api->recv_fn          = rtw_recv;
    api->send_fn          = rtw_send;
    api->recvmsg_fn       = (ssize_t (*)(int, const struct msghdr *, int))rtw_recvmsg; // TODO: fix unnecessary 'const' in lwipgz_posix_api.h
    api->sendmsg_fn       = rtw_sendmsg;
    api->recvfrom_fn      = rtw_recvfrom;
    api->sendto_fn        = rtw_sendto;

    api->epoll_ctl_fn     = rtw_epoll_ctl;
    api->epoll_create1_fn = rtw_epoll_create1;
    api->epoll_create_fn  = rtw_epoll_create;
    api->epoll_wait_fn    = rtw_epoll_wait;

    api->poll_fn          = rtw_poll;
    api->select_fn        = rtw_select;
}