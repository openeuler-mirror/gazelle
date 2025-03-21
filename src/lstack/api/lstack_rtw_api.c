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

#include "common/gazelle_base_func.h"
#include "lstack_log.h"
#include "lstack_cfg.h"
#include "lstack_thread_rpc.h"
#include "lstack_protocol_stack.h"
#include "lstack_lwip.h"
#include "lstack_rtw_api.h"
#include "lstack_epoll.h"
#include "lstack_wait.h"

/* when fd is listenfd, listenfd of all protocol stack thread will be closed */
static int stack_broadcast_close(int fd)
{
    int ret = 0;
    struct protocol_stack *stack;
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }

    do {
        if (POSIX_IS_CLOSED(sock)) {
            break;
        }
        stack = get_protocol_stack_by_id(sock->stack_id);
        if (stack == NULL || rpc_call_close(&stack->rpc_queue, fd)) {
            ret = -1;
        }

        sock = sock->listen_next;
        fd = sock->conn->callback_arg.socket;
    } while (1);

    return ret;
}

static int stack_broadcast_shutdown(int fd, int how)
{
    int32_t ret = 0;
    struct protocol_stack *stack;
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }

    do {
        if (POSIX_IS_CLOSED(sock)) {
            break;
        }
        stack = get_protocol_stack_by_id(sock->stack_id);
        if (stack == NULL || rpc_call_shutdown(&stack->rpc_queue, fd, how)) {
            ret = -1;
        }

        sock = sock->listen_next;
        fd = sock->conn->callback_arg.socket;
    } while (1);

    return ret;
}

/* choice one stack bind */
static int stack_single_bind(int fd, const struct sockaddr *name, socklen_t namelen)
{
    struct protocol_stack *stack;
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    stack = get_protocol_stack_by_id(sock->stack_id);
    return rpc_call_bind(&stack->rpc_queue, fd, name, namelen);
}

/* bind sync to all protocol stack thread, so that any protocol stack thread can build connect */
static int stack_broadcast_bind(int fd, const struct sockaddr *name, socklen_t namelen)
{
    struct protocol_stack *cur_stack;
    struct protocol_stack *stack = NULL;
    int ret, clone_fd;

    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, %d get sock null or stack null\n", rte_gettid(), fd);
        GAZELLE_RETURN(EBADF);
    }

    cur_stack = get_protocol_stack_by_id(sock->stack_id);
    ret = rpc_call_bind(&cur_stack->rpc_queue, fd, name, namelen);
    if (ret < 0) {
        close(fd);
        return ret;
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    for (int i = 0; i < stack_group->stack_num; ++i) {
        stack = stack_group->stacks[i];
        if (stack != cur_stack) {
            clone_fd = rpc_call_shadow_fd(&stack->rpc_queue, fd, name, namelen);
            if (clone_fd < 0) {
                stack_broadcast_close(fd);
                return clone_fd;
            }
        }
    }
    return 0;
}

static struct lwip_sock *get_min_accept_sock(int fd)
{
    struct lwip_sock *sock;
    struct lwip_sock *min_sock = NULL;

    for (sock = lwip_get_socket(fd); sock != NULL; sock = sock->listen_next) {
        if (!netconn_is_nonblocking(sock->conn)) {
            /* init all sock sk_wait */
            if (unlikely(sock->sk_wait == NULL) || sock->sk_wait->type == WAIT_CLOSE) {
                sock->sk_wait = poll_construct_wait(0);
            }
            if (!(sock->sk_wait->type & WAIT_BLOCK)) {
                sock->sk_wait->type |= WAIT_BLOCK;
            }
        }

        if (!sock_event_hold_pending(sock, WAIT_BLOCK, NETCONN_EVT_RCVPLUS, 0)) {
            continue;
        }

        if (min_sock == NULL || 
            get_protocol_stack_by_id(min_sock->stack_id)->conn_num > get_protocol_stack_by_id(sock->stack_id)->conn_num) {
            min_sock = sock;
        }
    }

    return min_sock;
}

/* ergodic the protocol stack thread to find the connection, because all threads are listening */
static int stack_broadcast_accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    int ret = -1;
    struct lwip_sock *min_sock = NULL;
    struct lwip_sock *sock = lwip_get_socket(fd);
    struct protocol_stack *stack = NULL;
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }

    min_sock = get_min_accept_sock(fd);
    if (min_sock == NULL) {
        if (sock_event_wait(sock, netconn_is_nonblocking(sock->conn) || (flags & SOCK_NONBLOCK))) {
            min_sock = get_min_accept_sock(fd);
        }
    }

    if (!POSIX_IS_CLOSED(min_sock)) {
        stack = get_protocol_stack_by_id(min_sock->stack_id);
        ret = rpc_call_accept(&stack->rpc_queue, min_sock->conn->callback_arg.socket, addr, addrlen, flags);
    }

    if (ret < 0) {
        errno = EAGAIN;
    }
    return ret;
}

static int stack_broadcast_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    return stack_broadcast_accept4(fd, addr, addrlen, 0);
}

/* choice one stack listen */
static int stack_single_listen(int fd, int backlog)
{
    struct protocol_stack *stack;
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    stack = get_protocol_stack_by_id(sock->stack_id);
    return rpc_call_listen(&stack->rpc_queue, fd, backlog);
}

/* listen sync to all protocol stack thread, so that any protocol stack thread can build connect */
static int stack_broadcast_listen(int fd, int backlog)
{
    typedef union sockaddr_union {
        struct sockaddr     sa;
        struct sockaddr_in  in;
        struct sockaddr_in6 in6;
    } sockaddr_t;

    struct protocol_stack *cur_stack;
    struct protocol_stack *stack = NULL;
    sockaddr_t addr;
    socklen_t addr_len = sizeof(addr);
    int ret, clone_fd;

    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, %d get sock null or stack null\n", rte_gettid(), fd);
        GAZELLE_RETURN(EBADF);
    }

    cur_stack = get_protocol_stack_by_id(sock->stack_id);
    ret = rpc_call_getsockname(&cur_stack->rpc_queue, fd, (struct sockaddr *)&addr, &addr_len);
    if (ret != 0) {
        return ret;
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
#if GAZELLE_TCP_REUSE_IPPORT
    int min_conn_stk_idx = get_min_conn_stack(stack_group);
#endif
    for (int32_t i = 0; i < stack_group->stack_num; ++i) {
        stack = stack_group->stacks[i];
        if (stack != cur_stack) {
            clone_fd = rpc_call_shadow_fd(&stack->rpc_queue, fd, (struct sockaddr *)&addr, addr_len);
            if (clone_fd < 0) {
                stack_broadcast_close(fd);
                return clone_fd;
            }
        } else {
            clone_fd = fd;
        }
#if GAZELLE_TCP_REUSE_IPPORT
        if (min_conn_stk_idx == i) {
            lwip_get_socket(clone_fd)->conn->is_master_fd = 1;
        } else {
            lwip_get_socket(clone_fd)->conn->is_master_fd = 0;
        }
#endif
        ret = rpc_call_listen(&stack->rpc_queue, clone_fd, backlog);
        if (ret < 0) {
            stack_broadcast_close(fd);
            return ret;
        }
    }
    return 0;
}

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
    struct protocol_stack *stack;
    struct lwip_sock *sock = lwip_get_socket(s);
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    stack = get_protocol_stack_by_id(sock->stack_id);
    return rpc_call_connect(&stack->rpc_queue, s, name, namelen);
}

static int rtw_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
    struct protocol_stack *stack;
    struct lwip_sock *sock = lwip_get_socket(s);
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    stack = get_protocol_stack_by_id(sock->stack_id);
    return rpc_call_setsockopt(&stack->rpc_queue, s, level, optname, optval, optlen);
}

static int rtw_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
    struct protocol_stack *stack;
    struct lwip_sock *sock = lwip_get_socket(s);
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    stack = get_protocol_stack_by_id(sock->stack_id);
    return rpc_call_getsockopt(&stack->rpc_queue, s, level, optname, optval, optlen);
}

static int rtw_getpeername(int s, struct sockaddr *name, socklen_t *namelen)
{
    struct protocol_stack *stack;
    struct lwip_sock *sock = lwip_get_socket(s);
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    stack = get_protocol_stack_by_id(sock->stack_id);
    return rpc_call_getpeername(&stack->rpc_queue, s, name, namelen);
}

static int rtw_getsockname(int s, struct sockaddr *name, socklen_t *namelen)
{
    struct protocol_stack *stack;
    struct lwip_sock *sock = lwip_get_socket(s);
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    stack = get_protocol_stack_by_id(sock->stack_id);
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

static int rtw_close(int s)
{
    return stack_broadcast_close(s);
}

static int rtw_shutdown(int fd, int how)
{
    return stack_broadcast_shutdown(fd, how);
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
    api->recvmsg_fn       = rtw_recvmsg;
    api->sendmsg_fn       = rtw_sendmsg;
    api->recvfrom_fn      = rtw_recvfrom;
    api->sendto_fn        = rtw_sendto;
}
