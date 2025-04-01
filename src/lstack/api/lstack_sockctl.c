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
#include <lwip/udp.h>

#include "common/gazelle_base_func.h"
#include "lstack_log.h"
#include "lstack_cfg.h"
#include "lstack_thread_rpc.h"
#include "lstack_protocol_stack.h"
#include "lstack_epoll.h"
#include "lstack_sockctl.h"
#include "lstack_sockio.h"


static void callback_getpeername(struct rpc_msg *msg)
{
    msg->result = lwip_getpeername(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].p);
}

static void callback_getsockname(struct rpc_msg *msg)
{
    msg->result = lwip_getsockname(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].p);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d fail %ld\n", rte_gettid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

static void callback_getsockopt(struct rpc_msg *msg)
{
    msg->result = lwip_getsockopt(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i,
        msg->args[MSG_ARG_3].p, msg->args[MSG_ARG_4].p);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d, level %d, optname %d, fail %ld\n", rte_gettid(),
                   msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i, msg->result);
    }
}

static void callback_setsockopt(struct rpc_msg *msg)
{
    msg->result = lwip_setsockopt(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i,
        msg->args[MSG_ARG_3].cp, msg->args[MSG_ARG_4].u);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d, level %d, optname %d, fail %ld\n", rte_gettid(),
                   msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i, msg->result);
    }
}

static int rpc_call_getpeername(int stack_id, int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_getpeername);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].p = addr;
    msg->args[MSG_ARG_2].p = addrlen;

    return rpc_sync_call(queue, msg);
}

static int rpc_call_getsockname(int stack_id, int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_getsockname);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].p = addr;
    msg->args[MSG_ARG_2].p = addrlen;

    return rpc_sync_call(queue, msg);
}

static int rpc_call_getsockopt(int stack_id, int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_getsockopt);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].i = level;
    msg->args[MSG_ARG_2].i = optname;
    msg->args[MSG_ARG_3].p = optval;
    msg->args[MSG_ARG_4].p = optlen;

    return rpc_sync_call(queue, msg);
}

static int rpc_call_setsockopt(int stack_id, int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_setsockopt);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].i = level;
    msg->args[MSG_ARG_2].i = optname;
    msg->args[MSG_ARG_3].cp = optval;
    msg->args[MSG_ARG_4].u = optlen;

    return rpc_sync_call(queue, msg);
}

static int rtw_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
    struct lwip_sock *sock = lwip_get_socket(s);
    if (POSIX_IS_CLOSED(sock)) {
        GAZELLE_RETURN(EBADF);
    }
    return rpc_call_setsockopt(sock->stack_id, s, level, optname, optval, optlen);
}

static int rtw_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
    struct lwip_sock *sock = lwip_get_socket(s);
    if (POSIX_IS_CLOSED(sock)) {
        GAZELLE_RETURN(EBADF);
    }
    return rpc_call_getsockopt(sock->stack_id, s, level, optname, optval, optlen);
}

static int rtw_getpeername(int s, struct sockaddr *name, socklen_t *namelen)
{
    struct lwip_sock *sock = lwip_get_socket(s);
    if (POSIX_IS_CLOSED(sock)) {
        GAZELLE_RETURN(EBADF);
    }
    return rpc_call_getpeername(sock->stack_id, s, name, namelen);
}

static int rtw_getsockname(int s, struct sockaddr *name, socklen_t *namelen)
{
    struct lwip_sock *sock = lwip_get_socket(s);
    if (POSIX_IS_CLOSED(sock)) {
        GAZELLE_RETURN(EBADF);
    }
    return rpc_call_getsockname(sock->stack_id, s, name, namelen);
}


static void callback_socket(struct rpc_msg *msg)
{
    msg->result = lwip_socket(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i);
    if (msg->result < 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, %ld socket failed\n", rte_gettid(), msg->result);
    }
}

static int rpc_call_socket(int stack_id, int domain, int type, int protocol)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_socket);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = domain;
    msg->args[MSG_ARG_1].i = type;
    msg->args[MSG_ARG_2].i = protocol;

    return rpc_sync_call(queue, msg);
}

static void callback_close(struct rpc_msg *msg)
{
    int fd = msg->args[MSG_ARG_0].i;
    struct lwip_sock *sock = lwip_get_socket(fd);

    if (sockio_mbox_pending(sock)) {
        rpc_queue *queue = &get_protocol_stack_by_id(sock->stack_id)->rpc_queue;
        rpc_async_call(queue, msg, RPC_MSG_RECALL); /* until stack_send recall finish */
        return;
    }

    msg->result = lwip_close(fd);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d failed %ld\n", rte_gettid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

static void callback_shutdown(struct rpc_msg *msg)
{
    int fd = msg->args[MSG_ARG_0].i;
    int how = msg->args[MSG_ARG_1].i;
    struct lwip_sock *sock = lwip_get_socket(fd);

    if (sockio_mbox_pending(sock)) {
        rpc_queue *queue = &get_protocol_stack_by_id(sock->stack_id)->rpc_queue;
        rpc_async_call(queue, msg, RPC_MSG_RECALL);
        return;
    }

    msg->result = lwip_shutdown(fd, how);
    if (msg->result != 0 && errno != ENOTCONN) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d fail %ld\n", rte_gettid(), fd, msg->result);
    }

    posix_api->shutdown_fn(fd, how);
}

static int rpc_call_close(int stack_id, int fd)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_close);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;

    return rpc_sync_call(queue, msg);
}

static int rpc_call_shutdown(int stack_id, int fd, int how)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_shutdown);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].i = how;

    return rpc_sync_call(queue, msg);
}

static void callback_bind(struct rpc_msg *msg)
{
    msg->result = lwip_bind(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].cp, msg->args[MSG_ARG_2].u);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d failed %ld\n", rte_gettid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

static int rpc_call_bind(int stack_id, int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_bind);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].cp = addr;
    msg->args[MSG_ARG_2].u = addrlen;

    return rpc_sync_call(queue, msg);
}

static void callback_listen(struct rpc_msg *msg)
{
    int fd = msg->args[MSG_ARG_0].i;
    int backlog = msg->args[MSG_ARG_1].i;

    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock == NULL) {
        msg->result = -1;
        return;
    }

    /* new listen add to stack listen list */
    msg->result = lwip_listen(fd, backlog);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d failed %ld\n", rte_gettid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

static int rpc_call_listen(int stack_id, int s, int backlog)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_listen);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = s;
    msg->args[MSG_ARG_1].i = backlog;

    return rpc_sync_call(queue, msg);
}

static void do_lwip_clone_sockopt(struct lwip_sock *dst_sock, struct lwip_sock *src_sock)
{
    dst_sock->conn->pcb.ip->so_options = src_sock->conn->pcb.ip->so_options;
    dst_sock->conn->pcb.ip->ttl = src_sock->conn->pcb.ip->ttl;
    dst_sock->conn->pcb.ip->tos = src_sock->conn->pcb.ip->tos;
    dst_sock->conn->flags = src_sock->conn->flags;

    switch (NETCONN_TYPE(src_sock->conn)) {
    case NETCONN_TCP:
        dst_sock->conn->pcb.tcp->netif_idx = src_sock->conn->pcb.tcp->netif_idx;
        dst_sock->conn->pcb.tcp->flags = src_sock->conn->pcb.tcp->flags;
        dst_sock->conn->pcb.tcp->keep_idle = src_sock->conn->pcb.tcp->keep_idle;
        dst_sock->conn->pcb.tcp->keep_intvl = src_sock->conn->pcb.tcp->keep_intvl;
        dst_sock->conn->pcb.tcp->keep_cnt = src_sock->conn->pcb.tcp->keep_cnt;
        break;
    case NETCONN_UDP:
        dst_sock->conn->pcb.udp->flags = src_sock->conn->pcb.udp->flags;
        dst_sock->conn->pcb.udp->mcast_ifindex = src_sock->conn->pcb.udp->mcast_ifindex;
        dst_sock->conn->pcb.udp->mcast_ttl = src_sock->conn->pcb.udp->mcast_ttl;
        break;
    default:
        break;
    }
}
static void callback_create_shadow_fd(struct rpc_msg *msg)
{
    int fd = msg->args[MSG_ARG_0].i;
    struct sockaddr *addr = msg->args[MSG_ARG_1].p;
    socklen_t addr_len = msg->args[MSG_ARG_2].u;

    int clone_fd = 0;
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "get sock null fd=%d\n", fd);
        msg->result = -1;
        return;
    }

    int domain = addr->sa_family;
    int type = NETCONN_TYPE(sock->conn) == NETCONN_UDP ? SOCK_DGRAM : SOCK_STREAM;
    clone_fd = lwip_socket(domain, type, 0);
    if (clone_fd < 0) {
        LSTACK_LOG(ERR, LSTACK, "clone socket failed clone_fd=%d errno=%d\n", clone_fd, errno);
        msg->result = clone_fd;
        return;
    }

    struct lwip_sock *clone_sock = lwip_get_socket(clone_fd);
    if (clone_sock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "get sock null fd=%d clone_fd=%d\n", fd, clone_fd);
        msg->result = -1;
        return;
    }

    do_lwip_clone_sockopt(clone_sock, sock);

    while (sock->listen_next) {
        sock = sock->listen_next;
    }
    sock->listen_next = clone_sock;

    int ret = lwip_bind(clone_fd, addr, addr_len);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "clone bind failed clone_fd=%d errno=%d\n", clone_fd, errno);
        msg->result = ret;
        return;
    }

    msg->result = clone_fd;
}

static int rpc_call_shadow_fd(int stack_id, int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_create_shadow_fd);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].cp = addr;
    msg->args[MSG_ARG_2].u = addrlen;

    return rpc_sync_call(queue, msg);
}

static void callback_accept(struct rpc_msg *msg)
{
    struct lwip_sock *sock;
    int fd = msg->args[MSG_ARG_0].i;
    msg->result = -1;

    int accept_fd = lwip_accept4(fd, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].p, msg->args[MSG_ARG_3].i);
    if (accept_fd < 0) {
        sock = lwip_get_socket(fd);
        if (!POSIX_IS_CLOSED(sock)) {
            SOCK_WAIT_STAT(sock->sk_wait, accept_fail, 1);
        }
        LSTACK_LOG(ERR, LSTACK, "fd %d ret %d\n", fd, accept_fd);
        return;
    }
    msg->result = accept_fd;
}

static int rpc_call_accept(int stack_id, int fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_accept);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].p = addr;
    msg->args[MSG_ARG_2].p = addrlen;
    msg->args[MSG_ARG_3].i = flags;

    return rpc_sync_call(queue, msg);
}

static void callback_connect(struct rpc_msg *msg)
{
    msg->result = lwip_connect(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].u);
    if (msg->result < 0) {
        msg->result = -errno;
    }
}

static int rpc_call_connect(int stack_id, int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_connect);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].cp = addr;
    msg->args[MSG_ARG_2].u = addrlen;

    int ret = rpc_sync_call(queue, msg);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }

    if (ret < 0 && errno == EINPROGRESS) {
        struct lwip_sock *sock = lwip_get_socket(fd);
        if (sock_event_wait(sock, netconn_is_nonblocking(sock->conn))) {
            ret = 0;
        }
    }
    return ret;
}

/* for lwip nonblock connected callback */
void do_lwip_connected_callback(int fd)
{
    bool has_kernel;
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (POSIX_IS_CLOSED(sock)) {
        return;
    }

    has_kernel = POSIX_HAS_TYPE(sock, POSIX_KERNEL);
    POSIX_SET_TYPE(sock, POSIX_LWIP);
    if (has_kernel) {
        /* delete kernel event */
        if (sock->sk_wait != NULL) {
            posix_api->epoll_ctl_fn(sock->sk_wait->epfd, EPOLL_CTL_DEL, fd, NULL);
        }
        /* shutdown kernel connect, do_connect() has tried both kernel and lwip. */
        posix_api->shutdown_fn(fd, SHUT_RDWR);
    }
    return;
}

/* when fd is listenfd, listenfd of all protocol stack thread will be closed */
static int stack_broadcast_close(int fd)
{
    int ret = 0;
    struct lwip_sock *sock = lwip_get_socket(fd);

    while (sock != NULL) {
        if (POSIX_IS_CLOSED(sock)) {
            ret = -1;
            break;
        }
        fd = sock->conn->callback_arg.socket;
        ret |= rpc_call_close(sock->stack_id, fd);
        sock = sock->listen_next;
    }

    if (ret != 0) {
        GAZELLE_RETURN(EBADF);
    }
    return ret;
}

static int stack_broadcast_shutdown(int fd, int how)
{
    int ret = 0;
    struct lwip_sock *sock = lwip_get_socket(fd);

    while (true) {
        if (POSIX_IS_CLOSED(sock)) {
            ret = -1;
            break;
        }
        fd = sock->conn->callback_arg.socket;
        ret |= rpc_call_shutdown(sock->stack_id, fd, how);
        sock = sock->listen_next;
    }

    if (ret != 0) {
        GAZELLE_RETURN(EBADF);
    }
    return ret;
}

/* choice one stack bind */
static int stack_single_bind(int fd, const struct sockaddr *name, socklen_t namelen)
{
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (POSIX_IS_CLOSED(sock)) {
        GAZELLE_RETURN(EBADF);
    }
    return rpc_call_bind(sock->stack_id, fd, name, namelen);
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

    ret = rpc_call_bind(sock->stack_id, fd, name, namelen);
    if (ret < 0) {
        close(fd);
        return ret;
    }

    cur_stack = get_protocol_stack_by_id(sock->stack_id);
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    for (int i = 0; i < stack_group->stack_num; ++i) {
        stack = stack_group->stacks[i];
        if (stack != cur_stack) {
            clone_fd = rpc_call_shadow_fd(stack->stack_idx, fd, name, namelen);
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
    struct protocol_stack *stack;
    struct lwip_sock *min_sock;

    struct lwip_sock *sock = lwip_get_socket(fd);
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
        ret = rpc_call_accept(stack->stack_idx, min_sock->conn->callback_arg.socket, addr, addrlen, flags);
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
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (POSIX_IS_CLOSED(sock)) {
        GAZELLE_RETURN(EBADF);
    }
    return rpc_call_listen(sock->stack_id, fd, backlog);
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

    ret = rpc_call_getsockname(sock->stack_id, fd, (struct sockaddr *)&addr, &addr_len);
    if (ret != 0) {
        return ret;
    }

    cur_stack = get_protocol_stack_by_id(sock->stack_id);
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
#if GAZELLE_TCP_REUSE_IPPORT
    int min_conn_stk_idx = get_min_conn_stack(stack_group);
#endif

    for (int32_t i = 0; i < stack_group->stack_num; ++i) {
        stack = stack_group->stacks[i];
        if (stack != cur_stack) {
            clone_fd = rpc_call_shadow_fd(stack->stack_idx, fd, (struct sockaddr *)&addr, addr_len);
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
#endif /* GAZELLE_TCP_REUSE_IPPORT */

        ret = rpc_call_listen(stack->stack_idx, clone_fd, backlog);
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
    return rpc_call_socket(stack->stack_idx, domain, type, protocol);
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

    if (NETCONN_TYPE(sock->conn) == NETCONN_UDP && 
        get_global_cfg_params()->listen_shadow) {
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
    struct lwip_sock *sock = lwip_get_socket(s);
    struct protocol_stack *stack = get_protocol_stack_by_id(sock->stack_id);
    if (stack == NULL || POSIX_IS_CLOSED(sock)) {
        GAZELLE_RETURN(EBADF);
    }

    return rpc_call_connect(stack->stack_idx, s, name, namelen);
}

static int rtw_close(int s)
{
    return stack_broadcast_close(s);
}

static int rtw_shutdown(int fd, int how)
{
    return stack_broadcast_shutdown(fd, how);
}

void sockctl_rtw_api_init(posix_api_t *api)
{
    api->close_fn         = rtw_close;
    api->shutdown_fn      = rtw_shutdown;
    api->socket_fn        = rtw_socket;
    api->bind_fn          = rtw_bind;
    api->listen_fn        = rtw_listen;
    api->accept_fn        = rtw_accept;
    api->accept4_fn       = rtw_accept4;
    api->connect_fn       = rtw_connect;

    api->setsockopt_fn    = rtw_setsockopt;
    api->getsockopt_fn    = rtw_getsockopt;
    api->getpeername_fn   = rtw_getpeername;
    api->getsockname_fn   = rtw_getsockname;
}

static int rtc_connect(int s, const struct sockaddr *name, socklen_t namelen)
{
    int ret;

    ret = lwip_connect(s, name, namelen);
    if (ret < 0 && errno == EINPROGRESS) {
        struct lwip_sock *sock = lwip_get_socket(s);
        if (sock_event_wait(sock, netconn_is_nonblocking(sock->conn))) {
            ret = 0;
        }
    }

    return ret;
}

static int rtc_accept4(int s, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    int ret;
    struct lwip_sock *sock = lwip_get_socket(s);
    if (POSIX_IS_CLOSED(sock)) {
        GAZELLE_RETURN(EBADF);
    }

    ret = lwip_accept4(s, addr, addrlen, flags);
    if (ret < 0 && errno == EWOULDBLOCK) {
        if (sock_event_wait(sock, netconn_is_nonblocking(sock->conn) || (flags & SOCK_NONBLOCK))) {
            ret = lwip_accept4(s, addr, addrlen, flags);
        }
    }
    return ret;
}

static int rtc_accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
    return rtc_accept4(s, addr, addrlen, 0);
}

void sockctl_rtc_api_init(posix_api_t *api)
{
    api->close_fn         = lwip_close;
    api->shutdown_fn      = lwip_shutdown;
    api->socket_fn        = lwip_socket;
    api->bind_fn          = lwip_bind;
    api->listen_fn        = lwip_listen;
    api->accept_fn        = rtc_accept;
    api->accept4_fn       = rtc_accept4;
    api->connect_fn       = rtc_connect;

    api->setsockopt_fn    = lwip_setsockopt;
    api->getsockopt_fn    = lwip_getsockopt;
    api->getpeername_fn   = lwip_getpeername;
    api->getsockname_fn   = lwip_getsockname;
}
