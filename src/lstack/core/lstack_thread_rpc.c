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
#include <sys/types.h>
#include <stdatomic.h>
#include <lwip/sockets.h>
#include <lwipsock.h>
#include <rte_mempool.h>

#include "lstack_log.h"
#include "lstack_lwip.h"
#include "lstack_protocol_stack.h"
#include "lstack_control_plane.h"
#include "gazelle_base_func.h"
#include "lstack_dpdk.h"
#include "lstack_thread_rpc.h"

#define RPC_MSG_MAX            32
#define RPC_MSG_MASK           (RPC_MSG_MAX - 1)
struct rpc_msg_pool {
    struct rpc_msg msgs[RPC_MSG_MAX];
    uint32_t prod __rte_cache_aligned;
    uint32_t cons __rte_cache_aligned;
};

static PER_THREAD struct rpc_msg_pool *g_rpc_pool = NULL;

static inline __attribute__((always_inline)) struct rpc_msg *get_rpc_msg(struct rpc_msg_pool *rpc_pool)
{
    uint32_t cons = __atomic_load_n(&rpc_pool->cons, __ATOMIC_ACQUIRE);
    uint32_t prod = rpc_pool->prod + 1;

    if (prod - cons >= RPC_MSG_MAX) {
        return NULL;
    }

    rpc_pool->prod = prod;
    return &rpc_pool->msgs[prod & RPC_MSG_MASK];
}

static struct rpc_msg *rpc_msg_alloc(struct protocol_stack *stack, rpc_msg_func func)
{
    struct rpc_msg *msg = NULL;

    if (stack == NULL) {
        return NULL;
    }

    if (g_rpc_pool == NULL) {
        g_rpc_pool = calloc(1, sizeof(struct rpc_msg_pool));
        if (g_rpc_pool == NULL) {
            get_protocol_stack_group()->call_alloc_fail++;
            return NULL;
        }
    }

    msg = get_rpc_msg(g_rpc_pool);
    if (msg == NULL) {
        get_protocol_stack_group()->call_alloc_fail++;
        return NULL;
    }
    msg->pool = g_rpc_pool;

    pthread_spin_init(&msg->lock, PTHREAD_PROCESS_PRIVATE);
    msg->func = func;
    msg->self_release = 1;

    return msg;
}

static inline __attribute__((always_inline)) void rpc_msg_free(struct rpc_msg *msg)
{
    pthread_spin_destroy(&msg->lock);

    msg->self_release = 0;
    msg->func = NULL;

    atomic_fetch_add((_Atomic uint32_t *)&msg->pool->cons, 1);
}

static inline __attribute__((always_inline)) void rpc_call(lockless_queue *queue, struct rpc_msg *msg)
{
    pthread_spin_trylock(&msg->lock);
    lockless_queue_mpsc_push(queue, &msg->queue_node);
}

static inline __attribute__((always_inline)) int32_t rpc_sync_call(lockless_queue *queue, struct rpc_msg *msg)
{
    int32_t ret;

    rpc_call(queue, msg);

    // waiting stack unlock
    pthread_spin_lock(&msg->lock);

    ret = msg->result;
    rpc_msg_free(msg);
    return ret;
}

void poll_rpc_msg(struct protocol_stack *stack, uint32_t max_num)
{
    uint32_t num;
    struct rpc_msg *msg = NULL;

    num = 0;
    while (num++ < max_num) {
        lockless_queue_node *node = lockless_queue_mpsc_pop(&stack->rpc_queue);
        if (node == NULL) {
            break;
        }

        msg = container_of(node, struct rpc_msg, queue_node);

        if (msg->func) {
            msg->func(msg);
        } else {
            stack->stats.call_null++;
        }

        if (msg->self_release) {
            pthread_spin_unlock(&msg->lock);
        } else {
            rpc_msg_free(msg);
        }
    }
}

int32_t rpc_call_conntable(struct protocol_stack *stack, void *conn_table, uint32_t max_conn)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack, get_lwip_conntable);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].p = conn_table;
    msg->args[MSG_ARG_1].u = max_conn;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_connnum(struct protocol_stack *stack)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack, get_lwip_connnum);
    if (msg == NULL) {
        return -1;
    }

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_shadow_fd(struct protocol_stack *stack, int32_t fd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack, create_shadow_fd);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].cp = addr;
    msg->args[MSG_ARG_2].socklen = addrlen;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

static void rpc_msgcnt(struct rpc_msg *msg)
{
    struct protocol_stack *stack = get_protocol_stack();
    msg->result = lockless_queue_count(&stack->rpc_queue);
}

int32_t rpc_call_msgcnt(struct protocol_stack *stack)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack, rpc_msgcnt);
    if (msg == NULL) {
        return -1;
    }

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_thread_regphase1(struct protocol_stack *stack, void *conn)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack, thread_register_phase1);
    if (msg == NULL) {
        return -1;
    }
    msg->args[MSG_ARG_0].p = conn;
    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_thread_regphase2(struct protocol_stack *stack, void *conn)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack, thread_register_phase2);
    if (msg == NULL) {
        return -1;
    }
    msg->args[MSG_ARG_0].p = conn;
    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_sendlistcnt(struct protocol_stack *stack)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_sendlist_count);
    if (msg == NULL) {
        return -1;
    }

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_recvlistcnt(struct protocol_stack *stack)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_recvlist_count);
    if (msg == NULL) {
        return -1;
    }

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_arp(struct protocol_stack *stack, struct rte_mbuf *mbuf)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_arp);
    if (msg == NULL) {
        return -1;
    }

    msg->self_release = 0;
    msg->args[MSG_ARG_0].p = mbuf;
    lockless_queue_mpsc_push(&stack->rpc_queue, &msg->queue_node);

    return 0;
}

int32_t rpc_call_socket(int32_t domain, int32_t type, int32_t protocol)
{
    struct protocol_stack *stack = get_bind_protocol_stack();
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_socket);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = domain;
    msg->args[MSG_ARG_1].i = type;
    msg->args[MSG_ARG_2].i = protocol;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_close(int fd)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_close);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_bind(int32_t fd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_bind);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].cp = addr;
    msg->args[MSG_ARG_2].socklen = addrlen;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_listen(int s, int backlog)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(s);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_listen);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = s;
    msg->args[MSG_ARG_1].i = backlog;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_accept);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].p = addr;
    msg->args[MSG_ARG_2].p = addrlen;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_connect);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].cp = addr;
    msg->args[MSG_ARG_2].socklen = addrlen;

    int32_t ret = rpc_sync_call(&stack->rpc_queue, msg);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

int32_t rpc_call_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_getpeername);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].p = addr;
    msg->args[MSG_ARG_2].p = addrlen;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_getsockname);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].p = addr;
    msg->args[MSG_ARG_2].p = addrlen;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_getsockopt);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].i = level;
    msg->args[MSG_ARG_2].i = optname;
    msg->args[MSG_ARG_3].p = optval;
    msg->args[MSG_ARG_4].p = optlen;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_setsockopt);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].i = level;
    msg->args[MSG_ARG_2].i = optname;
    msg->args[MSG_ARG_3].cp = optval;
    msg->args[MSG_ARG_4].socklen = optlen;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_fcntl(int fd, int cmd, long val)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_fcntl);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].i = cmd;
    msg->args[MSG_ARG_2].l = val;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_ioctl(int fd, long cmd, void *argp)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_ioctl);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].l = cmd;
    msg->args[MSG_ARG_2].p = argp;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

void rpc_call_send(int fd, const void *buf, size_t len, int flags)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_send);
    if (msg == NULL) {
        return;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].size = len;
    msg->args[MSG_ARG_2].i = flags;

    msg->self_release = 0;
    rpc_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_sendmsg(int fd, const struct msghdr *msghdr, int flags)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_sendmsg);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].cp = msghdr;
    msg->args[MSG_ARG_2].i = flags;

    return rpc_sync_call(&stack->rpc_queue, msg);
}

int32_t rpc_call_recvmsg(int fd, struct msghdr *msghdr, int flags)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct rpc_msg *msg = rpc_msg_alloc(stack, stack_recvmsg);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].p = msghdr;
    msg->args[MSG_ARG_2].i = flags;

    return rpc_sync_call(&stack->rpc_queue, msg);
}
