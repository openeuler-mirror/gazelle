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
#include <lwip/sockets.h>
#include <rte_mempool.h>

#include "lstack_log.h"
#include "lstack_dpdk.h"
#include "lstack_rpc_proc.h"
#include "lstack_stack_stat.h"
#include "lstack_protocol_stack.h"
#include "lstack_thread_rpc.h"

static PER_THREAD struct rpc_msg_pool *g_rpc_pool = NULL;
static struct rpc_stats g_rpc_stats;
struct rpc_stats *rpc_stats_get(void)
{
    return &g_rpc_stats;
}

static inline __attribute__((always_inline)) struct rpc_msg *get_rpc_msg(struct rpc_msg_pool *rpc_pool)
{
    int ret;
    struct rpc_msg *msg = NULL;
    ret = rte_mempool_get(rpc_pool->mempool, (void **)&msg);
    if (ret < 0) {
        errno = ENOMEM;
        return NULL;
    }
    return msg;
}

static void rpc_msg_init(struct rpc_msg *msg, rpc_msg_func func, struct rpc_msg_pool *pool)
{
    msg->rpcpool = pool;
    pthread_spin_init(&msg->lock, PTHREAD_PROCESS_PRIVATE);
    msg->func = func;
    msg->sync_flag = 1;
    msg->recall_flag = 0;
}

static struct rpc_msg *rpc_msg_alloc_except(rpc_msg_func func)
{
    struct rpc_msg *msg = calloc(1, sizeof(struct rpc_msg));
    if (msg == NULL) {
        return NULL;
    }

    rpc_msg_init(msg, func, NULL);

    return msg;
}

static struct rpc_msg *rpc_msg_alloc(rpc_msg_func func)
{
    struct rpc_msg *msg = NULL;

    if (g_rpc_pool == NULL) {
        g_rpc_pool = calloc(1, sizeof(struct rpc_msg_pool));
        if (g_rpc_pool == NULL) {
            LSTACK_LOG(INFO, LSTACK, "g_rpc_pool calloc failed\n");
            g_rpc_stats.call_alloc_fail++;
            exit(-1);
        }

        g_rpc_pool->mempool = create_mempool("rpc_pool", RPC_MSG_MAX, sizeof(struct rpc_msg),
            0, rte_gettid());
        if (g_rpc_pool->mempool == NULL) {
            LSTACK_LOG(INFO, LSTACK, "rpc_pool create failed, errno is %d\n", errno);
            g_rpc_stats.call_alloc_fail++;
            exit(-1);
        }
    }

    msg = get_rpc_msg(g_rpc_pool);
    if (msg == NULL) {
        g_rpc_stats.call_alloc_fail++;
        return NULL;
    }
    rpc_msg_init(msg, func, g_rpc_pool);

    return msg;
}

static inline __attribute__((always_inline)) int32_t rpc_sync_call(rpc_queue *queue, struct rpc_msg *msg)
{
    int32_t ret;

    pthread_spin_trylock(&msg->lock);
    rpc_call(queue, msg);

    // waiting stack unlock
    pthread_spin_lock(&msg->lock);

    ret = msg->result;
    rpc_msg_free(msg);
    return ret;
}

int32_t rpc_msgcnt(rpc_queue *queue)
{
    return lockless_queue_count(queue);
}

int rpc_poll_msg(rpc_queue *queue, uint32_t max_num)
{
    int force_quit = 0;
    struct rpc_msg *msg = NULL;

    while (max_num--) {
        lockless_queue_node *node = lockless_queue_mpsc_pop(queue);
        if (node == NULL) {
            break;
        }

        msg = container_of(node, struct rpc_msg, queue_node);

        if (msg->func) {
            msg->func(msg);
        } else {
            g_rpc_stats.call_null++;
        }

        if (msg->func == stack_exit_by_rpc) {
            force_quit = 1;
        }

        if (!msg->recall_flag) {
            if (msg->sync_flag) {
                pthread_spin_unlock(&msg->lock);
            } else {
                rpc_msg_free(msg);
            }
        } else {
            msg->recall_flag = 0;
        }
    }

    return force_quit;
}

int32_t rpc_call_conntable(rpc_queue *queue, void *conn_table, uint32_t max_conn)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_get_conntable);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].p = conn_table;
    msg->args[MSG_ARG_1].u = max_conn;

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_connnum(rpc_queue *queue)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_get_connnum);
    if (msg == NULL) {
        return -1;
    }

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_shadow_fd(rpc_queue *queue, int32_t fd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_create_shadow_fd);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].cp = addr;
    msg->args[MSG_ARG_2].socklen = addrlen;

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_thread_regphase1(rpc_queue *queue, void *conn)
{
    struct rpc_msg *msg = rpc_msg_alloc(thread_register_phase1);
    if (msg == NULL) {
        return -1;
    }
    msg->args[MSG_ARG_0].p = conn;
    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_thread_regphase2(rpc_queue *queue, void *conn)
{
    struct rpc_msg *msg = rpc_msg_alloc(thread_register_phase2);
    if (msg == NULL) {
        return -1;
    }
    msg->args[MSG_ARG_0].p = conn;
    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_mbufpoolsize(rpc_queue *queue)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_mempool_size);
    if (msg == NULL) {
        return -1;
    }

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_recvlistcnt(rpc_queue *queue)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_recvlist_count);
    if (msg == NULL) {
        return -1;
    }

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_arp(rpc_queue *queue, void *mbuf)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_arp);
    if (msg == NULL) {
        return -1;
    }

    msg->sync_flag = 0;
    msg->args[MSG_ARG_0].p = mbuf;

    rpc_call(queue, msg);

    return 0;
}

int32_t rpc_call_socket(rpc_queue *queue, int32_t domain, int32_t type, int32_t protocol)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_socket);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = domain;
    msg->args[MSG_ARG_1].i = type;
    msg->args[MSG_ARG_2].i = protocol;

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_close(rpc_queue *queue, int fd)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_close);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_stack_exit(rpc_queue *queue)
{
    struct rpc_msg *msg = rpc_msg_alloc_except(stack_exit_by_rpc);
    if (msg == NULL) {
        return -1;
    }

    rpc_call(queue, msg);
    return 0;
}

int32_t rpc_call_shutdown(rpc_queue *queue, int fd, int how)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_shutdown);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].i = how;

    return rpc_sync_call(queue, msg);
}

void rpc_call_clean_epoll(rpc_queue *queue, void *wakeup)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_clean_epoll);
    if (msg == NULL) {
        return;
    }

    msg->args[MSG_ARG_0].p = wakeup;

    rpc_sync_call(queue, msg);
}

int32_t rpc_call_bind(rpc_queue *queue, int32_t fd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_bind);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].cp = addr;
    msg->args[MSG_ARG_2].socklen = addrlen;

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_listen(rpc_queue *queue, int s, int backlog)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_listen);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = s;
    msg->args[MSG_ARG_1].i = backlog;

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_accept(rpc_queue *queue, int fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_accept);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].p = addr;
    msg->args[MSG_ARG_2].p = addrlen;
    msg->args[MSG_ARG_3].i = flags;

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_connect(rpc_queue *queue, int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_connect);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].cp = addr;
    msg->args[MSG_ARG_2].socklen = addrlen;

    int32_t ret = rpc_sync_call(queue, msg);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

int32_t rpc_call_getpeername(rpc_queue *queue, int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_getpeername);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].p = addr;
    msg->args[MSG_ARG_2].p = addrlen;

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_getsockname(rpc_queue *queue, int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_getsockname);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].p = addr;
    msg->args[MSG_ARG_2].p = addrlen;

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_getsockopt(rpc_queue *queue, int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_getsockopt);
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

int32_t rpc_call_setsockopt(rpc_queue *queue, int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_setsockopt);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].i = level;
    msg->args[MSG_ARG_2].i = optname;
    msg->args[MSG_ARG_3].cp = optval;
    msg->args[MSG_ARG_4].socklen = optlen;

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_fcntl(rpc_queue *queue, int fd, int cmd, long val)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_fcntl);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].i = cmd;
    msg->args[MSG_ARG_2].l = val;

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_ioctl(rpc_queue *queue, int fd, long cmd, void *argp)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_ioctl);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].l = cmd;
    msg->args[MSG_ARG_2].p = argp;

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_replenish(rpc_queue *queue, void *sock)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_replenish_sendring);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].p = sock;

    return rpc_sync_call(queue, msg);
}

int32_t rpc_call_send(rpc_queue *queue, int fd, const void *buf, size_t len, int flags)
{
    struct rpc_msg *msg = rpc_msg_alloc(stack_send);
    if (msg == NULL) {
        return -1;
    }

    if (get_protocol_stack_group()->latency_start) {
        time_stamp_into_rpcmsg(msg);
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].size = len;
    msg->args[MSG_ARG_2].i = flags;
    msg->sync_flag = 0;

    rpc_call(queue, msg);

    return 0;
}

