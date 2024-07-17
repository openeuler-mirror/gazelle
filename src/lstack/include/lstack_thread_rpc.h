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

#ifndef __GAZELLE_THREAD_RPC_H__
#define __GAZELLE_THREAD_RPC_H__

#include <pthread.h>
#include <rte_mempool.h>

#include "lstack_lockless_queue.h"

#define MSG_ARG_0                      (0)
#define MSG_ARG_1                      (1)
#define MSG_ARG_2                      (2)
#define MSG_ARG_3                      (3)
#define MSG_ARG_4                      (4)
#define RPM_MSG_ARG_SIZE               (5)

#define GAZELLE_MEMPOOL_MAX_NAME       26

typedef struct lockless_queue rpc_queue;

struct rpc_stats {
    uint16_t call_null;
    uint64_t call_alloc_fail;
};

struct rpc_msg;
typedef void (*rpc_msg_func)(struct rpc_msg *msg);
union rpc_msg_arg {
    int32_t i;
    uint32_t u;
    long l;
    unsigned long ul;
    void *p;
    const void *cp;
    socklen_t socklen;
    size_t size;
};
struct rpc_msg_pool {
    struct rte_mempool *mempool;
};

struct rpc_mempool_info {
    char name[GAZELLE_MEMPOOL_MAX_NAME];
    uint32_t size;
    uint32_t obj_total;
    uint32_t obj_size;
    uint32_t remain_size;
};

struct rpc_msg {
    pthread_spinlock_t lock; /* msg handler unlock notice sender msg process done */
    int8_t sync_flag : 1;
    int8_t recall_flag : 1;
    int64_t result; /* func return val */
    int64_t errno_code;
    lockless_queue_node queue_node;
    struct rpc_msg_pool *rpcpool;

    rpc_msg_func func; /* msg handle func hook */
    union rpc_msg_arg args[RPM_MSG_ARG_SIZE]; /* resolve by type */
};

static inline void rpc_queue_init(rpc_queue *queue)
{
    lockless_queue_init(queue);
}

struct rpc_stats *rpc_stats_get(void);
struct rte_mempool *rpc_pool_get(void);
int32_t rpc_msgcnt(rpc_queue *queue);
int rpc_poll_msg(rpc_queue *queue, uint32_t max_num);
void rpc_call_clean_epoll(rpc_queue *queue, void *wakeup);
int32_t rpc_call_shadow_fd(rpc_queue *queue, int32_t fd, const struct sockaddr *addr, socklen_t addrlen);
int32_t rpc_call_recvlistcnt(rpc_queue *queue);
int32_t rpc_call_thread_regphase1(rpc_queue *queue, void *conn);
int32_t rpc_call_thread_regphase2(rpc_queue *queue, void *conn);
int32_t rpc_call_conntable(rpc_queue *queue, void *conn_table, uint32_t max_conn);
int32_t rpc_call_connnum(rpc_queue *queue);
int32_t rpc_call_arp(rpc_queue *queue, void *mbuf);
int32_t rpc_call_socket(rpc_queue *queue, int32_t domain, int32_t type, int32_t protocol);
int32_t rpc_call_close(rpc_queue *queue, int32_t fd);
int32_t rpc_call_shutdown(rpc_queue *queue, int fd, int how);
int32_t rpc_call_bind(rpc_queue *queue, int32_t fd, const struct sockaddr *addr, socklen_t addrlen);
int32_t rpc_call_listen(rpc_queue *queue, int s, int backlog);
int32_t rpc_call_accept(rpc_queue *queue, int fd, struct sockaddr *addr, socklen_t *addrlen, int flags);
int32_t rpc_call_connect(rpc_queue *queue, int fd, const struct sockaddr *addr, socklen_t addrlen);
int32_t rpc_call_tcp_send(rpc_queue *queue, int fd, size_t len, int flags);
int32_t rpc_call_udp_send(rpc_queue *queue, int fd, size_t len, int flags);
int32_t rpc_call_getpeername(rpc_queue *queue, int fd, struct sockaddr *addr, socklen_t *addrlen);
int32_t rpc_call_getsockname(rpc_queue *queue, int fd, struct sockaddr *addr, socklen_t *addrlen);
int32_t rpc_call_getsockopt(rpc_queue *queue, int fd, int level, int optname, void *optval, socklen_t *optlen);
int32_t rpc_call_setsockopt(rpc_queue *queue, int fd, int level, int optname, const void *optval, socklen_t optlen);
int32_t rpc_call_fcntl(rpc_queue *queue, int fd, int cmd, long val);
int32_t rpc_call_ioctl(rpc_queue *queue, int fd, long cmd, void *argp);
int32_t rpc_call_replenish(rpc_queue *queue, void *sock);
int32_t rpc_call_mbufpoolsize(rpc_queue *queue);
int32_t rpc_call_stack_exit(rpc_queue *queue);
int32_t rpc_call_lstack_mem(rpc_queue* queue, void* memory);

static inline __attribute__((always_inline)) void rpc_call(rpc_queue *queue, struct rpc_msg *msg)
{
    lockless_queue_mpsc_push(queue, &msg->queue_node);
}

static inline __attribute__((always_inline)) void rpc_msg_free(struct rpc_msg *msg)
{
    pthread_spin_destroy(&msg->lock);
    if (msg->rpcpool != NULL && msg->rpcpool->mempool != NULL) {
        rte_mempool_put(msg->rpcpool->mempool, (void *)msg);
    } else {
        free(msg);
    }
}

#endif
