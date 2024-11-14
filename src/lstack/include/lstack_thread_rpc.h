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
#include "lstack_interrupt.h"

#define MSG_ARG_0                      (0)
#define MSG_ARG_1                      (1)
#define MSG_ARG_2                      (2)
#define MSG_ARG_3                      (3)
#define MSG_ARG_4                      (4)
#define RPM_MSG_ARG_SIZE               (5)

#define RPC_MEMPOOL_THREAD_NUM         64

typedef struct rpc_queue rpc_queue;
struct rpc_queue {
    struct lockless_queue queue;
    uint16_t queue_id;
};

struct rpc_stats {
    uint16_t call_null;
    uint64_t call_alloc_fail;
};

union rpc_msg_arg {
    int i;
    unsigned int u;
    long l;
    unsigned long ul;
    void *p;
    const void *cp;
    size_t size;
};

struct rpc_msg;
typedef void (*rpc_func_t)(struct rpc_msg *msg);
struct rpc_msg {
    int8_t sync_flag : 1;
    int8_t recall_flag : 1;

    long result; /* func return val */
    rpc_func_t func; /* msg handle func hook */
    union rpc_msg_arg args[RPM_MSG_ARG_SIZE]; /* resolve by type */

    struct rpc_msg_pool {
        struct rte_mempool *mempool;
    } *rpcpool;

    pthread_spinlock_t lock; /* msg handler unlock notice sender msg process done */
    lockless_queue_node queue_node;
};

static inline void rpc_queue_init(rpc_queue *queue, uint16_t queue_id)
{
    lockless_queue_init(&queue->queue);
    queue->queue_id = queue_id;
}
struct rpc_stats *rpc_stats_get(void);
int rpc_msgcnt(rpc_queue *queue);
int rpc_poll_msg(rpc_queue *queue, int max_num);

int rpc_call_stack_exit(rpc_queue *queue);

/* #include <sys/socket.h> will conflict with lwip/sockets.h */
struct sockaddr;

int rpc_call_close(rpc_queue *queue, int fd);
int rpc_call_shutdown(rpc_queue *queue, int fd, int how);
int rpc_call_socket(rpc_queue *queue, int domain, int type, int protocol);
int rpc_call_bind(rpc_queue *queue, int fd, const struct sockaddr *addr, socklen_t addrlen);
int rpc_call_listen(rpc_queue *queue, int s, int backlog);
int rpc_call_shadow_fd(rpc_queue *queue, int fd, const struct sockaddr *addr, socklen_t addrlen);
int rpc_call_accept(rpc_queue *queue, int fd, struct sockaddr *addr, socklen_t *addrlen, int flags);
int rpc_call_connect(rpc_queue *queue, int fd, const struct sockaddr *addr, socklen_t addrlen);

int rpc_call_getpeername(rpc_queue *queue, int fd, struct sockaddr *addr, socklen_t *addrlen);
int rpc_call_getsockname(rpc_queue *queue, int fd, struct sockaddr *addr, socklen_t *addrlen);
int rpc_call_getsockopt(rpc_queue *queue, int fd, int level, int optname, void *optval, socklen_t *optlen);
int rpc_call_setsockopt(rpc_queue *queue, int fd, int level, int optname, const void *optval, socklen_t optlen);

int rpc_call_tcp_send(rpc_queue *queue, int fd, size_t len, int flags);
int rpc_call_udp_send(rpc_queue *queue, int fd, size_t len, int flags);

int rpc_call_replenish(rpc_queue *queue, void *sock);
int rpc_call_recvlistcnt(rpc_queue *queue);

int rpc_call_clean_epoll(rpc_queue *queue, void *wakeup);
int rpc_call_arp(rpc_queue *queue, void *mbuf);

int rpc_call_conntable(rpc_queue *queue, void *conn_table, unsigned max_conn);
int rpc_call_connnum(rpc_queue *queue);
int rpc_call_mbufpoolsize(rpc_queue *queue);

int rpc_call_thread_regphase1(rpc_queue *queue, void *conn);
int rpc_call_thread_regphase2(rpc_queue *queue, void *conn);

#endif
