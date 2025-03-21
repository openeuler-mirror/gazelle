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

typedef struct rpc_queue rpc_queue;
struct rpc_queue {
    struct lockless_queue queue;
    uint16_t queue_id;
};

struct rpc_stats {
    uint16_t call_null;
    uint64_t call_alloc_fail;
};
struct rpc_stats *rpc_stats_get(void);

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
#define RPC_MSG_SYNC    0x01
#define RPC_MSG_FREE    0x02
#define RPC_MSG_EXIT    0x04
#define RPC_MSG_RECALL  0x08
#define RPC_MSG_REUSE   0x10
    int flags;
    int stack_id; /* the stack to which buf belongs */

    long result; /* func return val */
    rpc_func_t func; /* msg handle func hook */
    union rpc_msg_arg args[RPM_MSG_ARG_SIZE]; /* resolve by type */

    pthread_spinlock_t lock; /* msg handler unlock notice sender msg process done */
    lockless_queue_node queue_node;
};

struct rpc_msg *rpc_msg_alloc(int stack_id, rpc_func_t func);
void rpc_msg_free(struct rpc_msg *msg);

void rpc_queue_init(rpc_queue *queue, uint16_t queue_id);
int rpc_msgcnt(rpc_queue *queue);
int rpc_poll_msg(rpc_queue *queue, int max_num);

int rpc_sync_call(rpc_queue *queue, struct rpc_msg *msg);
void rpc_async_call(rpc_queue *queue, struct rpc_msg *msg, int flags);

int rpc_call_conntable(int stack_id, void *conn_table, unsigned max_conn);
int rpc_call_connnum(int stack_id);
int rpc_call_arp(int stack_id, void *mbuf);

#endif
