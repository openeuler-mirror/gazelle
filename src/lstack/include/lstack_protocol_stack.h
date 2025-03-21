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

#ifndef __GAZELLE_PROTOCOL_STACK_H__
#define __GAZELLE_PROTOCOL_STACK_H__

#include <semaphore.h>
#include <stdbool.h>

#include <rte_ring.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <lwip/lwipgz_list.h>
#include <lwip/netif.h>

#include "common/gazelle_opt.h"
#include "common/gazelle_dfx_msg.h"
#include "lstack_thread_rpc.h"
#include "lstack_ethdev.h"
#include "lstack_tx_cache.h"

#define SOCK_RECV_RING_SIZE         (get_global_cfg_params()->recv_ring_size)
#define SOCK_RECV_RING_SIZE_MAX     (2048)
#define SOCK_SEND_RING_SIZE_MAX     (2048)

#define MBUFPOOL_RESERVE_NUM (2 * get_global_cfg_params()->rxqueue_size + 1024)

struct protocol_stack {
    uint32_t tid;
    uint16_t queue_id;
    uint16_t port_id;
    uint16_t numa_id;
    uint16_t cpu_id;
    uint32_t stack_idx;

    struct netif netif;
    struct lstack_dev_ops dev_ops;

    cpu_set_t idle_cpuset; /* idle cpu in numa of stack, app thread bind to it */

    volatile enum rte_lcore_state_t state;
    volatile bool low_power;
    volatile uint16_t conn_num;

    struct rte_mempool *rxtx_mbuf_pool;
    struct rte_ring *rx_ring;
    struct rte_ring *tx_ring;
    struct rte_ring *reg_ring;
    struct reg_ring_msg *reg_buf;
    uint32_t reg_head;

    uint32_t rx_ring_used;
    uint32_t tx_ring_used;
    struct rte_mbuf *pkts[NIC_QUEUE_SIZE_MAX];

    char pad1 __rte_cache_aligned;
    rpc_queue dfx_rpc_queue;
    rpc_queue rpc_queue;
    char pad2 __rte_cache_aligned;

    struct list_node recv_list;
    struct list_node same_node_recv_list; /* used for same node processes communication */

    struct stats_ *lwip_stats;
    struct gazelle_stack_latency latency;
    struct gazelle_stack_stat stats;
    struct gazelle_stack_aggregate_stats aggregate_stats;
};

struct eth_params;
struct protocol_stack_group {
    uint16_t stack_num;
    uint16_t port_id;
    uint64_t rx_offload;
    uint64_t tx_offload;
    struct rte_mempool *kni_pktmbuf_pool;
    struct eth_params *eth_params;
    struct protocol_stack *stacks[PROTOCOL_STACK_MAX];

    sem_t sem_listen_thread;
    struct rte_mempool *total_rxtx_pktmbuf_pool[PROTOCOL_STACK_MAX];
    sem_t sem_stack_setup;
    bool stack_setup_fail;

    /* dfx stats */
    bool latency_start;
    uint64_t call_alloc_fail;
    pthread_spinlock_t socket_lock;
};

struct thread_params {
    uint16_t queue_id;
    uint16_t idx;
};

struct protocol_stack_group *get_protocol_stack_group(void);

extern PER_THREAD struct protocol_stack *g_stack_p;
static inline struct protocol_stack *get_protocol_stack(void)
{
    return g_stack_p;
}
struct protocol_stack *get_protocol_stack_by_id(int stack_id);
struct protocol_stack *get_bind_protocol_stack(void);

#if GAZELLE_TCP_REUSE_IPPORT
int get_min_conn_stack(struct protocol_stack_group *stack_group);
#endif /* GAZELLE_TCP_REUSE_IPPORT */
void bind_to_stack_numa(int stack_id);
void thread_bind_stack(int stack_id);

int stack_group_init(void);
void stack_group_exit(void);
void stack_exit(void);
void stack_wait(void);

int stack_setup_thread(void);
int stack_setup_app_thread(void);

int stack_polling(unsigned wakeup_tick);

enum rte_lcore_state_t stack_get_state(struct protocol_stack *stack);

#endif
