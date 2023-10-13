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
#include <sys/epoll.h>
#include <stdbool.h>

#include <lwip/list.h>
#include <lwip/netif.h>

#include "gazelle_dfx_msg.h"
#include "lstack_lockless_queue.h"
#include "lstack_ethdev.h"
#include "gazelle_opt.h"

#define SOCK_RECV_RING_SIZE         (128)
#define SOCK_RECV_FREE_THRES        (32)
#define SOCK_SEND_RING_SIZE_MAX     (2048)
#define SOCK_SEND_REPLENISH_THRES   (16)
#define WAKEUP_MAX_NUM              (32)

struct rte_mempool;
struct rte_ring;
struct rte_mbuf;

struct protocol_stack {
    uint32_t tid;
    uint16_t queue_id;
    uint16_t port_id;
    uint16_t socket_id;
    uint16_t cpu_id;
    uint32_t stack_idx;
    cpu_set_t idle_cpuset; /* idle cpu in numa of stack, app thread bind to it */
    int32_t epollfd; /* kernel event thread epoll fd */

    struct rte_mempool *rxtx_pktmbuf_pool;
    struct rte_ring  *rx_ring;
    struct rte_ring *tx_ring;
    struct rte_ring *reg_ring;
    struct rte_ring *wakeup_ring;
    struct reg_ring_msg *reg_buf;
    uint32_t reg_head;

    volatile bool low_power;
    bool is_send_thread;

    lockless_queue rpc_queue __rte_cache_aligned;
    char pad __rte_cache_aligned;

    /* kernel event thread read/write frequently */
    struct epoll_event kernel_events[KERNEL_EPOLL_MAX];
    int32_t kernel_event_num;
    char pad1 __rte_cache_aligned;

    struct netif netif;
    struct lstack_dev_ops dev_ops;
    uint32_t rx_ring_used;
    uint32_t tx_ring_used;

    struct rte_mbuf *pkts[NIC_QUEUE_SIZE_MAX];
    struct list_node recv_list;
    struct list_node same_node_recv_list; /* used for same node processes communication */
    struct list_node wakeup_list;

    volatile uint16_t conn_num;
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
    uint32_t reta_mask;
    uint16_t nb_queues;
    struct rte_mempool *kni_pktmbuf_pool;
    struct eth_params *eth_params;
    struct protocol_stack *stacks[PROTOCOL_STACK_MAX];
    struct list_node  poll_list;
    pthread_spinlock_t poll_list_lock;
    sem_t sem_listen_thread;
    struct rte_mempool *total_rxtx_pktmbuf_pool[PROTOCOL_STACK_MAX];

    /* dfx stats */
    bool latency_start;
    uint64_t call_alloc_fail;
    pthread_spinlock_t socket_lock;
};

long get_stack_tid(void);
struct protocol_stack *get_protocol_stack(void);
struct protocol_stack *get_protocol_stack_by_fd(int32_t fd);
struct protocol_stack *get_bind_protocol_stack(void);
struct protocol_stack_group *get_protocol_stack_group(void);

int32_t stack_group_init(void);
int32_t stack_thread_setup(void);

void bind_to_stack_numa(struct protocol_stack *stack);
int32_t init_dpdk_ethdev(void);

void wait_sem_value(sem_t *sem, int32_t wait_value);

/* any protocol stack thread receives arp packet and sync it to other threads so that it can have the arp table */
void stack_broadcast_arp(struct rte_mbuf *mbuf, struct protocol_stack *cur_stack);

/* when fd is listenfd, listenfd of all protocol stack thread will be closed */
int32_t stack_broadcast_close(int32_t fd);

/* listen sync to all protocol stack thread, so that any protocol stack thread can build connect */
int32_t stack_broadcast_listen(int32_t fd, int backlog);
int32_t stack_single_listen(int32_t fd, int32_t backlog);

/* bind sync to all protocol stack thread, only for udp protocol */
int32_t stack_broadcast_bind(int32_t fd, const struct sockaddr *name, socklen_t namelen);
int32_t stack_single_bind(int32_t fd, const struct sockaddr *name, socklen_t namelen);

/* ergodic the protocol stack thread to find the connection, because all threads are listening */
int32_t stack_broadcast_accept(int32_t fd, struct sockaddr *addr, socklen_t *addrlen);
int32_t stack_broadcast_accept4(int32_t fd, struct sockaddr *addr, socklen_t *addrlen, int32_t flags);

struct wakeup_poll;
void stack_broadcast_clean_epoll(struct wakeup_poll *wakeup);

void stack_send_pkts(struct protocol_stack *stack);

struct rpc_msg;
struct thread_params {
    uint16_t queue_id;
    uint16_t idx;
};
void stack_clean_epoll(struct rpc_msg *msg);
void stack_arp(struct rpc_msg *msg);
void stack_socket(struct rpc_msg *msg);
void stack_close(struct rpc_msg *msg);
void stack_bind(struct rpc_msg *msg);
void stack_listen(struct rpc_msg *msg);
void stack_accept(struct rpc_msg *msg);
void stack_connect(struct rpc_msg *msg);
void stack_recv(struct rpc_msg *msg);
void stack_getpeername(struct rpc_msg *msg);
void stack_getsockname(struct rpc_msg *msg);
void stack_getsockopt(struct rpc_msg *msg);
void stack_setsockopt(struct rpc_msg *msg);
void stack_fcntl(struct rpc_msg *msg);
void stack_ioctl(struct rpc_msg *msg);
void stack_send(struct rpc_msg *msg);
void stack_mempool_size(struct rpc_msg *msg);
void stack_create_shadow_fd(struct rpc_msg *msg);
void stack_replenish_sendring(struct rpc_msg *msg);
void stack_get_conntable(struct rpc_msg *msg);
void stack_get_connnum(struct rpc_msg *msg);
void stack_recvlist_count(struct rpc_msg *msg);
void kni_handle_tx(struct rte_mbuf *mbuf);
#endif
