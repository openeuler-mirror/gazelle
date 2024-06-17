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
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>

#include <lwip/sockets.h>
#include <lwip/tcpip.h>
#include <lwip/tcp.h>
#include <lwip/memp_def.h>
#include <lwipsock.h>
#include <lwip/posix_api.h>
#include <securec.h>
#include <numa.h>

#include "gazelle_base_func.h"
#include "lstack_thread_rpc.h"
#include "dpdk_common.h"
#include "lstack_log.h"
#include "lstack_dpdk.h"
#include "lstack_ethdev.h"
#include "lstack_vdev.h"
#include "lstack_lwip.h"
#include "lstack_cfg.h"
#include "lstack_control_plane.h"
#include "posix/lstack_epoll.h"
#include "lstack_stack_stat.h"
#include "lstack_protocol_stack.h"

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
#include <rte_kni.h>
#endif

#define KERNEL_EVENT_10us               10

static PER_THREAD struct protocol_stack *g_stack_p = NULL;
static struct protocol_stack_group g_stack_group = {0};

typedef void *(*stack_thread_func)(void *arg);

static void stack_set_state(struct protocol_stack *stack, enum rte_lcore_state_t state)
{
    __atomic_store_n(&stack->state, state, __ATOMIC_RELEASE);
}

static enum rte_lcore_state_t stack_get_state(struct protocol_stack *stack)
{
    return __atomic_load_n(&stack->state, __ATOMIC_ACQUIRE);
}

static void stack_wait_quit(struct protocol_stack *stack)
{
    while (__atomic_load_n(&stack->state, __ATOMIC_ACQUIRE) != WAIT) {
        rte_pause();
    }
}

void bind_to_stack_numa(struct protocol_stack *stack)
{
    int32_t ret;
    pthread_t tid = pthread_self();

    ret = pthread_setaffinity_np(tid, sizeof(stack->idle_cpuset), &stack->idle_cpuset);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "thread %d setaffinity to stack %hu failed\n", rte_gettid(), stack->queue_id);
        return;
    }
}

static inline void set_stack_idx(uint16_t idx)
{
    g_stack_p = g_stack_group.stacks[idx];
}

long get_stack_tid(void)
{
    static PER_THREAD int32_t g_stack_tid = 0;

    if (g_stack_tid == 0) {
        g_stack_tid = rte_gettid();
    }

    return g_stack_tid;
}

struct protocol_stack_group *get_protocol_stack_group(void)
{
    return &g_stack_group;
}

int get_min_conn_stack(struct protocol_stack_group *stack_group)
{
    int min_conn_stk_idx = 0;
    int min_conn_num = GAZELLE_MAX_CLIENTS;
    for (int i = 0; i < stack_group->stack_num; i++) {
        struct protocol_stack* stack = stack_group->stacks[i];
        if (get_global_cfg_params()->seperate_send_recv) {
            if (!stack->is_send_thread && stack->conn_num < min_conn_num) {
                min_conn_stk_idx = i;
                min_conn_num = stack->conn_num;
            }
        } else {
            if (stack->conn_num < min_conn_num) {
                min_conn_stk_idx = i;
                min_conn_num = stack->conn_num;
            }
        }
    }
    return min_conn_stk_idx;
}

struct protocol_stack *get_protocol_stack(void)
{
    return g_stack_p;
}

struct protocol_stack *get_protocol_stack_by_fd(int32_t fd)
{
    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        return NULL;
    }

    return sock->stack;
}

struct protocol_stack *get_bind_protocol_stack(void)
{
    static PER_THREAD struct protocol_stack *bind_stack = NULL;

    /* same app communication thread bind same stack */
    if (bind_stack) {
        bind_stack->conn_num++;
        return bind_stack;
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    uint16_t index = 0;
    int min_conn_num = GAZELLE_MAX_CLIENTS;

    /* close listen shadow, per app communication thread select only one stack */
    if (!get_global_cfg_params()->tuple_filter && !get_global_cfg_params()->listen_shadow) {
        static _Atomic uint16_t stack_index = 0;
        index = atomic_fetch_add(&stack_index, 1);
        if (index >= stack_group->stack_num) {
            LSTACK_LOG(ERR, LSTACK, "thread =%hu larger than stack num = %hu\n", index, stack_group->stack_num);
            return NULL;
        }
    } else {
        pthread_spin_lock(&stack_group->socket_lock);
        for (uint16_t i = 0; i < stack_group->stack_num; i++) {
            struct protocol_stack* stack = stack_group->stacks[i];
            if (get_global_cfg_params()->seperate_send_recv) {
                if (stack->is_send_thread && stack->conn_num < min_conn_num) {
                    index = i;
                    min_conn_num = stack->conn_num;
                }
            } else {
                if (stack->conn_num < min_conn_num) {
                    index = i;
                    min_conn_num = stack->conn_num;
                }
            }
        }
    }

    stack_group->stacks[index]->conn_num++;
    bind_stack = stack_group->stacks[index];
    pthread_spin_unlock(&stack_group->socket_lock);
    return stack_group->stacks[index];
}

static uint32_t get_protocol_traffic(struct protocol_stack *stack)
{
    if (use_ltran()) {
        return rte_ring_count(stack->rx_ring) + rte_ring_count(stack->tx_ring);
    }

    /* only lstack mode, have not appropriate method to get traffic */
    return LSTACK_LPM_RX_PKTS + 1;
}

void low_power_idling(struct protocol_stack *stack)
{
    static PER_THREAD uint32_t last_cycle_ts = 0;
    static PER_THREAD uint64_t last_cycle_pkts = 0;
    struct timespec st = {
        .tv_sec = 0,
        .tv_nsec = 1
    };

    /* CPU delegation strategy in idling scenarios:
        1. In the detection period, if the number of received packets is less than the threshold,
        set the CPU decentralization flag;
        2. If the number of received packets exceeds the threshold, the authorization mark will end;
        3. If the number of rx queue packets is less than the threshold, set the CPU delegation flag; */
    if (get_protocol_traffic(stack) < LSTACK_LPM_RX_PKTS) {
        nanosleep(&st, NULL);
        stack->low_power = true;
        return;
    }

    if (last_cycle_ts == 0) {
        last_cycle_ts = sys_now();
    }

    uint64_t now_pkts = stack->stats.rx;
    uint32_t now_ts = sys_now();
    if (((now_ts - last_cycle_ts) > LSTACK_LPM_DETECT_MS) ||
        ((now_pkts - last_cycle_pkts) >= LSTACK_LPM_PKTS_IN_DETECT)) {
        if ((now_pkts - last_cycle_pkts) < LSTACK_LPM_PKTS_IN_DETECT) {
            stack->low_power = true;
        } else {
            stack->low_power = false;
        }

        last_cycle_ts = now_ts;
        last_cycle_pkts = now_pkts;
    }

    if (stack->low_power) {
        nanosleep(&st, NULL);
    }
}

static int32_t create_thread(void *arg, char *thread_name, stack_thread_func func)
{
    /* thread may run slow, if arg is temp var maybe have relese */
    char name[PATH_MAX];
    pthread_t tid;
    int32_t ret;
    struct thread_params *t_params = (struct thread_params*) arg;

    if (t_params->queue_id >= PROTOCOL_STACK_MAX) {
        LSTACK_LOG(ERR, LSTACK, "queue_id is %hu exceed max=%d\n", t_params->queue_id, PROTOCOL_STACK_MAX);
        return -1;
    }

    if (get_global_cfg_params()->seperate_send_recv) {
        ret = sprintf_s(name, sizeof(name), "%s", thread_name);
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "set name failed\n");
            return -1;
        }
    } else {
        ret = sprintf_s(name, sizeof(name), "%s%02hu", thread_name, t_params->queue_id);
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "set name failed\n");
            return -1;
        }
    }

    ret = pthread_create(&tid, NULL, func, arg);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "pthread_create ret=%d\n", ret);
        return -1;
    }

    ret = pthread_setname_np(tid, name);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "pthread_setname_np name=%s ret=%d errno=%d\n", name, ret, errno);
        return -1;
    }

    return 0;
}

static void wakeup_kernel_event(struct protocol_stack *stack)
{
    if (stack->kernel_event_num <= 0) {
        return;
    }

    for (int32_t i = 0; i < stack->kernel_event_num; i++) {
        struct wakeup_poll *wakeup = stack->kernel_events[i].data.ptr;
        if (wakeup->type == WAKEUP_CLOSE) {
            continue;
        }

        __atomic_store_n(&wakeup->have_kernel_event, true, __ATOMIC_RELEASE);
        lstack_block_wakeup(wakeup);
    }

    return;
}

static void* gazelle_kernelevent_thread(void *arg)
{
    struct thread_params *t_params = (struct thread_params*) arg;
    uint16_t idx = t_params->idx;
    struct protocol_stack *stack = get_protocol_stack_group()->stacks[idx];

    bind_to_stack_numa(stack);

    LSTACK_LOG(INFO, LSTACK, "kernelevent_%02hu start\n", idx);
    free(arg);
    sem_post(&g_stack_group.sem_stack_setup);

    for (;;) {
        stack->kernel_event_num = posix_api->epoll_wait_fn(stack->epollfd, stack->kernel_events, KERNEL_EPOLL_MAX, -1);
        if (stack->kernel_event_num > 0) {
            wakeup_kernel_event(stack);
            usleep(KERNEL_EVENT_10us);
        }
    }

    return NULL;
}

static int32_t init_stack_value(struct protocol_stack *stack, void *arg)
{
    struct thread_params *t_params = (struct thread_params*) arg;
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    stack->tid = rte_gettid();
    stack->queue_id = t_params->queue_id;
    stack->port_id = stack_group->port_id;
    stack->stack_idx = t_params->idx;
    stack->lwip_stats = &lwip_stats;

    init_list_node(&stack->recv_list);
    init_list_node(&stack->same_node_recv_list);
    init_list_node(&stack->wakeup_list);

    sys_calibrate_tsc();
    stack_stat_init();

    stack_group->stacks[t_params->idx] = stack;
    set_stack_idx(t_params->idx);

    stack->epollfd = posix_api->epoll_create_fn(GAZELLE_LSTACK_MAX_CONN);
    if (stack->epollfd < 0) {
        LSTACK_LOG(ERR, LSTACK, "kernel epoll_create failed\n");
        return -1;
    }

    int idx = t_params->idx;
    if (get_global_cfg_params()->seperate_send_recv) {
        // 2: idx is even, stack is recv thread, idx is odd, stack is send thread
        if (idx % 2 == 0) {
            stack->cpu_id = get_global_cfg_params()->recv_cpus[idx / 2];
            stack->is_send_thread = 0;
        } else {
            stack->cpu_id = get_global_cfg_params()->send_cpus[idx / 2];
            stack->is_send_thread = 1;
        }
    } else {
        stack->cpu_id = get_global_cfg_params()->cpus[idx];
    }

    stack->socket_id = numa_node_of_cpu(stack->cpu_id);
    if (stack->socket_id < 0) {
        LSTACK_LOG(ERR, LSTACK, "numa_node_of_cpu failed\n");
        return -1;
    }

    if (pktmbuf_pool_init(stack) != 0) {
        LSTACK_LOG(ERR, LSTACK, "pktmbuf_pool_init failed\n");
        return -1;
    }

    if (create_shared_ring(stack) != 0) {
        LSTACK_LOG(ERR, LSTACK, "create_shared_ring failed\n");
        return -1;
    }

    return 0;
}

void wait_sem_value(sem_t *sem, int32_t wait_value)
{
    int32_t sem_val;
    do {
        sem_getvalue(sem, &sem_val);
    } while (sem_val < wait_value);
}

static int32_t create_affiliate_thread(void *arg)
{
    struct thread_params *params = malloc(sizeof(struct thread_params));
    if (params == NULL) {
        return -1;
    }
    memcpy_s(params, sizeof(*params), arg, sizeof(struct thread_params));
    if (create_thread((void *)params, "gazellekernel", gazelle_kernelevent_thread) != 0) {
        LSTACK_LOG(ERR, LSTACK, "gazellekernel errno=%d\n", errno);
        return -1;
    }

    return 0;
}

static struct protocol_stack *stack_thread_init(void *arg)
{
    struct protocol_stack *stack = calloc(1, sizeof(*stack));
    if (stack == NULL) {
        LSTACK_LOG(ERR, LSTACK, "malloc stack failed\n");
        goto END;
    }

    if (init_stack_value(stack, arg) != 0) {
        goto END;
    }

    if (init_stack_numa_cpuset(stack) < 0) {
        goto END;
    }
    if (create_affiliate_thread(arg) < 0) {
        goto END;
    }

    if (thread_affinity_init(stack->cpu_id) != 0) {
        goto END;
    }
    RTE_PER_LCORE(_lcore_id) = stack->cpu_id;

    if (hugepage_init() != 0) {
        LSTACK_LOG(ERR, LSTACK, "hugepage init failed\n");
        goto END;
    }

    tcpip_init(NULL, NULL);

    if (use_ltran()) {
        if (client_reg_thrd_ring() != 0) {
            goto END;
        }
    }

    usleep(SLEEP_US_BEFORE_LINK_UP);

    if (ethdev_init(stack) != 0) {
        goto END;
    }

    return stack;
END:
    if (stack != NULL) {
        free(stack);
    }
    return NULL;
}

int stack_polling(uint32_t wakeup_tick)
{
    int force_quit;
    struct cfg_params *cfg = get_global_cfg_params();
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
    bool kni_switch = cfg->kni_switch;
#endif
    bool use_sockmap = cfg->use_sockmap;
    bool stack_mode_rtc = cfg->stack_mode_rtc;
    uint32_t rpc_number = cfg->rpc_number;
    uint32_t read_connect_number = cfg->read_connect_number;
    struct protocol_stack *stack = get_protocol_stack();

    /* 2: one dfx consumes two rpc */
    rpc_poll_msg(&stack->dfx_rpc_queue, 2);
    force_quit = rpc_poll_msg(&stack->rpc_queue, rpc_number);

    eth_dev_poll();
    sys_timer_run();
    if (cfg->low_power_mod != 0) {
        low_power_idling(stack);
    }

    if (stack_mode_rtc) {
        return force_quit;
    }

    do_lwip_read_recvlist(stack, read_connect_number);
    if ((wakeup_tick & 0xf) == 0) {
        wakeup_stack_epoll(stack);
        stack_send_pkts(stack);
    }

    /* run to completion mode currently does not support sockmap */
    if (use_sockmap) {
        netif_poll(&stack->netif);
        /* reduce traversal times */
        if ((wakeup_tick & 0xff) == 0) {
            read_same_node_recv_list(stack);
        }
    }

    if (cfg->udp_enable) {
        udp_netif_poll(&stack->netif);
    }

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
    /* run to completion mode currently does not support kni */
    /* KNI requests are generally low-rate I/Os,
    * so processing KNI requests only in the thread with queue_id No.0 is sufficient. */
    if (kni_switch && !stack->queue_id && !(wakeup_tick & 0xfff)) {
        rte_kni_handle_request(get_gazelle_kni());
        if (get_kni_started()) {
            kni_handle_rx(stack->port_id);
        }
    }
#endif
    return force_quit;
}

static void* gazelle_stack_thread(void *arg)
{
    struct thread_params *t_params = (struct thread_params*) arg;

    uint16_t queue_id = t_params->queue_id;
    uint32_t wakeup_tick = 0;

    struct protocol_stack *stack = stack_thread_init(arg);

    free(arg);
    if (stack == NULL) {
        LSTACK_LOG(ERR, LSTACK, "stack_thread_init failed queue_id=%hu\n", queue_id);
        g_stack_group.stack_setup_fail = 1;
        sem_post(&g_stack_group.sem_stack_setup);
        return NULL;
    }
    sem_post(&g_stack_group.sem_stack_setup);

    LSTACK_LOG(INFO, LSTACK, "stack_%02hu init success\n", queue_id);
    if (get_global_cfg_params()->stack_mode_rtc) {
        return NULL;
    }

    stack_set_state(stack, RUNNING);

    while (stack_polling(wakeup_tick) == 0) {
        wakeup_tick++;
    }

    stack_set_state(stack, WAIT);

    return NULL;
}

int32_t stack_group_init_mempool(void)
{
    struct cfg_params *global_cfg_parmas = get_global_cfg_params();
    uint32_t total_mbufs = get_global_cfg_params()->mbuf_count_per_conn * get_global_cfg_params()->tcp_conn_count;
    struct rte_mempool *rxtx_mbuf = NULL;
    uint32_t cpu_id = 0;
    unsigned numa_id = 0;
    int queue_id = 0;

    LSTACK_LOG(INFO, LSTACK,
        "config::num_cpu=%d num_process=%d \n", global_cfg_parmas->num_cpu, global_cfg_parmas->num_process);
    
    for (int cpu_idx = 0; cpu_idx < get_global_cfg_params()->num_queue; cpu_idx++) {
        cpu_id = global_cfg_parmas->cpus[cpu_idx];
        numa_id = numa_node_of_cpu(cpu_id);
        
        for (int process_idx = 0; process_idx < global_cfg_parmas->num_process; process_idx++) {
            queue_id = cpu_idx * global_cfg_parmas->num_process + process_idx;
            if (queue_id >= PROTOCOL_STACK_MAX) {
                LSTACK_LOG(ERR, LSTACK, "index is over\n");
                return -1;
            }
            
            rxtx_mbuf = create_pktmbuf_mempool(
                "rxtx_mbuf", total_mbufs / get_global_cfg_params()->num_queue, RXTX_CACHE_SZ, queue_id, numa_id);
            if (rxtx_mbuf == NULL) {
                LSTACK_LOG(ERR, LSTACK, "cpuid=%u, numid=%d , rxtx_mbuf idx= %d create_pktmbuf_mempool fail\n",
                    cpu_id, numa_id, queue_id);
                return -1;
            }
            
            get_protocol_stack_group()->total_rxtx_pktmbuf_pool[queue_id] = rxtx_mbuf;
        }
    }

    return 0;
}

int32_t stack_group_init(void)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    stack_group->stack_num = 0;

    init_list_node(&stack_group->poll_list);
    pthread_spin_init(&stack_group->poll_list_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&stack_group->socket_lock, PTHREAD_PROCESS_PRIVATE);
    if (sem_init(&stack_group->sem_stack_setup, 0, 0) < 0) {
        LSTACK_LOG(ERR, LSTACK, "sem_init failed errno=%d\n", errno);
        return -1;
    }

    stack_group->stack_setup_fail = 0;

    if (get_global_cfg_params()->is_primary) {
        if (stack_group_init_mempool() != 0) {
            LSTACK_LOG(ERR, LSTACK, "stack group init mempool failed\n");
            return -1;
        }
    }

    return 0;
}

int32_t stack_setup_app_thread(void)
{
    static PER_THREAD int first_flags = 1;
    static _Atomic uint32_t queue_id = 0;

    if (likely(first_flags == 0)) {
        return 0;
    }
    first_flags=0;

    uint32_t cur_queue_id = atomic_fetch_add(&queue_id, 1);
    struct thread_params *t_params = malloc(sizeof(struct thread_params));
    if (t_params == NULL) {
        return -1;
    }
    t_params->idx = cur_queue_id;
    t_params->queue_id = cur_queue_id;

    if (stack_thread_init(t_params) == NULL) {
        LSTACK_LOG(INFO, LSTACK, "stack setup failed in app thread\n");
        free(t_params);
        return -1;
    }
    atomic_fetch_add(&g_stack_group.stack_num, 1);
    free(t_params);
    return 0;
}

int32_t stack_setup_thread(void)
{
    int32_t ret;
    char name[PATH_MAX];
    int queue_num = get_global_cfg_params()->num_queue;
    struct thread_params *t_params[PROTOCOL_STACK_MAX] = {NULL};
    int process_index = get_global_cfg_params()->process_idx;

    for (uint32_t i = 0; i < queue_num; ++i) {
        t_params[i] = malloc(sizeof(struct thread_params));
        if (t_params[i] == NULL) {
            goto OUT1;
        }
    }
    for (uint32_t i = 0; i < queue_num; i++) {
        if (get_global_cfg_params()->seperate_send_recv) {
            if (i % 2 == 0) {
                ret = sprintf_s(name, sizeof(name), "%s_%d_%d", LSTACK_RECV_THREAD_NAME, process_index, i / 2);
                if (ret < 0) {
                    goto OUT1;
                }
            } else {
                ret = sprintf_s(name, sizeof(name), "%s_%d_%d", LSTACK_SEND_THREAD_NAME, process_index, i / 2);
                if (ret < 0) {
                    goto OUT1;
                }
            }
        } else {
            ret = sprintf_s(name, sizeof(name), "%s", LSTACK_THREAD_NAME);
            if (ret < 0) {
                goto OUT1;
            }
        }

        t_params[i]->idx = i;
        t_params[i]->queue_id = process_index * queue_num + i;

        ret = create_thread((void *)t_params[i], name, gazelle_stack_thread);
        if (ret != 0) {
            goto OUT1;
        }
    }

    /* 2: wait stack thread and kernel_event thread init finish */
    wait_sem_value(&g_stack_group.sem_stack_setup, queue_num * 2);
    if (g_stack_group.stack_setup_fail) {
        /* t_params free by stack thread */
        goto OUT2;
    }
    g_stack_group.stack_num = queue_num;

    return 0;

OUT1:
    for (int32_t i = 0; i < queue_num; ++i) {
        if (t_params[i] != NULL) {
            free(t_params[i]);
        }
    }
OUT2:
    return -1;
}

void stack_arp(struct rpc_msg *msg)
{
    struct rte_mbuf *mbuf = (struct rte_mbuf *)msg->args[MSG_ARG_0].p;
    struct protocol_stack *stack = get_protocol_stack();

    eth_dev_recv(mbuf, stack);
}

void stack_socket(struct rpc_msg *msg)
{
    msg->result = do_lwip_socket(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i);
    if (msg->result < 0) {
        msg->result = do_lwip_socket(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i);
        if (msg->result < 0) {
            LSTACK_LOG(ERR, LSTACK, "tid %ld, %ld socket failed\n", get_stack_tid(), msg->result);
        }
    }
}

void stack_close(struct rpc_msg *msg)
{
    int32_t fd = msg->args[MSG_ARG_0].i;
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct lwip_sock *sock = get_socket(fd);
    
    if (sock && __atomic_load_n(&sock->call_num, __ATOMIC_ACQUIRE) > 0) {
        msg->recall_flag = 1;
        rpc_call(&stack->rpc_queue, msg); /* until stack_send recall finish */
        return;
    }
    
    msg->result = do_lwip_close(fd);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d failed %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

void stack_shutdown(struct rpc_msg *msg)
{
    int fd = msg->args[MSG_ARG_0].i;
    int how = msg->args[MSG_ARG_1].i;
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct lwip_sock *sock = get_socket(fd);

    if (sock && __atomic_load_n(&sock->call_num, __ATOMIC_ACQUIRE) > 0) {
        msg->recall_flag = 1;
        rpc_call(&stack->rpc_queue, msg);
        return;
    }

    msg->result = lwip_shutdown(fd, how);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d fail %ld\n", get_stack_tid(), fd, msg->result);
    }

    posix_api->shutdown_fn(fd, how);
}

void stack_bind(struct rpc_msg *msg)
{
    msg->result = lwip_bind(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].cp, msg->args[MSG_ARG_2].socklen);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d failed %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

void stack_listen(struct rpc_msg *msg)
{
    int32_t fd = msg->args[MSG_ARG_0].i;
    int32_t backlog = msg->args[MSG_ARG_1].i;

    struct lwip_sock *sock = get_socket_by_fd(fd);
    if (sock == NULL) {
        msg->result = -1;
        return;
    }

    /* new listen add to stack listen list */
    msg->result = lwip_listen(fd, backlog);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d failed %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

void stack_accept(struct rpc_msg *msg)
{
    int32_t fd = msg->args[MSG_ARG_0].i;
    msg->result = -1;
    struct protocol_stack *stack = get_protocol_stack();

    int32_t accept_fd = lwip_accept4(fd, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].p, msg->args[MSG_ARG_3].i);
    if (accept_fd < 0) {
        stack->stats.accept_fail++;
        LSTACK_LOG(ERR, LSTACK, "fd %d ret %d\n", fd, accept_fd);
        return;
    }

    struct lwip_sock *sock = get_socket(accept_fd);
    if (sock == NULL || sock->stack == NULL) {
        do_lwip_close(accept_fd);
        LSTACK_LOG(ERR, LSTACK, "fd %d ret %d\n", fd, accept_fd);
        return;
    }

    msg->result = accept_fd;
    sock->stack->conn_num++;
    if (rte_ring_count(sock->conn->recvmbox->ring)) {
        do_lwip_add_recvlist(accept_fd);
    }
}

void stack_connect(struct rpc_msg *msg)
{
    msg->result = lwip_connect(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].socklen);
    if (msg->result < 0) {
        msg->result = -errno;
    }
}

void stack_getpeername(struct rpc_msg *msg)
{
    msg->result = lwip_getpeername(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].p);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d fail %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

void stack_getsockname(struct rpc_msg *msg)
{
    msg->result = lwip_getsockname(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].p);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d fail %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

void stack_getsockopt(struct rpc_msg *msg)
{
    msg->result = lwip_getsockopt(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i,
        msg->args[MSG_ARG_3].p, msg->args[MSG_ARG_4].p);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d, level %d, optname %d, fail %ld\n", get_stack_tid(),
                   msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i, msg->result);
    }
}

void stack_setsockopt(struct rpc_msg *msg)
{
    msg->result = lwip_setsockopt(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i,
        msg->args[MSG_ARG_3].cp, msg->args[MSG_ARG_4].socklen);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d, level %d, optname %d, fail %ld\n", get_stack_tid(),
                   msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i, msg->result);
    }
}

void stack_fcntl(struct rpc_msg *msg)
{
    msg->result = lwip_fcntl(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].l);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d fail %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

void stack_ioctl(struct rpc_msg *msg)
{
    msg->result = lwip_ioctl(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].l, msg->args[MSG_ARG_2].p);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d fail %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

void stack_recv(struct rpc_msg *msg)
{
    msg->result = lwip_recv(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].size,
        msg->args[MSG_ARG_3].i);
}

void stack_send(struct rpc_msg *msg)
{
    int32_t fd = msg->args[MSG_ARG_0].i;
    size_t len = msg->args[MSG_ARG_1].size;
    struct protocol_stack *stack = get_protocol_stack();
    int replenish_again;

    if (get_protocol_stack_group()->latency_start) {
        calculate_rpcmsg_latency(&stack->latency, msg, GAZELLE_LATENCY_WRITE_RPC_MSG);
    }

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        msg->result = -1;
        LSTACK_LOG(ERR, LSTACK, "get sock error! fd=%d, len=%ld\n", fd, len);
        return;
    }

    replenish_again = do_lwip_send(stack, sock->conn->callback_arg.socket, sock, len, 0);
    if (replenish_again < 0) {
        __sync_fetch_and_sub(&sock->call_num, 1);
        return;
    }

    if (NETCONN_IS_DATAOUT(sock) || replenish_again > 0) {
        if (__atomic_load_n(&sock->call_num, __ATOMIC_ACQUIRE) == 1) {
            msg->recall_flag = 1;
            rpc_call(&stack->rpc_queue, msg);
            return;
        }
    }

    __sync_fetch_and_sub(&sock->call_num, 1);
    return;
}

/* any protocol stack thread receives arp packet and sync it to other threads so that it can have the arp table */
void stack_broadcast_arp(struct rte_mbuf *mbuf, struct protocol_stack *cur_stack)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    struct rte_mbuf *mbuf_copy = NULL;
    struct protocol_stack *stack = NULL;
    int32_t ret;

    for (int32_t i = 0; i < stack_group->stack_num; i++) {
        stack = stack_group->stacks[i];
        if (cur_stack == stack) {
            continue;
        }

        /* stack maybe not init in app thread yet */
        if (stack == NULL || !(netif_is_up(&stack->netif))) {
            continue;
        }

        ret = dpdk_alloc_pktmbuf(stack->rxtx_mbuf_pool, &mbuf_copy, 1, true);
        if (ret != 0) {
            stack->stats.rx_allocmbuf_fail++;
            return;
        }
        copy_mbuf(mbuf_copy, mbuf);

        ret = rpc_call_arp(&stack->rpc_queue, mbuf_copy);
        if (ret != 0) {
            rte_pktmbuf_free(mbuf_copy);
            return;
        }
    }
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
    ret = dpdk_alloc_pktmbuf(cur_stack->rxtx_mbuf_pool, &mbuf_copy, 1, true);
    if (ret != 0) {
        cur_stack->stats.rx_allocmbuf_fail++;
        return;
    }
    copy_mbuf(mbuf_copy, mbuf);
    kni_handle_tx(mbuf_copy);
#endif
    return;
}

void stack_broadcast_clean_epoll(struct wakeup_poll *wakeup)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    struct protocol_stack *stack = NULL;

    for (int32_t i = 0; i < stack_group->stack_num; i++) {
        stack = stack_group->stacks[i];
        rpc_call_clean_epoll(&stack->rpc_queue, wakeup);
    }
}

void stack_clean_epoll(struct rpc_msg *msg)
{
    struct protocol_stack *stack = get_protocol_stack();
    struct wakeup_poll *wakeup = (struct wakeup_poll *)msg->args[MSG_ARG_0].p;

    list_del_node_null(&wakeup->wakeup_list[stack->stack_idx]);
}

void stack_mempool_size(struct rpc_msg *msg)
{
    struct protocol_stack *stack = get_protocol_stack();

    msg->result = rte_mempool_avail_count(stack->rxtx_mbuf_pool);
}

void stack_create_shadow_fd(struct rpc_msg *msg)
{
    int32_t fd = msg->args[MSG_ARG_0].i;
    struct sockaddr *addr = msg->args[MSG_ARG_1].p;
    socklen_t addr_len = msg->args[MSG_ARG_2].socklen;

    int32_t clone_fd = 0;
    struct lwip_sock *sock = get_socket_by_fd(fd);
    if (sock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "get sock null fd=%d\n", fd);
        msg->result = -1;
        return;
    }

    int domain = addr->sa_family;
    if (NETCONN_IS_UDP(sock)) {
        clone_fd = do_lwip_socket(domain, SOCK_DGRAM, 0);
    } else {
        clone_fd = do_lwip_socket(domain, SOCK_STREAM, 0);
    }

    if (clone_fd < 0) {
        LSTACK_LOG(ERR, LSTACK, "clone socket failed clone_fd=%d errno=%d\n", clone_fd, errno);
        msg->result = clone_fd;
        return;
    }

    struct lwip_sock *clone_sock = get_socket_by_fd(clone_fd);
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

    int32_t ret = lwip_bind(clone_fd, addr, addr_len);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "clone bind failed clone_fd=%d errno=%d\n", clone_fd, errno);
        msg->result = ret;
        return;
    }

    msg->result = clone_fd;
}

void stack_replenish_sendring(struct rpc_msg *msg)
{
    struct protocol_stack *stack = get_protocol_stack();
    struct lwip_sock *sock = (struct lwip_sock *)msg->args[MSG_ARG_0].p;

    msg->result = do_lwip_replenish_sendring(stack, sock);
}

void stack_get_conntable(struct rpc_msg *msg)
{
    struct gazelle_stat_lstack_conn_info *conn = (struct gazelle_stat_lstack_conn_info *)msg->args[MSG_ARG_0].p;
    uint32_t max_num = msg->args[MSG_ARG_1].u;

    msg->result = do_lwip_get_conntable(conn, max_num);
}

void stack_get_connnum(struct rpc_msg *msg)
{
    msg->result = do_lwip_get_connnum();
}

void stack_recvlist_count(struct rpc_msg *msg)
{
    struct protocol_stack *stack = get_protocol_stack();
    struct list_node *list = &stack->recv_list;
    uint32_t count = 0;
    struct list_node *node;
    struct list_node *temp;

    list_for_each_safe(node, temp, list) {
        count++;
    }

    msg->result = count;
}

/* when fd is listenfd, listenfd of all protocol stack thread will be closed */
int32_t stack_broadcast_close(int32_t fd)
{
    int32_t ret = 0;
    struct lwip_sock *sock = get_socket(fd);
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }

    do {
        sock = sock->listen_next;
        if (stack == NULL || rpc_call_close(&stack->rpc_queue, fd)) {
            ret = -1;
        }

        if (sock == NULL || sock->conn == NULL) {
            break;
        }
        fd = sock->conn->callback_arg.socket;
        stack = get_protocol_stack_by_fd(fd);
    } while (1);

    return ret;
}

int stack_broadcast_shutdown(int fd, int how)
{
    int32_t ret = 0;
    struct lwip_sock *sock = get_socket(fd);
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }

    do {
        sock = sock->listen_next;
        if (stack == NULL || rpc_call_shutdown(&stack->rpc_queue, fd, how)) {
            ret = -1;
        }

        if (sock == NULL || sock->conn == NULL) {
            break;
        }
        fd = sock->conn->callback_arg.socket;
        stack = get_protocol_stack_by_fd(fd);
    } while (1);

    return ret;
}

/* choice one stack listen */
int32_t stack_single_listen(int32_t fd, int32_t backlog)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    if (stack == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    return rpc_call_listen(&stack->rpc_queue, fd, backlog);
}

/* listen sync to all protocol stack thread, so that any protocol stack thread can build connect */
int32_t stack_broadcast_listen(int32_t fd, int32_t backlog)
{
    typedef union sockaddr_union {
        struct sockaddr     sa;
        struct sockaddr_in  in;
        struct sockaddr_in6 in6;
    } sockaddr_t;

    struct protocol_stack *cur_stack = get_protocol_stack_by_fd(fd);
    struct protocol_stack *stack = NULL;
    sockaddr_t addr;
    socklen_t addr_len = sizeof(addr);
    int32_t ret, clone_fd;

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL || cur_stack == NULL) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, %d get sock null or stack null\n", get_stack_tid(), fd);
        GAZELLE_RETURN(EBADF);
    }

    ret = rpc_call_getsockname(&cur_stack->rpc_queue, fd, (struct sockaddr *)&addr, &addr_len);
    if (ret != 0) {
        return ret;
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    int min_conn_stk_idx = get_min_conn_stack(stack_group);

    for (int32_t i = 0; i < stack_group->stack_num; ++i) {
        stack = stack_group->stacks[i];
        if (get_global_cfg_params()->seperate_send_recv && stack->is_send_thread) {
            continue;
        }
        if (stack != cur_stack) {
            clone_fd = rpc_call_shadow_fd(&stack->rpc_queue, fd, (struct sockaddr *)&addr, addr_len);
            if (clone_fd < 0) {
                stack_broadcast_close(fd);
                return clone_fd;
            }
        } else {
            clone_fd = fd;
        }

        if (min_conn_stk_idx == i) {
            get_socket_by_fd(clone_fd)->conn->is_master_fd = 1;
        } else {
            get_socket_by_fd(clone_fd)->conn->is_master_fd = 0;
        }

        ret = rpc_call_listen(&stack->rpc_queue, clone_fd, backlog);
        if (ret < 0) {
            stack_broadcast_close(fd);
            return ret;
        }
    }
    return 0;
}

static struct lwip_sock *get_min_accept_sock(int32_t fd)
{
    struct lwip_sock *sock = get_socket(fd);
    struct lwip_sock *min_sock = NULL;

    while (sock) {
        if (!NETCONN_IS_ACCEPTIN(sock)) {
            sock = sock->listen_next;
            continue;
        }

        if (min_sock == NULL || min_sock->stack->conn_num > sock->stack->conn_num) {
            min_sock = sock;
        }

        sock = sock->listen_next;
    }

    return min_sock;
}

static void inline del_accept_in_event(struct lwip_sock *sock)
{
    pthread_spin_lock(&sock->wakeup->event_list_lock);

    if (!NETCONN_IS_ACCEPTIN(sock)) {
        sock->events &= ~EPOLLIN;
        if (sock->events == 0) {
            list_del_node_null(&sock->event_list);
        }
    }

    pthread_spin_unlock(&sock->wakeup->event_list_lock);
}

/* choice one stack bind */
int32_t stack_single_bind(int32_t fd, const struct sockaddr *name, socklen_t namelen)
{
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    if (stack == NULL) {
        GAZELLE_RETURN(EBADF);
    }
    return rpc_call_bind(&stack->rpc_queue, fd, name, namelen);
}

/* bind sync to all protocol stack thread, so that any protocol stack thread can build connect */
int32_t stack_broadcast_bind(int32_t fd, const struct sockaddr *name, socklen_t namelen)
{
    struct protocol_stack *cur_stack = get_protocol_stack_by_fd(fd);
    struct protocol_stack *stack = NULL;
    int32_t ret, clone_fd;

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL || cur_stack == NULL) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, %d get sock null or stack null\n", get_stack_tid(), fd);
        GAZELLE_RETURN(EBADF);
    }

    ret = rpc_call_bind(&cur_stack->rpc_queue, fd, name, namelen);
    if (ret < 0) {
        close(fd);
        return ret;
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    for (int32_t i = 0; i < stack_group->stack_num; ++i) {
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

/* ergodic the protocol stack thread to find the connection, because all threads are listening */
int32_t stack_broadcast_accept4(int32_t fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    int32_t ret = -1;
    struct lwip_sock *min_sock = NULL;
    struct lwip_sock *sock = get_socket(fd);
    struct protocol_stack *stack = NULL;
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }

    if (netconn_is_nonblocking(sock->conn)) {
        min_sock = get_min_accept_sock(fd);
    } else {
        while ((min_sock = get_min_accept_sock(fd)) == NULL) {
            lstack_block_wait(sock->wakeup, 0);
	}
    }

    if (min_sock && min_sock->conn) {
        stack = get_protocol_stack_by_fd(min_sock->conn->callback_arg.socket);
        if (stack == NULL) {
            GAZELLE_RETURN(EBADF);
        }
        ret = rpc_call_accept(&stack->rpc_queue, min_sock->conn->callback_arg.socket, addr, addrlen, flags);
    }

    if (min_sock && min_sock->wakeup && min_sock->wakeup->type == WAKEUP_EPOLL) {
        del_accept_in_event(min_sock);
    }

    if (ret < 0) {
        errno = EAGAIN;
    }
    return ret;
}

int32_t stack_broadcast_accept(int32_t fd, struct sockaddr *addr, socklen_t *addrlen)
{
    if (get_global_cfg_params()->nonblock_mode)
        return stack_broadcast_accept4(fd, addr, addrlen, O_NONBLOCK);
    else
        return stack_broadcast_accept4(fd, addr, addrlen, 0);
}

static void stack_all_fds_close(void)
{
    for (int i = 3; i < GAZELLE_MAX_CLIENTS + GAZELLE_RESERVED_CLIENTS; i++) {
        struct lwip_sock *sock = get_socket(i);
        if (sock && sock->stack == get_protocol_stack()) {
            do_lwip_close(i);
        }
    }
}

static void stack_exit(void)
{
    stack_all_fds_close();
}

void stack_exit_by_rpc(struct rpc_msg *msg)
{
    stack_exit();
}

void stack_group_exit(void)
{
    int i;
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    struct protocol_stack *stack = get_protocol_stack();

    for (i = 0; i < stack_group->stack_num; i++) {
        if ((stack_group->stacks[i] == NULL) ||
            stack_get_state(stack_group->stacks[i]) != RUNNING) {
            continue;
        }

        if (stack != stack_group->stacks[i]) {
            rpc_call_stack_exit(&stack_group->stacks[i]->rpc_queue);
        }
    }

    if (stack != NULL) {
        stack_exit();
    }

    for (i = 0; i < stack_group->stack_num; i++) {
        if (stack_group->stacks[i] == NULL || stack == stack_group->stacks[i]) {
            continue;
        }
        /* wait stack thread quit */
        stack_wait_quit(stack_group->stacks[i]);
    }
}
