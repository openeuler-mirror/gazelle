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

#include <pthread.h>
#include <stdatomic.h>
#include <securec.h>
#include <numa.h>

#include <lwip/sockets.h>
#include <lwip/init.h>
#include <lwip/tcp.h>
#include <lwipgz_sock.h>
#include <lwip/lwipgz_posix_api.h>

#include "common/gazelle_base_func.h"
#include "common/dpdk_common.h"
#include "lstack_log.h"
#include "lstack_cfg.h"
#include "lstack_dpdk.h"
#include "lstack_ethdev.h"
#include "lstack_lwip.h"
#include "lstack_control_plane.h"
#include "lstack_epoll.h"
#include "lstack_stack_stat.h"
#include "lstack_virtio.h"
#include "lstack_interrupt.h"
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

enum rte_lcore_state_t stack_get_state(struct protocol_stack *stack)
{
    return __atomic_load_n(&stack->state, __ATOMIC_ACQUIRE);
}

static void stack_wait_quit(struct protocol_stack *stack)
{
    while (__atomic_load_n(&stack->state, __ATOMIC_ACQUIRE) != WAIT) {
        rte_pause();
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

struct protocol_stack *get_protocol_stack(void)
{
    return g_stack_p;
}

struct protocol_stack *get_protocol_stack_by_fd(int fd)
{
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (POSIX_IS_CLOSED(sock)) {
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
            if (stack->conn_num < min_conn_num) {
                index = i;
                min_conn_num = stack->conn_num;
            }
        }
    }

    stack_group->stacks[index]->conn_num++;
    bind_stack = stack_group->stacks[index];
    pthread_spin_unlock(&stack_group->socket_lock);
    return stack_group->stacks[index];
}

int get_min_conn_stack(struct protocol_stack_group *stack_group)
{
    struct protocol_stack* stack;
    int min_conn_stk_idx = 0;
    int min_conn_num = GAZELLE_MAX_CLIENTS;

    for (int i = 0; i < stack_group->stack_num; i++) {
        stack = stack_group->stacks[i];
        if (stack->conn_num < min_conn_num) {
            min_conn_stk_idx = i;
            min_conn_num = stack->conn_num;
        }
    }
    return min_conn_stk_idx;
}

void bind_to_stack_numa(struct protocol_stack *stack)
{
    int32_t ret;
    pthread_t tid = pthread_self();

    if (get_global_cfg_params()->stack_num > 0) {
        numa_run_on_node(stack->numa_id);
        return;
    }

    ret = pthread_setaffinity_np(tid, sizeof(stack->idle_cpuset), &stack->idle_cpuset);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "thread %d setaffinity to stack %hu failed\n", rte_gettid(), stack->queue_id);
        return;
    }
}

void thread_bind_stack(struct protocol_stack *stack)
{
    static PER_THREAD uint16_t stack_sock_num[GAZELLE_MAX_STACK_NUM] = {0};
    static PER_THREAD uint16_t max_sock_stack = 0;

    if (get_global_cfg_params()->app_bind_numa == 0) {
        return;
    }

    stack_sock_num[stack->stack_idx]++;
    if (stack_sock_num[stack->stack_idx] > max_sock_stack) {
        max_sock_stack = stack_sock_num[stack->stack_idx];
        bind_to_stack_numa(stack);
    }
}

static int stack_affinity_cpu(int cpu_id)
{
    int32_t ret;
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);

    ret = rte_thread_set_affinity(&cpuset);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "thread %d pthread_setaffinity_np failed ret=%d\n", rte_gettid(), ret);
    }

    return ret;
}

static void stack_affinity_numa(int numa_id)
{
    numa_run_on_node(numa_id);
}

static int32_t stack_idle_cpuset(struct protocol_stack *stack, cpu_set_t *exclude)
{
    int32_t cpunum;
    uint32_t cpulist[CPUS_MAX_NUM];

    cpunum = numa_to_cpusnum(stack->numa_id, cpulist, CPUS_MAX_NUM);
    if (cpunum <= 0) {
        LSTACK_LOG(ERR, LSTACK, "numa_to_cpusnum failed\n");
        return -1;
    }

    CPU_ZERO(&stack->idle_cpuset);
    for (uint32_t i = 0; i < cpunum; i++) {
        /* skip stack cpu */
        if (CPU_ISSET(cpulist[i], exclude)) {
            continue;
        }

        CPU_SET(cpulist[i], &stack->idle_cpuset);
    }

    return 0;
}

static int32_t init_stack_numa_cpuset(struct protocol_stack *stack)
{
    int32_t ret;
    struct cfg_params *cfg = get_global_cfg_params();

    cpu_set_t stack_cpuset;
    CPU_ZERO(&stack_cpuset);
    for (int32_t idx = 0; idx < cfg->num_cpu; ++idx) {
        CPU_SET(cfg->cpus[idx], &stack_cpuset);
    }

    for (int32_t idx = 0; idx < cfg->app_exclude_num_cpu; ++idx) {
        CPU_SET(cfg->app_exclude_cpus[idx], &stack_cpuset);
    }

    ret = stack_idle_cpuset(stack, &stack_cpuset);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "thread_get_cpuset stack(%u) failed\n", stack->tid);
        return -1;
    }

    return 0;
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

struct thread_params {
    uint16_t queue_id;
    uint16_t idx;
};

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

    ret = sprintf_s(name, sizeof(name), "%s%02hu", thread_name, t_params->queue_id);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "set name failed\n");
        return -1;
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
    struct cfg_params *cfg_params = get_global_cfg_params();

    stack->tid = rte_gettid();
    stack->queue_id = t_params->queue_id;
    stack->port_id = stack_group->port_id;
    stack->stack_idx = t_params->idx;
    stack->lwip_stats = &lwip_stats;

    list_init_head(&stack->recv_list);
    list_init_head(&stack->same_node_recv_list);
    list_init_head(&stack->wakeup_list);

    stack_group->stacks[t_params->idx] = stack;
    set_stack_idx(t_params->idx);

    stack->epollfd = posix_api->epoll_create_fn(GAZELLE_LSTACK_MAX_CONN);
    if (stack->epollfd < 0) {
        LSTACK_LOG(ERR, LSTACK, "kernel epoll_create failed\n");
        return -1;
    }

    if (cfg_params->stack_num > 0) {
        stack->numa_id = cfg_params->numa_id;
    } else {
        stack->cpu_id = cfg_params->cpus[t_params->idx];
        stack->numa_id = numa_node_of_cpu(stack->cpu_id);
        if (stack->numa_id < 0) {
            LSTACK_LOG(ERR, LSTACK, "numa_node_of_cpu failed\n");
            return -1;
        }
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

static void wait_sem_value(sem_t *sem, int32_t wait_value)
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

    if (get_global_cfg_params()->stack_num == 0) {
        if (stack_affinity_cpu(stack->cpu_id) != 0) {
            goto END;
        }
        RTE_PER_LCORE(_lcore_id) = stack->cpu_id;
    } else {
        stack_affinity_numa(stack->numa_id);
    }

    lwip_init();
    /* Using errno to return lwip_init() result. */
    if (errno != 0) {
        LSTACK_LOG(ERR, LSTACK, "lwip_init failed, errno %d\n", errno);
        goto END;
    }

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

int stack_polling(unsigned wakeup_tick)
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
    uint32_t timeout;

    /* 2: one dfx consumes two rpc */
    rpc_poll_msg(&stack->dfx_rpc_queue, 2);
    force_quit = rpc_poll_msg(&stack->rpc_queue, rpc_number);

    eth_dev_poll();
    timeout = sys_timer_run();
    if (cfg->stack_interrupt) {
        intr_wait(stack->stack_idx, timeout);
    }

    if (cfg->low_power_mod != 0) {
        low_power_idling(stack);
    }

    if (stack_mode_rtc) {
        return force_quit;
    }

    do_lwip_read_recvlist(stack, read_connect_number);

    if ((wakeup_tick & 0xf) == 0) {
        wakeup_stack_epoll(stack);
        if (get_global_cfg_params()->send_cache_mode) {
            tx_cache_send(stack->queue_id);
        }
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
    if (get_global_cfg_params()->flow_bifurcation) {
        virtio_tap_process_rx(stack->port_id, stack->queue_id);
    }
    return force_quit;
}

static bool stack_local_event_get(uint16_t stack_id)
{
    struct protocol_stack *stack = g_stack_group.stacks[stack_id];
    if (!lockless_queue_empty(&stack->dfx_rpc_queue.queue) ||
        !lockless_queue_empty(&stack->rpc_queue.queue) ||
        !list_head_empty(&stack->recv_list) ||
        !list_head_empty(&stack->wakeup_list) ||
        tx_cache_count(stack->queue_id)) {
        return true;
    }
    return false;
}

static void* gazelle_stack_thread(void *arg)
{
    struct thread_params *t_params = (struct thread_params*) arg;
    uint16_t queue_id = t_params->queue_id;
    struct protocol_stack *stack;
    unsigned wakeup_tick = 0;

    stack = stack_thread_init(arg);
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

    intr_register(stack->stack_idx, INTR_LOCAL_EVENT, stack_local_event_get);
    stack_set_state(stack, RUNNING);

    while (stack_polling(wakeup_tick) == 0) {
        wakeup_tick++;
    }

    stack_set_state(stack, WAIT);

    return NULL;
}

static int stack_group_init_mempool(void)
{
    struct cfg_params *cfg_params = get_global_cfg_params();
    uint32_t total_mbufs = dpdk_pktmbuf_mempool_num();
    struct rte_mempool *rxtx_mbuf = NULL;
    uint32_t cpu_id = 0;
    unsigned numa_id = 0;
    int queue_id = 0;

    LSTACK_LOG(INFO, LSTACK,
        "config::num_cpu=%d num_process=%d \n", cfg_params->num_cpu, cfg_params->num_process);

    for (int cpu_idx = 0; cpu_idx < cfg_params->num_queue; cpu_idx++) {
        if (cfg_params->stack_num > 0) {
            numa_id = cfg_params->numa_id;
        } else {
            cpu_id = cfg_params->cpus[cpu_idx];
            numa_id = numa_node_of_cpu(cpu_id);
        }

        for (int process_idx = 0; process_idx < cfg_params->num_process; process_idx++) {
            queue_id = cpu_idx * cfg_params->num_process + process_idx;
            if (queue_id >= PROTOCOL_STACK_MAX) {
                LSTACK_LOG(ERR, LSTACK, "index is over\n");
                return -1;
            }

            rxtx_mbuf = create_pktmbuf_mempool("rxtx_mbuf", total_mbufs, RXTX_CACHE_SZ, queue_id, numa_id);
            if (rxtx_mbuf == NULL) {
                LSTACK_LOG(ERR, LSTACK, "numid=%d, rxtx_mbuf idx=%d, create_pktmbuf_mempool fail\n", numa_id, queue_id);
                return -1;
            }

            get_protocol_stack_group()->total_rxtx_pktmbuf_pool[queue_id] = rxtx_mbuf;
        }
    }

    return 0;
}

int stack_group_init(void)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    stack_group->stack_num = 0;

    list_init_head(&stack_group->poll_list);
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

int stack_setup_app_thread(void)
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

int stack_setup_thread(void)
{
    int ret, i;
    char name[PATH_MAX];
    int queue_num = get_global_cfg_params()->num_queue;
    struct thread_params *t_params[PROTOCOL_STACK_MAX] = {NULL};
    int process_index = get_global_cfg_params()->process_idx;

    for (i = 0; i < queue_num; ++i) {
        t_params[i] = malloc(sizeof(struct thread_params));
        if (t_params[i] == NULL) {
            goto OUT1;
        }
    }
    for (i = 0; i < queue_num; i++) {
        ret = sprintf_s(name, sizeof(name), "%s", LSTACK_THREAD_NAME);
        if (ret < 0) {
            goto OUT1;
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
    for (i = 0; i < queue_num; ++i) {
        if (t_params[i] != NULL) {
            free(t_params[i]);
        }
    }
OUT2:
    return -1;
}

static void stack_all_fds_close(struct protocol_stack *stack)
{
    for (int i = 3; i < GAZELLE_MAX_CLIENTS + GAZELLE_RESERVED_CLIENTS; i++) {
        struct lwip_sock *sock = lwip_get_socket(i);
        if (!POSIX_IS_CLOSED(sock) && sock->stack == stack) {
            lwip_close(i);
        }
    }
}

void stack_exit(void)
{
    struct protocol_stack *stack = get_protocol_stack();
    if (stack != NULL) {
        stack_all_fds_close(stack);
    }
}

void stack_stop(void)
{
    struct protocol_stack *stack = get_protocol_stack();
    if (stack != NULL) {
        stack_set_state(stack, WAIT);
    }
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
