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
#include <rte_kni.h>
#include <securec.h>
#include <numa.h>

#include "gazelle_base_func.h"
#include "lstack_thread_rpc.h"
#include "dpdk_common.h"
#include "lstack_log.h"
#include "lstack_dpdk.h"
#include "lstack_ethdev.h"
#include "lstack_lwip.h"
#include "lstack_protocol_stack.h"
#include "lstack_cfg.h"
#include "lstack_control_plane.h"
#include "posix/lstack_epoll.h"
#include "lstack_stack_stat.h"

#define READ_LIST_MAX                   32
#define SEND_LIST_MAX                   32
#define HANDLE_RPC_MSG_MAX              32
#define KERNEL_EPOLL_MAX                256

static PER_THREAD uint16_t g_stack_idx = PROTOCOL_STACK_MAX;
static struct protocol_stack_group g_stack_group = {0};

void set_init_fail(void);
bool get_init_fail(void);
typedef void *(*stack_thread_func)(void *arg);


void bind_to_stack_numa(struct protocol_stack *stack)
{
    int32_t ret;
    pthread_t tid = pthread_self();

    ret = pthread_setaffinity_np(tid, sizeof(stack->idle_cpuset), &stack->idle_cpuset);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "thread %d setaffinity to stack %hu failed\n", rte_gettid(), stack->queue_id);
    }
}

static inline void set_stack_idx(uint16_t idx)
{
    g_stack_idx = idx;
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
    if (g_stack_idx >= PROTOCOL_STACK_MAX) {
        return NULL;
    }
    return g_stack_group.stacks[g_stack_idx];
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
        return bind_stack;
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    uint16_t index = 0;

    /* close listen shadow, per app communication thread select only one stack */
    if (get_global_cfg_params()->listen_shadow == false) {
        static _Atomic uint16_t stack_index = 0;
        index = atomic_fetch_add(&stack_index, 1);
        if (index >= stack_group->stack_num) {
            LSTACK_LOG(ERR, LSTACK, "thread =%hu larger than stack num = %hu\n", index, stack_group->stack_num);
            return NULL;
        }
    /* use listen shadow, app communication thread maybe more than stack num, select the least load stack */
    } else {
        for (uint16_t i = 1; i < stack_group->stack_num; i++) {
            if (stack_group->stacks[i]->conn_num < stack_group->stacks[index]->conn_num) {
                index = i;
            }
        }
    }

    bind_stack = stack_group->stacks[index];
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
        nanosleep(&st, &st);
        stack->low_power = true;
        return;
    }

    if (last_cycle_ts == 0) {
        last_cycle_ts = sys_now();
    }

    uint64_t now_pkts = get_protocol_stack()->stats.rx;
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
        nanosleep(&st, &st);
    }
}

static int32_t create_thread(uint16_t queue_id, char *thread_name, stack_thread_func func)
{
    /* thread may run slow, if arg is temp var maybe have relese */
    static uint16_t queue[PROTOCOL_STACK_MAX];
    char name[PATH_MAX];
    pthread_t tid;
    int32_t ret;

    if (queue_id >= PROTOCOL_STACK_MAX) {
        LSTACK_LOG(ERR, LSTACK, "queue_id is %hu exceed max=%d\n", queue_id, PROTOCOL_STACK_MAX);
        return -1;
    }
    queue[queue_id] = queue_id;

    ret = sprintf_s(name, sizeof(name), "%s%02hu", thread_name, queue[queue_id]);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "set name failed\n");
        return -1;
    }

    ret = pthread_create(&tid, NULL, func, &queue[queue_id]);
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

static void* gazelle_wakeup_thread(void *arg)
{
    uint16_t queue_id = *(uint16_t *)arg;
    struct protocol_stack *stack = get_protocol_stack_group()->stacks[queue_id];

    struct cfg_params *cfg = get_global_cfg_params();
    int32_t lcore_id = cfg->wakeup[stack->queue_id];
    thread_affinity_init(lcore_id);

    struct timespec st = {
        .tv_sec = 0,
        .tv_nsec = 1
    };

    LSTACK_LOG(INFO, LSTACK, "weakup_%02hu start\n", stack->queue_id);

    for (;;) {
        if (cfg->low_power_mod != 0 && stack->low_power) {
            nanosleep(&st, &st);
        }

        sem_t *event_sem[WAKEUP_MAX_NUM];
        uint32_t num = gazelle_light_ring_dequeue_burst(stack->wakeup_ring, (void **)event_sem, WAKEUP_MAX_NUM);
        for (uint32_t i = 0; i < num; i++) {
            sem_post(event_sem[i]);
        }
    }

    return NULL;
}

static int32_t init_stack_value(struct protocol_stack *stack, uint16_t queue_id)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    set_stack_idx(queue_id);
    stack->tid = rte_gettid();
    stack->queue_id = queue_id;
    stack->port_id = stack_group->port_id;
    stack->cpu_id = get_global_cfg_params()->cpus[queue_id];
    stack->lwip_stats = &lwip_stats;

    init_list_node(&stack->recv_list);
    init_list_node(&stack->send_list);

    sys_calibrate_tsc();
    stack_stat_init();

    stack_group->stacks[queue_id] = stack;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(stack->cpu_id, &cpuset);
    if (rte_thread_set_affinity(&cpuset) != 0) {
        LSTACK_LOG(ERR, LSTACK, "rte_thread_set_affinity failed\n");
        return -1;
    }
    RTE_PER_LCORE(_lcore_id) = stack->cpu_id;

    stack->socket_id = numa_node_of_cpu(stack->cpu_id);
    if (stack->socket_id < 0) {
        LSTACK_LOG(ERR, LSTACK, "numa_node_of_cpu failed\n");
        return -1;
    }

    if (pktmbuf_pool_init(stack, stack_group->stack_num) != 0) {
        return -1;
    }

    if (create_shared_ring(stack) != 0) {
        return -1;
    }

    return 0;
}

static void* gazelle_kernel_event(void *arg)
{
    uint16_t queue_id = *(uint16_t *)arg;
    struct protocol_stack *stack = get_protocol_stack_group()->stacks[queue_id];

    int32_t epoll_fd = posix_api->epoll_create_fn(GAZELLE_LSTACK_MAX_CONN);
    if (epoll_fd < 0) {
        LSTACK_LOG(ERR, LSTACK, "queue_id=%hu epoll_fd=%d errno=%d\n", queue_id, epoll_fd, errno);
        /* exit in main thread, avoid create mempool and exit at the same time */
        set_init_fail();
        stack->epollfd = -1;
        return NULL;
    }

    stack->epollfd = epoll_fd;

    LSTACK_LOG(INFO, LSTACK, "kernel_event_%02hu start\n", queue_id);

    struct epoll_event events[KERNEL_EPOLL_MAX];
    for (;;) {
        int32_t event_num = posix_api->epoll_wait_fn(epoll_fd, events, KERNEL_EPOLL_MAX, -1);
        if (event_num <= 0) {
            continue;
        }

        for (int32_t i = 0; i < event_num; i++) {
            struct wakeup_poll *wakeup = events[i].data.ptr;
            if (wakeup) {
                __atomic_store_n(&wakeup->have_kernel_event, true, __ATOMIC_RELEASE);
                sem_post(&wakeup->event_sem);
            }
        }
    }

    return NULL;
}

static int32_t create_companion_thread(struct protocol_stack_group *stack_group, struct protocol_stack *stack)
{
    int32_t ret;

    ret = create_thread(stack->queue_id, "gazellekernel", gazelle_kernel_event);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "gazellekernelEvent ret=%d errno=%d\n", ret, errno);
        return ret;
    }

    /* wait gazelle_kernel_event finish use stack.avoid use stack after free when create gazelle_weakup_thread fail */
    while (stack->epollfd == 0) {
        usleep(1);
    }

    if (stack_group->wakeup_enable) {
        ret = create_thread(stack->queue_id, "gazelleweakup", gazelle_wakeup_thread);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "gazelleweakup ret=%d errno=%d\n", ret, errno);
        }
    }

    return ret;
}

void wait_sem_value(sem_t *sem, int32_t wait_value)
{
    int32_t sem_val;
    do {
        sem_getvalue(sem, &sem_val);
    } while (sem_val < wait_value);
}

static struct protocol_stack *stack_thread_init(uint16_t queue_id)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    struct protocol_stack *stack = malloc(sizeof(*stack));
    if (stack == NULL) {
        LSTACK_LOG(ERR, LSTACK, "malloc stack failed\n");
        return NULL;
    }

    if (init_stack_value(stack, queue_id) != 0) {
        free(stack);
        return NULL;
    }

    thread_affinity_init(stack->cpu_id);

    hugepage_init();

    tcpip_init(NULL, NULL);

    if (use_ltran()) {
        if (client_reg_thrd_ring() != 0) {
            free(stack);
            return NULL;
        }
    }

    sem_post(&stack_group->thread_phase1);

    if (!use_ltran()) {
        wait_sem_value(&stack_group->ethdev_init, 1);
    }

    if (ethdev_init(stack) != 0) {
        free(stack);
        return NULL;
    }

    if (create_companion_thread(stack_group, stack) != 0) {
        free(stack);
        return NULL;
    }

    return stack;
}

static void* gazelle_stack_thread(void *arg)
{
    uint16_t queue_id = *(uint16_t *)arg;

    struct protocol_stack *stack = stack_thread_init(queue_id);
    if (stack == NULL) {
        /* exit in main thread, avoid create mempool and exit at the same time */
        set_init_fail();
        sem_post(&get_protocol_stack_group()->all_init);
        LSTACK_LOG(ERR, LSTACK, "stack_thread_init failed queue_id=%hu\n", queue_id);
        return NULL;
    }

    sem_post(&get_protocol_stack_group()->all_init);
    LSTACK_LOG(INFO, LSTACK, "stack_%02hu init success\n", queue_id);

    for (;;) {
        poll_rpc_msg(stack, HANDLE_RPC_MSG_MAX);

        eth_dev_poll();

        read_recv_list(stack, READ_LIST_MAX);

        send_stack_list(stack, SEND_LIST_MAX);

        sys_timer_run();

        if (get_global_cfg_params()->low_power_mod != 0) {
            low_power_idling(stack);
        }
    }

    return NULL;
}

static int32_t init_protocol_sem(void)
{
    int32_t ret;
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    pthread_spin_init(&stack_group->wakeup_list_lock, PTHREAD_PROCESS_PRIVATE);

    if (!use_ltran()) {
        ret = sem_init(&stack_group->ethdev_init, 0, 0);
        if (ret < 0) {
            LSTACK_LOG(ERR, PORT, "sem_init failed ret=%d errno=%d\n", ret, errno);
            return -1;
        }
    }

    ret = sem_init(&stack_group->thread_phase1, 0, 0);
    if (ret < 0) {
        LSTACK_LOG(ERR, PORT, "sem_init failed ret=%d errno=%d\n", ret, errno);
        return -1;
    }

    ret = sem_init(&stack_group->all_init, 0, 0);
    if (ret < 0) {
        LSTACK_LOG(ERR, PORT, "sem_init failed ret=%d errno=%d\n", ret, errno);
        return -1;
    }

    return 0;
}

int32_t init_protocol_stack(void)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    int32_t ret;

    stack_group->stack_num = get_global_cfg_params()->num_cpu;
    stack_group->wakeup_enable = (get_global_cfg_params()->num_wakeup > 0) ? true : false;
    stack_group->wakeup_list = NULL;

    if (init_protocol_sem() != 0) {
        return -1;
    }

    for (uint32_t i = 0; i < stack_group->stack_num; i++) {
        ret = create_thread(i, "gazellestack", gazelle_stack_thread);
        if (ret != 0) {
            return ret;
        }
    }

    wait_sem_value(&stack_group->thread_phase1, stack_group->stack_num);

    if (get_init_fail()) {
        return -1;
    }

    ret = init_stack_numa_cpuset();
    if (ret < 0) {
        return -1;
    }

    return 0;
}

void stack_arp(struct rpc_msg *msg)
{
    struct rte_mbuf *mbuf = (struct rte_mbuf *)msg->args[MSG_ARG_0].p;

    eth_dev_recv(mbuf);
}

void stack_socket(struct rpc_msg *msg)
{
    msg->result = gazelle_socket(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i);
    if (msg->result < 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, %ld socket failed\n", get_stack_tid(), msg->result);
    }
}

void stack_close(struct rpc_msg *msg)
{
    int32_t fd = msg->args[MSG_ARG_0].i;

    msg->result = lwip_close(fd);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d failed %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i, msg->result);
    }

    gazelle_clean_sock(fd);

    posix_api->close_fn(fd);
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

    int32_t accept_fd = lwip_accept(fd, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].p);
    if (accept_fd < 0) {
        LSTACK_LOG(ERR, LSTACK, "fd %d ret %d\n", fd, accept_fd);
        return;
    }

    struct lwip_sock *sock = get_socket(accept_fd);
    if (sock == NULL || sock->stack == NULL) {
        lwip_close(accept_fd);
        gazelle_clean_sock(accept_fd);
        posix_api->close_fn(accept_fd);
        LSTACK_LOG(ERR, LSTACK, "fd %d ret %d\n", fd, accept_fd);
        return;
    }

    msg->result = accept_fd;
    if (rte_ring_count(sock->conn->recvmbox->ring)) {
        add_recv_list(accept_fd);
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
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d fail %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

void stack_setsockopt(struct rpc_msg *msg)
{
    msg->result = lwip_setsockopt(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i,
        msg->args[MSG_ARG_3].cp, msg->args[MSG_ARG_4].socklen);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d fail %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i, msg->result);
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

void stack_sendmsg(struct rpc_msg *msg)
{
    msg->result = lwip_sendmsg(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].cp, msg->args[MSG_ARG_2].i);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d fail %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

void stack_recvmsg(struct rpc_msg *msg)
{
    msg->result = lwip_recvmsg(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].i);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d fail %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i, msg->result);
    }
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

        ret = gazelle_alloc_pktmbuf(stack->rx_pktmbuf_pool, &mbuf_copy, 1);
        if (ret != 0) {
            stack->stats.rx_allocmbuf_fail++;
            return;
        }
        copy_mbuf(mbuf_copy, mbuf);

        ret = rpc_call_arp(stack, mbuf_copy);
        if (ret != 0) {
            return;
        }
    }
}

/* when fd is listenfd, listenfd of all protocol stack thread will be closed */
int32_t stack_broadcast_close(int32_t fd)
{
    struct lwip_sock *sock = get_socket(fd);
    int32_t ret = 0;

    do {
        sock = sock->listen_next;
        if (rpc_call_close(fd)) {
            ret = -1;
        }

        if (sock == NULL) {
            break;
        }
        fd = sock->conn->socket;
    } while (sock);

    return ret;
}

/* choice one stack listen */
int32_t stack_single_listen(int32_t fd, int32_t backlog)
{
    return rpc_call_listen(fd, backlog);
}

/* listen sync to all protocol stack thread, so that any protocol stack thread can build connect */
int32_t stack_broadcast_listen(int32_t fd, int32_t backlog)
{
    struct protocol_stack *cur_stack = get_protocol_stack_by_fd(fd);
    struct protocol_stack *stack = NULL;
    struct sockaddr addr;
    socklen_t addr_len = sizeof(addr);
    int32_t ret, clone_fd;

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, %d get sock null\n", get_stack_tid(), fd);
        GAZELLE_RETURN(EINVAL);
    }

    ret = rpc_call_getsockname(fd, &addr, &addr_len);
    if (ret != 0) {
        return ret;
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    for (int32_t i = 0; i < stack_group->stack_num; ++i) {
        stack = stack_group->stacks[i];
        if (stack != cur_stack) {
            clone_fd = rpc_call_shadow_fd(stack, fd, &addr, sizeof(addr));
            if (clone_fd < 0) {
                stack_broadcast_close(fd);
                return clone_fd;
            }
        } else {
            clone_fd = fd;
        }

        ret = rpc_call_listen(clone_fd, backlog);
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

/* ergodic the protocol stack thread to find the connection, because all threads are listening */
int32_t stack_broadcast_accept(int32_t fd, struct sockaddr *addr, socklen_t *addrlen)
{
    int32_t ret = -1;

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        errno = EINVAL;
        return -1;
    }

    struct lwip_sock *min_sock = get_min_accept_sock(fd);
    if (min_sock && min_sock->conn) {
        ret = rpc_call_accept(min_sock->conn->socket, addr, addrlen);
    }

    if (min_sock && min_sock->wakeup && min_sock->wakeup->type == WAKEUP_EPOLL) {
        del_accept_in_event(min_sock);
    }

    if (ret < 0) {
        errno = EAGAIN;
    }
    return ret;
}
