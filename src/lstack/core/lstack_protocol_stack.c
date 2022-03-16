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

#include <lwip/sockets.h>
#include <lwip/tcpip.h>
#include <lwip/tcp.h>
#include <lwip/memp_def.h>
#include <lwipsock.h>
#include <rte_kni.h>
#include <securec.h>
#include <numa.h>

#include "gazelle_base_func.h"
#include "lstack_thread_rpc.h"
#include "dpdk_common.h"
#include "lstack_log.h"
#include "lstack_lwip.h"
#include "lstack_protocol_stack.h"
#include "lstack_cfg.h"
#include "lstack_weakup.h"
#include "lstack_control_plane.h"
#include "lstack_stack_stat.h"

static PER_THREAD uint16_t g_stack_idx = PROTOCOL_STACK_MAX;
static struct protocol_stack_group g_stack_group = {0};
static PER_THREAD long g_stack_tid = 0;

typedef void *(*stack_thread_func)(void *arg);

int32_t bind_to_stack_numa(int32_t stack_id)
{
    static PER_THREAD int32_t last_stack_id = -1;

    int32_t ret;
    struct protocol_stack *stack = get_protocol_stack_group()->stacks[stack_id];
    pthread_t tid = pthread_self();

    if (last_stack_id == stack_id) {
        return 0;
    }
    last_stack_id = stack_id;

    ret = pthread_setaffinity_np(tid, sizeof(stack->idle_cpuset), &stack->idle_cpuset);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "thread %d setaffinity to stack %d failed\n", rte_gettid(), stack->queue_id);
        return -1;
    }

    return 0;
}

static inline void set_stack_idx(uint16_t idx)
{
    g_stack_idx = idx;
}

long get_stack_tid(void)
{
    if (g_stack_tid == 0) {
        g_stack_tid = syscall(__NR_gettid);
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

struct protocol_stack *get_minconn_protocol_stack(void)
{
    int32_t min_index = 0;

    for (int32_t i = 1; i < g_stack_group.stack_num; i++) {
        if (g_stack_group.stacks[i]->conn_num < g_stack_group.stacks[min_index]->conn_num) {
            min_index = i;
        }
    }

    return g_stack_group.stacks[min_index];
}

void lstack_low_power_idling(void)
{
    static PER_THREAD uint32_t wakeup_flag = 0;
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
    if (get_global_cfg_params()->low_power_mod == 0) {
        wakeup_flag = 0;
        return;
    }

    if (eth_get_flow_cnt() < LSTACK_LPM_RX_PKTS) {
        wakeup_flag = 1;
        nanosleep(&st, &st);
        return;
    }

    if (last_cycle_ts == 0) {
        last_cycle_ts = sys_now();
    }

    uint64_t now_pkts = get_protocol_stack()->stats.rx;
    uint32_t now_ts = sys_now();
    if (((now_ts - last_cycle_ts) > LSTACK_LPM_DETECT_MS) ||
        (wakeup_flag && ((now_pkts - last_cycle_pkts) >= LSTACK_LPM_PKTS_IN_DETECT))) {
        if (!wakeup_flag && ((now_pkts - last_cycle_pkts) < LSTACK_LPM_PKTS_IN_DETECT)) {
            wakeup_flag = 1;
        } else if (wakeup_flag && ((now_pkts - last_cycle_pkts) >= LSTACK_LPM_PKTS_IN_DETECT)) {
            wakeup_flag = 0;
        }

        last_cycle_ts = now_ts;
        last_cycle_pkts = now_pkts;
    }

    if (wakeup_flag) {
        nanosleep(&st, &st);
    }
}

int32_t init_protocol_stack(void)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    struct protocol_stack *stack = NULL;
    int32_t ret;

    for (uint32_t i = 0; i < stack_group->stack_num; i++) {
        stack = malloc(sizeof(*stack));
        if (stack == NULL) {
            return -ENOMEM;
        }
        memset_s(stack, sizeof(*stack), 0, sizeof(*stack));

        stack->queue_id = i;
        stack->port_id = stack_group->port_id;
        stack->cpu_id = get_global_cfg_params()->cpus[i];
        stack->socket_id = numa_node_of_cpu(stack->cpu_id);
        if (stack->socket_id < 0) {
            LSTACK_LOG(ERR, PORT, "numa_node_of_cpu failed\n");
            return -EINVAL;
        }

        ret = pktmbuf_pool_init(stack, stack_group->stack_num);
        if (ret != 0) {
            return ret;
        }

        ret = create_shared_ring(stack);
        if (ret != 0) {
            return ret;
        }

        init_list_node(&stack->recv_list);
        init_list_node(&stack->listen_list);

        stack_group->stacks[i] = stack;
    }

    ret = init_stack_numa_cpuset();
    if (ret < 0) {
        return -1;
    }

    if (!use_ltran()) {
        ret = dpdk_ethdev_init();
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "dpdk_ethdev_init failed\n");
            return -1;
        }

        ret = dpdk_ethdev_start();
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "dpdk_ethdev_start failed\n");
            return -1;
        }

        if (get_global_cfg_params()->kni_switch) {
            ret = dpdk_init_lstack_kni();
            if (ret < 0) {
                return -1;
            }
        }
    }

    return 0;
}

static int32_t create_thread(struct protocol_stack *stack, char *thread_name, stack_thread_func func)
{
    char name[PATH_MAX];
    pthread_t tid;
    int32_t ret;

    ret = sprintf_s(name, sizeof(name), "%s%02d", thread_name, stack->queue_id);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "set name failed\n");
        return -1;
    }

    ret = pthread_create(&tid, NULL, func, stack);
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

static void* gazelle_weakup_thread(void *arg)
{
    struct protocol_stack *stack = (struct protocol_stack *)arg;
    int32_t lcore_id = get_global_cfg_params()->weakup[stack->queue_id];

    thread_affinity_init(lcore_id);
    LSTACK_LOG(INFO, LSTACK, "weakup_%02d start\n", stack->queue_id);

    for (;;) {
        weakup_thread(stack->weakup_ring);
    }

    return NULL;
}

static void stack_thread_init(struct protocol_stack *stack)
{
    uint16_t queue_id = stack->queue_id;
    int32_t ret;

    set_stack_idx(queue_id);
    stack->tid = gettid();
    stack->lwip_stats = &lwip_stats;
    RTE_PER_LCORE(_lcore_id) = stack->cpu_id;

    thread_affinity_init(stack->cpu_id);

    sys_calibrate_tsc();

    hugepage_init();

    stack_replenish_send_idlembuf(stack);

    tcpip_init(NULL, NULL);

    if (use_ltran()) {
        ret = client_reg_thrd_ring();
        if (ret != 0) {
            LSTACK_EXIT(1, "failed reg thread ret=%d\n", ret);
        }
    }

    ret = ethdev_init(stack);
    if (ret != 0) {
        LSTACK_EXIT(1, "failed reg thread ret=%d\n", ret);
    }

    stack_stat_init();

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    sem_post(&stack_group->thread_inited);
    LSTACK_LOG(INFO, LSTACK, "stack_%02d init success\n", queue_id);
}

static void* gazelle_stack_thread(void *arg)
{
    struct protocol_stack *stack = (struct protocol_stack *)arg;

    stack_thread_init(stack);

    for (;;) {
        poll_rpc_msg(stack);

        eth_dev_poll();

        read_recv_list();

        sys_timer_run();
    }

    return NULL;
}

int32_t create_stack_thread(void)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    int32_t ret;

    ret = sem_init(&stack_group->thread_inited, 0, 0);
    if (ret < 0) {
        LSTACK_LOG(ERR, PORT, "sem_init failed\n");
        return -1;
    }

    for (uint32_t i = 0; i < stack_group->stack_num; i++) {
        ret = create_thread(stack_group->stacks[i], "gazellestack", gazelle_stack_thread);
        if (ret != 0) {
            return ret;
        }
    }

    int32_t thread_inited_num;
    do {
        sem_getvalue(&stack_group->thread_inited, &thread_inited_num);
    } while (thread_inited_num < stack_group->stack_num);

    for (uint32_t i = 0; i < stack_group->stack_num; i++) {
        ret = create_thread(stack_group->stacks[i], "gazelleweakup", gazelle_weakup_thread);
        if (ret != 0) {
            return ret;
        }
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
    int32_t fd = lwip_socket(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i);
    msg->result = fd;
    if (fd < 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, %d socket failed\n", get_stack_tid(), fd);
        return;
    }

    gazelle_init_sock(fd);
}

static inline bool is_real_close(int32_t fd)
{
    struct lwip_sock *sock = get_socket_by_fd(fd);

    /* last sock */
    if (list_is_empty(&sock->attach_list)) {
        list_del_node_init(&sock->attach_list);
        return true;
    }

    /* listen sock, but have attach sock */
    if (sock->attach_fd == fd) {
        sock->wait_close = true;
        return false;
    } else { /* attach sock */
        /* listen sock is normal */
        struct lwip_sock *listen_sock = get_socket_by_fd(sock->attach_fd);
        if (listen_sock == NULL || !listen_sock->wait_close) {
            list_del_node_init(&sock->attach_list);
            return true;
        }

        /* listen sock is wait clsoe. check this is last attach sock */
        struct list_node *list = &(sock->attach_list);
        struct list_node *node, *temp;
        uint32_t list_count = 0;
        list_for_each_safe(node, temp, list) {
            list_count++;
        }
        /* 2:listen sock is wait close and closing attach sock. close listen sock here */
        if (list_count == 2) {
            lwip_close(listen_sock->attach_fd);
            gazelle_clean_sock(listen_sock->attach_fd);
            posix_api->close_fn(listen_sock->attach_fd);
            list_del_node_init(&listen_sock->attach_list);
        }
        list_del_node_init(&sock->attach_list);
        return true;
    }

    list_del_node_init(&sock->attach_list);
    return true;
}

void stack_close(struct rpc_msg *msg)
{
    int32_t fd = msg->args[MSG_ARG_0].i;

    if (!is_real_close(fd)) {
        msg->result = 0;
        return;
    }

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

static inline struct lwip_sock *reuse_listen(struct protocol_stack *stack, struct lwip_sock *listen_sock)
{
    struct list_node *node, *temp;
    struct list_node *list = &(stack->listen_list);
    struct lwip_sock *sock;

    list_for_each_safe(node, temp, list) {
        sock = container_of(node, struct lwip_sock, listen_list);
        if (sock->conn->pcb.tcp->local_port == listen_sock->conn->pcb.tcp->local_port &&
            sock->conn->pcb.tcp->local_ip.addr == listen_sock->conn->pcb.tcp->local_ip.addr) {
            return sock;
        }
    }

    return NULL;
}

void stack_listen(struct rpc_msg *msg)
{
    struct protocol_stack *stack = get_protocol_stack();
    int32_t fd = msg->args[MSG_ARG_0].i;
    int32_t backlog = msg->args[MSG_ARG_1].i;

    struct lwip_sock *sock = get_socket_by_fd(fd);
    if (sock == NULL) {
        msg->result = -1;
        return;
    }

    /* stack have listen same ip+port, then attach to old listen */
    struct lwip_sock *listen_sock = reuse_listen(stack, sock);
    if (listen_sock) {
        if (list_is_empty(&sock->attach_list)) {
            list_add_node(&listen_sock->attach_list, &sock->attach_list);
        }
        sock->attach_fd = listen_sock->conn->socket;
        msg->result = 0;
        return;
    }

    /* new listen add to stack listen list */
    msg->result = lwip_listen(fd, backlog);
    if (msg->result == 0) {
        if (list_is_empty(&sock->listen_list)) {
            list_add_node(&stack->listen_list, &sock->listen_list);
        }
        sock->attach_fd = fd;
    } else {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d failed %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

static bool have_accept_event(int32_t fd)
{
    do {
        struct lwip_sock *sock = get_socket(fd);
        if (sock == NULL) {
            break;
        }

        if (NETCONN_IS_ACCEPTIN(sock)) {
            return true;
        }

        fd = sock->nextfd;
    } while (fd > 0);

    return false;
}

void stack_accept(struct rpc_msg *msg)
{
    int32_t fd = msg->args[MSG_ARG_0].i;

    /* listen sock attach_fd is self */
    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        msg->result = -1;
        return;
    }
    fd = sock->attach_fd;

    msg->result = lwip_accept(fd, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].p);
    if (msg->result <= 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %ld, fd %d attach_fd %d failed %ld\n", get_stack_tid(), msg->args[MSG_ARG_0].i,
            fd, msg->result);
    }
}

void stack_connect(struct rpc_msg *msg)
{
    msg->result = lwip_connect(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].socklen);
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
    struct lwip_sock *sock = NULL;
    int32_t next_fd;

    while (fd > 0) {
        sock = get_socket(fd);
        if (sock == NULL) {
            LSTACK_LOG(ERR, LSTACK, "tid %ld, %d get sock null\n", get_stack_tid(), fd);
            GAZELLE_RETURN(EINVAL);
        }
        next_fd = sock->nextfd;

        rpc_call_close(fd);
        fd = next_fd;
    }

    return 0;
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

/* ergodic the protocol stack thread to find the connection, because all threads are listening */
int32_t stack_broadcast_accept(int32_t fd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct lwip_sock *min_sock = NULL;
    int32_t head_fd = fd;
    int32_t min_fd = fd;
    int32_t ret = -1;

    while (fd > 0) {
        struct lwip_sock *sock = get_socket(fd);
        if (sock == NULL) {
            GAZELLE_RETURN(EINVAL);
        }

        if (!NETCONN_IS_ACCEPTIN(sock)) {
            fd = sock->nextfd;
            continue;
        }

        if (min_sock == NULL || min_sock->stack->conn_num > sock->stack->conn_num) {
            min_sock = sock;
            min_fd = fd;
        }

        fd = sock->nextfd;
    }

    if (min_sock) {
        ret = rpc_call_accept(min_fd, addr, addrlen);
    }

    struct lwip_sock *sock = get_socket(head_fd);
    if (!sock->have_event && have_accept_event(head_fd)) {
        sock->have_event = true;
        sock->events |= EPOLLIN;
        rte_ring_mp_enqueue(sock->weakup->event_ring, (void *)sock);
        sem_post(&sock->weakup->event_sem);
        sock->stack->stats.accept_events++;
    }

    if(ret < 0) {
        errno = EAGAIN;
    }
    return ret;
}
