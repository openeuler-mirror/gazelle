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

#include <stdatomic.h>
#include <securec.h>

#include <rte_config.h>
#include <rte_atomic.h>

#include <lwip/lwipgz_sock.h>
#include <lwip/lwipgz_posix_api.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/sockets.h>

#include "common/gazelle_base_func.h"
#include "lstack_wait.h"
#include "lstack_log.h"
#include "lstack_cfg.h"
#include "same_node.h"
#include "mbox_ring.h"

#define KERNEL_EVENT_WAIT_US    10
#define LWIP_EVENT_WAIT_US      10

struct kernel_wait {
    int epfd;
};

struct lwip_wait {
#if SOCK_WAIT_BATCH_NOTIFY
    struct list_node stk_notify_list;
#endif /* SOCK_WAIT_BATCH_NOTIFY */
} __rte_cache_aligned;

struct sock_wait_group {
    struct kernel_wait  kwaits[PROTOCOL_STACK_MAX];
    struct lwip_wait    lwaits[PROTOCOL_STACK_MAX];

    _Atomic uint16_t affinity_tick;

    /* new cache line */
    char pad0 __rte_cache_aligned;

    /* dfx stat */
    struct list_node group_list;
    rte_spinlock_t group_list_lock;
};
static struct sock_wait_group g_wait_group = {0};

static inline struct kernel_wait *kernel_wait_get(int stack_id)
{
    if (unlikely(stack_id < 0 || stack_id >= PROTOCOL_STACK_MAX)) {
        return NULL;
    }
    return &g_wait_group.kwaits[stack_id];
}

static inline struct lwip_wait *lwip_wait_get(int stack_id)
{
    if (unlikely(stack_id < 0 || stack_id >= PROTOCOL_STACK_MAX)) {
        return NULL;
    }
    return &g_wait_group.lwaits[stack_id];
}

static int lwip_wait_init(int stack_id)
{
    struct lwip_wait *lwait = lwip_wait_get(stack_id);
    LWIP_UNUSED_ARG(lwait);

#if SOCK_WAIT_BATCH_NOTIFY
    list_init_head(&lwait->stk_notify_list);
#endif /* SOCK_WAIT_BATCH_NOTIFY */
    return 0;
}

static int kernel_wait_init(int stack_id)
{
    struct kernel_wait *kwait = kernel_wait_get(stack_id);

    kwait->epfd = posix_api->epoll_create_fn(GAZELLE_LSTACK_MAX_CONN);
    if (kwait->epfd < 0) {
        LSTACK_LOG(ERR, LSTACK, "epoll_create failed, errno %d\n", errno);
        return -1;
    }

    return 0;
}

int sock_wait_group_init(void)
{
    list_init_head(&g_wait_group.group_list);
    rte_spinlock_init(&g_wait_group.group_list_lock);
    return 0;
}

static inline void sock_wait_group_add(struct sock_wait *sk_wait)
{
    list_init_node(&sk_wait->group_node);

    rte_spinlock_lock(&g_wait_group.group_list_lock);
    list_add_node(&sk_wait->group_node, &g_wait_group.group_list);
    rte_spinlock_unlock(&g_wait_group.group_list_lock);
}

static inline void sock_wait_group_del(struct sock_wait *sk_wait)
{
    rte_spinlock_lock(&g_wait_group.group_list_lock);
    list_del_node(&sk_wait->group_node);
    rte_spinlock_unlock(&g_wait_group.group_list_lock);
}

void sock_wait_group_stat(int stack_id, struct gazelle_wakeup_stat *stat)
{
    struct sock_wait *sk_wait;
    struct list_node *node, *next;

    rte_spinlock_lock(&g_wait_group.group_list_lock);

    list_for_each_node(node, next, &g_wait_group.group_list) {
        sk_wait = list_entry(node, struct sock_wait, group_node);

        if (sk_wait->affinity.bind_stack_id != stack_id)
            continue;

        stat->kernel_events += sk_wait->stat.kernel_events ;
        stat->app_events    += sk_wait->stat.app_events    ;
        stat->accept_fail   += sk_wait->stat.accept_fail   ;
        stat->app_write_cnt += sk_wait->stat.app_write_cnt ;
        stat->app_read_cnt  += sk_wait->stat.app_read_cnt  ;
        stat->read_null     += sk_wait->stat.read_null     ;
        stat->sock_rx_drop  += sk_wait->stat.sock_rx_drop  ;
        stat->sock_tx_merge += sk_wait->stat.sock_tx_merge ;
    }

    rte_spinlock_unlock(&g_wait_group.group_list_lock);
}

int kernel_wait_ctl(struct sock_wait *sk_wait, int new_stack_id, int old_stack_id)
{
    int ret;
    struct kernel_wait *old_kwait = kernel_wait_get(old_stack_id);
    struct kernel_wait *new_kwait = kernel_wait_get(new_stack_id);
    struct epoll_event epevent;

    /* not change */
    if (old_kwait != NULL && old_kwait == new_kwait) {
        return 0;
    }

    if (old_kwait) {
        ret = posix_api->epoll_ctl_fn(old_kwait->epfd, EPOLL_CTL_DEL, sk_wait->epfd, NULL);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "epoll_ctl failed, errno %d\n", errno);
            return -1;
        }
    }

    if (new_kwait) {
        epevent.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLET;
        epevent.data.ptr = sk_wait;
        ret = posix_api->epoll_ctl_fn(new_kwait->epfd, EPOLL_CTL_ADD, sk_wait->epfd, &epevent);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "epoll_ctl failed, errno %d\n", errno);
            return -1;
        }
    }

    return 0;
}

void* kernel_wait_thread(void *arg)
{
    struct thread_params *t_params = (struct thread_params*) arg;
    unsigned stack_id = t_params->idx;
    struct epoll_event kernel_events[KERNEL_EPOLL_MAX];
    int num, i;
    struct kernel_wait *kwait;
    struct sock_wait *sk_wait;

    bind_to_stack_numa(stack_id);
    free(arg);
    sem_post(&get_protocol_stack_group()->sem_stack_setup);

    lwip_wait_init(stack_id);
    kernel_wait_init(stack_id);
    kwait = kernel_wait_get(stack_id);

    LSTACK_LOG(INFO, LSTACK, "kernelevent_%02hu start\n", stack_id);

    for (;;) {
        num = posix_api->epoll_wait_fn(kwait->epfd, kernel_events, KERNEL_EPOLL_MAX, -1);
        if (num < 0 && errno != EINTR && errno != EAGAIN) {
            LSTACK_LOG(ERR, LSTACK, "epoll_wait faild, errno %d\n", errno);
        }

        for (i = 0; i < num; ++i) {
            sk_wait = kernel_events[i].data.ptr;
            if (sk_wait->type == WAIT_CLOSE)
                continue;
            rte_atomic16_set(&sk_wait->kernel_pending, true);
            sys_sem_signal_internal(&sk_wait->sem);
        }
        usleep(KERNEL_EVENT_WAIT_US);
    }

    return NULL;
}

static unsigned affinity_choice_stack(int stack_num)
{
    if (get_global_cfg_params()->stack_mode_rtc) {
        return get_protocol_stack()->stack_idx;
    }
    return atomic_fetch_add(&g_wait_group.affinity_tick, 1) % stack_num;
}

static void affinity_find_max_stack(struct wait_affinity *affinity, int stack_num)
{
    int max_stack_id = affinity->max_stack_id;

    for (int i = 0; i < stack_num; i++) {
        if (affinity->stack_nfds[i] > affinity->stack_nfds[max_stack_id]) {
            max_stack_id = i;
        }
    }
    affinity->max_stack_id = max_stack_id;
}

void affinity_update_max_stack(struct wait_affinity *affinity)
{
    struct protocol_stack_group *stack_group;

    if (get_global_cfg_params()->stack_mode_rtc) {
        affinity->max_stack_id = get_protocol_stack()->stack_idx;
    } else {
        stack_group = get_protocol_stack_group();
        affinity_find_max_stack(affinity, stack_group->stack_num);
    }
}

void affinity_bind_stack(struct sock_wait *sk_wait, struct wait_affinity *affinity)
{
    if (affinity->max_stack_id != affinity->bind_stack_id) {
        bind_to_stack_numa(affinity->max_stack_id);
        kernel_wait_ctl(sk_wait, affinity->max_stack_id, affinity->bind_stack_id);
        affinity->bind_stack_id = affinity->max_stack_id;
    }
}

int sock_event_init(struct sock_event *sk_event)
{
    memset_s(sk_event, sizeof(struct sock_event), 0, sizeof(struct sock_event));

    list_init_node(&sk_event->event_node);
#if SOCK_WAIT_BATCH_NOTIFY
    list_init_node(&sk_event->stk_event_node);
#endif /* SOCK_WAIT_BATCH_NOTIFY */
    return 0;
}

void sock_event_free(struct sock_event *sk_event, struct sock_wait *sk_wait)
{
    if (sk_wait && sk_wait->type & WAIT_EPOLL) {
        rte_spinlock_lock(&sk_wait->epcb.lock);
        list_del_node(&sk_event->event_node);
        rte_spinlock_unlock(&sk_wait->epcb.lock);

#if SOCK_WAIT_BATCH_NOTIFY
        list_del_node(&sk_event->stk_event_node);
#endif /* SOCK_WAIT_BATCH_NOTIFY */
    }
}

int sock_wait_common_init(struct sock_wait *sk_wait)
{
    sk_wait->lwip_nfds = 0;
    sk_wait->kernel_nfds = 0;
    sys_sem_new_internal(&sk_wait->sem, 0);

#if SOCK_WAIT_BATCH_NOTIFY
    for (int i = 0; i < PROTOCOL_STACK_MAX; ++i) {
        list_init_node(&sk_wait->stk_notify_node[i]);
        list_init_head(&sk_wait->stk_event_list[i]);
    }
#endif /* SOCK_WAIT_BATCH_NOTIFY */
    sock_wait_group_add(sk_wait);

    return 0;
}

void sock_wait_common_free(struct sock_wait *sk_wait)
{
#if SOCK_WAIT_BATCH_NOTIFY
    bool wait_stack;

    /* wait lwip_wait_foreach_notify() finish. */
    do {
        wait_stack = false;
        for (int i = 0; i < PROTOCOL_STACK_MAX; ++i) {
            rte_mb();
            if (!list_node_null(&sk_wait->stk_notify_node[i])) {
                wait_stack = true;
                usleep(LWIP_EVENT_WAIT_US);
                break;
            }
        }
    } while (wait_stack);
#endif /* SOCK_WAIT_BATCH_NOTIFY */

    sock_wait_group_del(sk_wait);
    sys_sem_free_internal(&sk_wait->sem);
}

int sock_wait_kernel_init(struct sock_wait *sk_wait, int epfd, int stack_num)
{
    sk_wait->epfd = epfd;
    sk_wait->affinity.max_stack_id = affinity_choice_stack(stack_num);
    kernel_wait_ctl(sk_wait, sk_wait->affinity.max_stack_id, -1);
    sk_wait->affinity.bind_stack_id = sk_wait->affinity.max_stack_id;

    rte_atomic16_init(&sk_wait->kernel_pending);
    rte_atomic16_set(&sk_wait->kernel_pending, true);
    return 0;
}

void sock_wait_kernel_free(struct sock_wait *sk_wait)
{
    kernel_wait_ctl(sk_wait, -1, sk_wait->affinity.bind_stack_id);
    sk_wait->epfd = -1;
    sk_wait->affinity.bind_stack_id = -1;
    sk_wait->affinity.max_stack_id = -1;

    rte_atomic16_clear(&sk_wait->kernel_pending);
}


static inline bool NETCONN_NEED_ACCEPT(const struct lwip_sock *sock)
{
    if (sys_mbox_valid(&sock->conn->acceptmbox)) {
        const struct mbox_ring *mr = &sock->conn->acceptmbox->mring;
        return mr->ops->count(mr) > 0;
    }
    return false;
}

static inline bool NETCONN_NEED_RECV(const struct lwip_sock *sock)
{
    if (sock->lastdata.pbuf != NULL)
        return true;
    if (sys_mbox_valid(&sock->conn->recvmbox)) {
        const struct mbox_ring *mr = &sock->conn->recvmbox->mring;
        return mr->ops->recv_count(mr) > 0;
    }
    return false;
}

static inline bool NETCONN_ALLOW_SEND(const struct lwip_sock *sock)
{
    if (get_global_cfg_params()->stack_mode_rtc) {
        if (NETCONN_TYPE(sock->conn) == NETCONN_TCP)
            return lwip_tcp_allow_send(sock->conn->pcb.tcp);
        return false;
    }
    if (sys_mbox_valid(&sock->conn->sendmbox)) {
        const struct mbox_ring *mr = &sock->conn->sendmbox->mring;
        return mr->ops->free_count(mr) > 0;
    }
    return false;
}

static unsigned sock_event_lose_pending(const struct lwip_sock *sock, enum netconn_evt evt, unsigned len)
{
    unsigned event = 0;

    switch (evt) {
    case NETCONN_EVT_RCVMINUS:
        if (sock->sk_event.events & EPOLLIN) {
            if (!NETCONN_NEED_RECV(sock) && 
                !NETCONN_NEED_ACCEPT(sock)) {
                event = EPOLLIN;
            }
        }
        break;
    case NETCONN_EVT_SENDMINUS:
        if (sock->sk_event.events & EPOLLOUT) {
            if (!NETCONN_ALLOW_SEND(sock)) {
                event = EPOLLOUT;
            }
        }
        break;
    default:
        break;
    }

    return event;
}

unsigned sock_event_hold_pending(const struct lwip_sock *sock, 
    enum sock_wait_type type, enum netconn_evt evt, unsigned len)
{
    unsigned event = 0;

    switch (evt) {
    case NETCONN_EVT_RCVPLUS:
        if (sock->sk_event.events & EPOLLIN || type & WAIT_BLOCK) {
            if (len > 0 ||
                NETCONN_NEED_RECV(sock) || 
                NETCONN_NEED_ACCEPT(sock)) {
                event = EPOLLIN;
            }
        }
        break;
    case NETCONN_EVT_SENDPLUS:
        if (sock->sk_event.events & EPOLLOUT || type & WAIT_BLOCK) {
            if (len > 0 ||
                NETCONN_ALLOW_SEND(sock)) {
                event = EPOLLOUT;
            }
        }
        break;
    case NETCONN_EVT_ERROR:
        if (sock->errevent) {
            event = EPOLLERR | EPOLLHUP | EPOLLIN;
        }
        break;
    default:
        break;
    }

    return event;
}

void sock_event_remove_pending(struct lwip_sock *sock, enum netconn_evt evt, unsigned len)
{
    LWIP_DEBUGF(SOCKETS_DEBUG, ("%s(sock=%p, sk_wait=%p, evt=%d, len=%u)\n",
                __FUNCTION__, sock, sock->sk_wait, evt, len));

    if (sock->sk_wait == NULL) {
        return;
    }
    if (unlikely(sock->sk_wait->type == WAIT_CLOSE)) {
        sock->sk_wait = NULL;
        return;
    }

    unsigned pending = sock_event_lose_pending(sock, evt, 0);
    if (pending) {
        sock->sk_wait->remove_fn(sock->sk_wait, &sock->sk_event, pending);
    }
}

void sock_event_notify_pending(struct lwip_sock *sock, enum netconn_evt evt, unsigned len)
{
    LWIP_DEBUGF(SOCKETS_DEBUG, ("%s(sock=%p, sk_wait=%p, evt=%d, len=%u)\n",
                __FUNCTION__, sock, sock->sk_wait, evt, len));

    if (sock->sk_wait == NULL) {
        return;
    }
    if (unlikely(sock->sk_wait->type == WAIT_CLOSE)) {
        sock->sk_wait = NULL;
        return;
    }

    unsigned pending = sock_event_hold_pending(sock, sock->sk_wait->type, evt, len);
    if (pending) {
        sock->sk_wait->notify_fn(sock->sk_wait, &sock->sk_event, pending, sock->stack_id);
    }
}

#if SOCK_WAIT_BATCH_NOTIFY
/* Only allow stack call */
void lwip_wait_add_notify(struct sock_wait *sk_wait, struct sock_event *sk_event, 
    unsigned pending, int stack_id)
{
    struct lwip_wait *lwait = lwip_wait_get(stack_id);

    if (sk_event != NULL) {
        sk_event->stk_pending |= pending;
        if (list_node_null(&sk_event->stk_event_node)) {
            list_add_node(&sk_event->stk_event_node, &sk_wait->stk_event_list[stack_id]);
        }
    }

    if (list_node_null(&sk_wait->stk_notify_node[stack_id])) {
        list_add_node(&sk_wait->stk_notify_node[stack_id], &lwait->stk_notify_list);
    }
}

static inline
unsigned sock_wait_foreach_event(struct sock_wait *sk_wait, int stack_id)
{
    struct list_node *node, *next;
    struct sock_event *sk_event;
    unsigned count = 0;

    /* only rtw epoll need */
    if (list_head_empty(&sk_wait->stk_event_list[stack_id]))
        return 0;

    rte_spinlock_lock(&sk_wait->epcb.lock);

    list_for_each_node(node, next, &sk_wait->stk_event_list[stack_id]) {
        list_del_node(node);
        sk_event = container_of(node, struct sock_event, stk_event_node);

        /* see rtw_epoll_notify_event() */
        sk_event->pending |= sk_event->stk_pending;
        if (list_node_null(&sk_event->event_node)) {
            list_add_node(&sk_event->event_node, &sk_wait->epcb.event_list);
        }

        sk_event->stk_pending = 0;
        count++;
    }

    rte_spinlock_unlock(&sk_wait->epcb.lock);

    return count;
}

/* Only allow stack call */
unsigned lwip_wait_foreach_notify(int stack_id)
{
    struct lwip_wait *lwait = lwip_wait_get(stack_id);
    struct sock_wait *sk_wait;
    struct list_node *node, *next;
    unsigned count = 0;

    list_for_each_node(node, next, &lwait->stk_notify_list) {
        list_del_node(node);
        sk_wait = container_of_uncheck_ptr((node - stack_id), struct sock_wait, stk_notify_node);

        sock_wait_foreach_event(sk_wait, stack_id);

        sys_sem_signal_internal(&sk_wait->sem);
        count++;
    }
    return count;
}

bool lwip_wait_notify_empty(int stack_id)
{
    struct lwip_wait *lwait = lwip_wait_get(stack_id);
    return list_head_empty(&lwait->stk_notify_list);
}
#endif /* SOCK_WAIT_BATCH_NOTIFY */
