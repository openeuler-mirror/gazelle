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

#include <string.h>
#include <securec.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <time.h>
#include <poll.h>
#include <stdatomic.h>
#include <pthread.h>

#include <lwip/sockets.h>
#include <lwip/lwipgz_posix_api.h>

#include "lstack_stack_stat.h"
#include "lstack_cfg.h"
#include "lstack_log.h"
#include "common/dpdk_common.h"
#include "common/gazelle_base_func.h"
#include "lstack_lwip.h"
#include "lstack_protocol_stack.h"
#include "lstack_epoll.h"

#define EPOLL_KERNEL_INTERVAL   10 /* ms */
#define SEC_TO_NSEC             1000000000
#define SEC_TO_MSEC             1000
#define MSEC_TO_NSEC            1000000
#define POLL_KERNEL_EVENTS      32

static void update_epoll_max_stack(struct wakeup_poll *wakeup);
static void change_epollfd_kernel_thread(struct wakeup_poll *wakeup, struct protocol_stack *old_stack,
    struct protocol_stack *new_stack);

static inline void add_wakeup_to_stack_wakeuplist(struct wakeup_poll *wakeup, struct protocol_stack *stack)
{
    if (list_node_null(&wakeup->wakeup_list[stack->stack_idx])) {
        list_add_node(&wakeup->wakeup_list[stack->stack_idx], &stack->wakeup_list);
    }
}

void add_sock_event_nolock(struct lwip_sock *sock, uint32_t event)
{
    struct wakeup_poll *wakeup = sock->wakeup;

    if (wakeup == NULL || wakeup->type == WAKEUP_CLOSE || (event & sock->epoll_events) == 0) {
        return;
    }

    if (!get_global_cfg_params()->stack_mode_rtc) {
        if (event == EPOLLIN && !NETCONN_IS_DATAIN(sock) && !NETCONN_IS_ACCEPTIN(sock)) {
            return;
        }

        if (event == EPOLLOUT && !NETCONN_IS_OUTIDLE(sock)) {
            return;
        }
    }

    sock->events |= (event == EPOLLERR) ? (EPOLLIN | EPOLLERR) : (event & sock->epoll_events);
    if (list_node_null(&sock->event_list)) {
        list_add_node(&sock->event_list, &wakeup->event_list);
    }
    return;
}

static void _add_sock_event(struct lwip_sock *sock, struct wakeup_poll *wakeup, uint32_t event)
{
    struct protocol_stack *stack = sock->stack;
    if (wakeup == NULL || wakeup->type == WAKEUP_CLOSE) {
        return;
    }

    if (wakeup->type == WAKEUP_BLOCK) {
        if (!(event & (EPOLLIN | EPOLLERR))) {
            return;
        }
    } else if (!(event & sock->epoll_events)) {
        return;
    }

    if (wakeup->type == WAKEUP_EPOLL) {
        pthread_spin_lock(&wakeup->event_list_lock);
        add_sock_event_nolock(sock, event);
        pthread_spin_unlock(&wakeup->event_list_lock);
    }

    add_wakeup_to_stack_wakeuplist(wakeup, stack);
    return;
}

void add_sock_event(struct lwip_sock *sock, uint32_t event)
{
    _add_sock_event(sock, sock->wakeup, event);
    _add_sock_event(sock, sock->recv_block, event);
}

void del_sock_event_nolock(struct lwip_sock *sock, uint32_t event)
{
    if (get_global_cfg_params()->stack_mode_rtc) {
        sock->events &= ~event;
    } else {
        if ((event & EPOLLOUT) && !NETCONN_IS_OUTIDLE(sock)) {
            sock->events &= ~EPOLLOUT;
        }
        if ((event & EPOLLIN) && !NETCONN_IS_DATAIN(sock) && !NETCONN_IS_ACCEPTIN(sock)) {
            sock->events &= ~EPOLLIN;
        }
    }

    if (sock->events == 0) {
        list_del_node(&sock->event_list);
    }
    return;
}

void del_sock_event(struct lwip_sock *sock, uint32_t event)
{
    pthread_spin_lock(&sock->wakeup->event_list_lock);
    del_sock_event_nolock(sock, event);
    pthread_spin_unlock(&sock->wakeup->event_list_lock);
}

void wakeup_stack_epoll(struct protocol_stack *stack)
{
    struct list_node *node, *temp;

    list_for_each_node(node, temp, &stack->wakeup_list) {
        struct wakeup_poll *wakeup = container_of_uncheck_ptr((node - stack->stack_idx), struct wakeup_poll, wakeup_list);

        if (__atomic_load_n(&wakeup->in_wait, __ATOMIC_ACQUIRE)) {
            __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);
            rte_mb();
            sem_post(&wakeup->wait);
            stack->stats.wakeup_events++;
        }

        list_del_node(&wakeup->wakeup_list[stack->stack_idx]);
    }
}

static uint32_t update_events(struct lwip_sock *sock)
{
    uint32_t event = 0;

    if (sock->epoll_events & EPOLLIN) {
        if (NETCONN_IS_DATAIN(sock) || NETCONN_IS_ACCEPTIN(sock)) {
            event |= EPOLLIN;
        }
    }

    if ((sock->epoll_events & EPOLLOUT) && NETCONN_IS_OUTIDLE(sock)) {
        /* lwip_netconn_do_connected set LIBOS FLAGS when connected */
        if (!POSIX_IS_CLOSED(sock) && POSIX_IS_TYPE(sock, POSIX_LWIP)) {
            event |= EPOLLOUT;
        }
    }

    if (sock->errevent > 0) {
        event |= EPOLLERR | EPOLLIN;
    }

    return event;
}

static void rtc_raise_pending_events(struct wakeup_poll *wakeup, struct lwip_sock *sock)
{
    uint32_t event = 0;

    if (sock->rcvevent) {
        event |= EPOLLIN;
    }

    if (sock->errevent > 0) {
        event |= EPOLLERR | EPOLLIN;
    }

    if (sock->sendevent) {
        /* lwip_netconn_do_connected set LIBOS FLAGS when connected */
        if (!POSIX_IS_CLOSED(sock) && POSIX_IS_TYPE(sock, POSIX_LWIP)) {
            event |= EPOLLOUT;
        }
    }

    if (event) {
        sock->events = event;
        if (wakeup->type == WAKEUP_EPOLL && (sock->events & sock->epoll_events) &&
            list_node_null(&sock->event_list)) {
            list_add_node(&sock->event_list, &wakeup->event_list);
        }
    }
}

static void raise_pending_events(struct wakeup_poll *wakeup, struct lwip_sock *sock)
{
    uint32_t event = 0;

    pthread_spin_lock(&wakeup->event_list_lock);
    if (NETCONN_IS_DATAIN(sock) || NETCONN_IS_ACCEPTIN(sock)) {
        event |= EPOLLIN;
    }

    if (sock->errevent > 0) {
        event |= EPOLLERR | EPOLLIN;
    }

    if (NETCONN_IS_OUTIDLE(sock)) {
        /* lwip_netconn_do_connected set LIBOS FLAGS when connected */
        if (!POSIX_IS_CLOSED(sock) && POSIX_IS_TYPE(sock, POSIX_LWIP)) {
            event |= EPOLLOUT;
        }
    }

    if (event) {
        sock->events = event;
        if (wakeup->type == WAKEUP_EPOLL && (sock->events & sock->epoll_events) &&
            list_node_null(&sock->event_list)) {
            list_add_node(&sock->event_list, &wakeup->event_list);
            rte_mb();
            sem_post(&wakeup->wait);
        }
    }
    pthread_spin_unlock(&wakeup->event_list_lock);
}

int32_t lstack_do_epoll_create(int32_t fd)
{
    if (fd < 0) {
        return fd;
    }

    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "fd=%d sock is NULL errno=%d\n", fd, errno);
        posix_api->close_fn(fd);
        GAZELLE_RETURN(EINVAL);
    }

    struct wakeup_poll *wakeup = calloc(1, sizeof(struct wakeup_poll));
    if (wakeup == NULL) {
        LSTACK_LOG(ERR, LSTACK, "calloc null\n");
        posix_api->close_fn(fd);
        GAZELLE_RETURN(EINVAL);
    }

    for (uint32_t i = 0; i < PROTOCOL_STACK_MAX; i++) {
        list_init_node(&wakeup->wakeup_list[i]);
    }

    if (sem_init(&wakeup->wait, 0, 0) != 0) {
        posix_api->close_fn(fd);
        free(wakeup);
        GAZELLE_RETURN(EINVAL);
    }
    __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    list_init_node(&wakeup->poll_list);
    pthread_spin_lock(&stack_group->poll_list_lock);
    list_add_node(&wakeup->poll_list, &stack_group->poll_list);
    pthread_spin_unlock(&stack_group->poll_list_lock);

    list_init_head(&wakeup->event_list);
    pthread_spin_init(&wakeup->event_list_lock, PTHREAD_PROCESS_PRIVATE);

    wakeup->type = WAKEUP_EPOLL;
    wakeup->epollfd = fd;
    sock->wakeup = wakeup;

    if (!get_global_cfg_params()->stack_mode_rtc) {
        update_epoll_max_stack(wakeup);
        change_epollfd_kernel_thread(wakeup, wakeup->bind_stack, wakeup->max_stack);
        wakeup->bind_stack = wakeup->max_stack;
        if (get_global_cfg_params()->app_bind_numa) {
            bind_to_stack_numa(wakeup->bind_stack);
        }
    } else {
        wakeup->bind_stack = wakeup->max_stack = get_protocol_stack();
        change_epollfd_kernel_thread(wakeup, NULL, wakeup->max_stack);
    }

    return fd;
}

int32_t lstack_epoll_create1(int32_t flags)
{
    int32_t fd = posix_api->epoll_create1_fn(flags);
    return lstack_do_epoll_create(fd);
}

int32_t lstack_epoll_create(int32_t flags)
{
    int32_t fd = posix_api->epoll_create_fn(flags);
    return lstack_do_epoll_create(fd);
}

static void stack_broadcast_clean_epoll(struct wakeup_poll *wakeup)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    struct protocol_stack *stack = NULL;

    for (int32_t i = 0; i < stack_group->stack_num; i++) {
        stack = stack_group->stacks[i];
        rpc_call_clean_epoll(&stack->rpc_queue, wakeup);
    }
}

int32_t lstack_epoll_close(int32_t fd)
{
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "fd=%d sock is NULL errno=%d\n", fd, errno);
        GAZELLE_RETURN(EINVAL);
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    struct wakeup_poll *wakeup = sock->wakeup;
    if (wakeup == NULL) {
        return 0;
    }

    wakeup->type = WAKEUP_CLOSE;

    if (!get_global_cfg_params()->stack_mode_rtc) {
        stack_broadcast_clean_epoll(wakeup);
    }

    struct list_node *node, *temp;
    pthread_spin_lock(&wakeup->event_list_lock);
    list_for_each_node(node, temp, &wakeup->event_list) {
        struct lwip_sock *sock = list_entry(node, struct lwip_sock, event_list);
        list_del_node(&sock->event_list);
    }
    pthread_spin_unlock(&wakeup->event_list_lock);
    pthread_spin_destroy(&wakeup->event_list_lock);

    pthread_spin_lock(&stack_group->poll_list_lock);
    list_del_node(&wakeup->poll_list);
    pthread_spin_unlock(&stack_group->poll_list_lock);

    sem_destroy(&wakeup->wait);

    free(wakeup);
    sock->wakeup = NULL;

    posix_api->close_fn(fd);
    return 0;
}

static uint16_t find_max_cnt_stack(int32_t *stack_count, uint16_t stack_num, struct protocol_stack *last_stack)
{
    uint16_t max_index = 0;
    bool all_same_cnt = true;

    for (uint16_t i = 1; i < stack_num; i++) {
        if (stack_count[i] != stack_count[0]) {
            all_same_cnt = false;
        }

        if (stack_count[i] > stack_count[max_index]) {
            max_index = i;
        }
    }

    /* all stack same, don't change */
    if (all_same_cnt && last_stack) {
        return last_stack->stack_idx;
    }

    /* first bind and all stack same. choice tick as queue_id, avoid all bind to statck_0. */
    static _Atomic uint16_t tick = 0;
    if (all_same_cnt && stack_num) {
        max_index = atomic_fetch_add(&tick, 1) % stack_num;
    }

    return max_index;
}

static void update_epoll_max_stack(struct wakeup_poll *wakeup)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    uint16_t bind_id = find_max_cnt_stack(wakeup->stack_fd_cnt, stack_group->stack_num, wakeup->max_stack);

    wakeup->max_stack = stack_group->stacks[bind_id];
}

int32_t lstack_rtc_epoll_ctl(int32_t epfd, int32_t op, int32_t fd, struct epoll_event *event)
{
    if (epfd < 0 || fd < 0 || epfd == fd || (event == NULL && op != EPOLL_CTL_DEL)) {
        LSTACK_LOG(ERR, LSTACK, "fd=%d epfd=%d op=%d\n", fd, epfd, op);
        GAZELLE_RETURN(EINVAL);
    }

    struct lwip_sock *epoll_sock = lwip_get_socket(epfd);
    if (epoll_sock == NULL || epoll_sock->wakeup == NULL) {
        return posix_api->epoll_ctl_fn(epfd, op, fd, event);
    }

    struct wakeup_poll *wakeup = epoll_sock->wakeup;
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (POSIX_IS_CLOSED(sock)) {
        return posix_api->epoll_ctl_fn(epfd, op, fd, event);
    }

    switch (op) {
        case EPOLL_CTL_ADD:
            sock->wakeup = wakeup;
            /* fall through */
        case EPOLL_CTL_MOD:
            sock->epoll_events = event->events | EPOLLERR | EPOLLHUP;
            sock->ep_data = event->data;
            rtc_raise_pending_events(wakeup, sock);
            break;
        case EPOLL_CTL_DEL:
            sock->epoll_events = 0;
            list_del_node(&sock->event_list);
            break;
        default:
            GAZELLE_RETURN(EINVAL);
    }

    return 0;
}

int32_t lstack_rtw_epoll_ctl(int32_t epfd, int32_t op, int32_t fd, struct epoll_event *event)
{
    LSTACK_LOG(DEBUG, LSTACK, "op=%d events: fd: %d\n", op, fd);

    if (epfd < 0 || fd < 0 || epfd == fd || (event == NULL && op != EPOLL_CTL_DEL)) {
        LSTACK_LOG(ERR, LSTACK, "fd=%d epfd=%d op=%d\n", fd, epfd, op);
        GAZELLE_RETURN(EINVAL);
    }

    struct lwip_sock *epoll_sock = lwip_get_socket(epfd);
    if (epoll_sock == NULL || epoll_sock->wakeup == NULL) {
        return posix_api->epoll_ctl_fn(epfd, op, fd, event);
    }

    struct wakeup_poll *wakeup = epoll_sock->wakeup;
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (POSIX_IS_CLOSED(sock) || POSIX_IS_TYPE(sock, POSIX_KERNEL)) {
        return posix_api->epoll_ctl_fn(epfd, op, fd, event);
    }

    if (POSIX_HAS_TYPE(sock, POSIX_KERNEL)) {
        int32_t ret = posix_api->epoll_ctl_fn(epfd, op, fd, event);
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "fd=%d epfd=%d op=%d errno=%d\n", fd, epfd, op, errno);
        }
    }

    do {
        switch (op) {
            case EPOLL_CTL_ADD:
                sock->wakeup = wakeup;
                wakeup->stack_fd_cnt[sock->stack->stack_idx]++;
                /* fall through */
            case EPOLL_CTL_MOD:
                sock->epoll_events = event->events | EPOLLERR | EPOLLHUP;
                sock->ep_data = event->data;
                raise_pending_events(wakeup, sock);
                break;
            case EPOLL_CTL_DEL:
                sock->epoll_events = 0;
                wakeup->stack_fd_cnt[sock->stack->stack_idx]--;
                pthread_spin_lock(&wakeup->event_list_lock);
                list_del_node(&sock->event_list);
                pthread_spin_unlock(&wakeup->event_list_lock);
                break;
            default:
                GAZELLE_RETURN(EINVAL);
        }
        sock = sock->listen_next;
    } while (sock != NULL);

    update_epoll_max_stack(wakeup);
    return 0;
}

int32_t epoll_lwip_event_nolock(struct wakeup_poll *wakeup, struct epoll_event *events, uint32_t maxevents)
{
    int32_t event_num = 0;
    struct list_node *node, *temp;

    list_for_each_node(node, temp, &wakeup->event_list) {
        struct lwip_sock *sock = list_entry(node, struct lwip_sock, event_list);

        if ((sock->epoll_events & sock->events) == 0) {
            list_del_node(node);
            continue;
        }
        
        if (event_num >= maxevents) {
            /* move list head after the current node, and start traversing from this node next time */
            list_del_node(&wakeup->event_list);
            list_add_node(&wakeup->event_list, node);
            break;
        }
        
        events[event_num].events = sock->events & sock->epoll_events;
        events[event_num].data = sock->ep_data;
        event_num++;

        if (sock->epoll_events & EPOLLET) {
            list_del_node(node);
            sock->events = 0;
        }

        /* EPOLLONESHOT: generate event after epoll_ctl add/mod event again
           epoll_event set 0 avoid generating event util epoll_ctl reset epoll_event */
        if (sock->epoll_events & EPOLLONESHOT) {
            list_del_node(node);
            sock->epoll_events = 0;
        }
    }

    return event_num;
}

static int32_t epoll_lwip_event(struct wakeup_poll *wakeup, struct epoll_event *events, uint32_t maxevents)
{
    int32_t event_num;

    pthread_spin_lock(&wakeup->event_list_lock);
    event_num = epoll_lwip_event_nolock(wakeup, events, maxevents);
    pthread_spin_unlock(&wakeup->event_list_lock);

    return event_num;
}

static int32_t poll_lwip_event(struct pollfd *fds, nfds_t nfds)
{
    int32_t event_num = 0;

    for (uint32_t i = 0; i < nfds; i++) {
        /* sock->listen_next pointerto next stack listen */
        int32_t fd = fds[i].fd;
        struct lwip_sock *sock = lwip_get_socket(fd);
        while (!POSIX_IS_CLOSED(sock)) {
            uint32_t events = update_events(sock);
            if (events) {
                fds[i].revents = events;
                event_num++;
                break;
            }

            sock = sock->listen_next;
        }
    }

    return event_num;
}

static void change_epollfd_kernel_thread(struct wakeup_poll *wakeup, struct protocol_stack *old_stack,
    struct protocol_stack *new_stack)
{
    if (old_stack) {
        if (posix_api->epoll_ctl_fn(old_stack->epollfd, EPOLL_CTL_DEL, wakeup->epollfd, NULL) != 0) {
            LSTACK_LOG(ERR, LSTACK, "epoll_ctl_fn errno=%d\n", errno);
        }
    }

    /* avoid kernel thread post too much, use EPOLLET */
    struct epoll_event event;
    event.data.ptr = wakeup;
    event.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLET;
    if (posix_api->epoll_ctl_fn(new_stack->epollfd, EPOLL_CTL_ADD, wakeup->epollfd, &event) != 0) {
        LSTACK_LOG(ERR, LSTACK, "epoll_ctl_fn errno=%d\n", errno);
    }
}

static void epoll_bind_statck(struct wakeup_poll *wakeup)
{
    if (wakeup->bind_stack != wakeup->max_stack && wakeup->max_stack) {
        bind_to_stack_numa(wakeup->max_stack);
        change_epollfd_kernel_thread(wakeup, wakeup->bind_stack, wakeup->max_stack);
        wakeup->bind_stack = wakeup->max_stack;
    }
}

static void ms_to_timespec(struct timespec *timespec, int32_t timeout)
{
    clock_gettime(CLOCK_REALTIME, timespec);
    timespec->tv_sec += timeout / SEC_TO_MSEC;
    timespec->tv_nsec += (timeout % SEC_TO_MSEC) * MSEC_TO_NSEC;
    timespec->tv_sec += timespec->tv_nsec / SEC_TO_NSEC;
    timespec->tv_nsec = timespec->tv_nsec % SEC_TO_NSEC;
}

/**
 * Block lstack thread
 *
 * @param wakeup
 *  The pointer to the wakeup_poll.
 * @param timeout
 *  The time to wait, if 'timeout <= 0' will block until unlock
 *
 * @return
 * - return '0' on unlock
 * - return 'ETIMEDOUT' on timeout
 */
int32_t lstack_block_wait(struct wakeup_poll *wakeup, int32_t timeout)
{
    int ret = 0;
    if (wakeup == NULL) {
        return ret;
    }

    __atomic_store_n(&wakeup->in_wait, true, __ATOMIC_RELEASE);
    if (timeout > 0) {
        struct timespec timespec;
        ms_to_timespec(&timespec, timeout);
        ret = sem_timedwait(&wakeup->wait, &timespec);
    } else {
        ret = sem_wait(&wakeup->wait);
    }

    if (__atomic_load_n(&wakeup->in_wait, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);
    }

    return ret;
}

int32_t lstack_rtc_epoll_wait(int32_t epfd, struct epoll_event* events, int32_t maxevents, int32_t timeout)
{
    struct lwip_sock *sock = lwip_get_socket(epfd);

    if (sock == NULL || sock->wakeup == NULL) {
        return posix_api->epoll_wait_fn(epfd, events, maxevents, timeout);
    }

    struct wakeup_poll *wakeup = sock->wakeup;
    int32_t lwip_num = 0;
    /* 16: avoid app process events for a long time */
    int32_t tmpmaxevents = 16;
    /* avoid the starvation of epoll events from both netstack */
    int host_maxevents = tmpmaxevents / 2;
    uint32_t poll_ts = sys_now();
    bool loop_flag;
    int32_t kernel_num = 0;
    int32_t tmptimeout = timeout;

    do {
        stack_polling(0);
        if (__atomic_load_n(&wakeup->have_kernel_event, __ATOMIC_ACQUIRE)) {
            kernel_num = posix_api->epoll_wait_fn(epfd, events, host_maxevents, 0);
            if (!kernel_num) {
                __atomic_store_n(&wakeup->have_kernel_event, false, __ATOMIC_RELEASE);
            }
        }
        if (tmptimeout > 0) {
            if (tmptimeout <= sys_now() - poll_ts) {
                tmptimeout = 0;
            }
        }

        loop_flag = false;
        if (!kernel_num && list_head_empty(&wakeup->event_list) && tmptimeout != 0) {
            loop_flag = true;
        }
    } while (loop_flag);

    if (kernel_num < 0) {
        LSTACK_LOG(ERR, LSTACK, "lstack_rtc_epoll_wait: kernel event failed\n");
        return kernel_num;
    }

    lwip_num = epoll_lwip_event_nolock(wakeup, &events[kernel_num], tmpmaxevents - kernel_num);
    wakeup->stat.app_events += lwip_num;
    wakeup->stat.kernel_events += kernel_num;

    return lwip_num + kernel_num;
}

int32_t lstack_rtw_epoll_wait(int32_t epfd, struct epoll_event* events, int32_t maxevents, int32_t timeout)
{
    struct lwip_sock *sock = lwip_get_socket(epfd);
    if (sock == NULL || sock->wakeup == NULL) {
        return posix_api->epoll_wait_fn(epfd, events, maxevents, timeout);
    }

    struct wakeup_poll *wakeup = sock->wakeup;
    int32_t kernel_num = 0;
    int32_t lwip_num = 0;

    if (get_global_cfg_params()->app_bind_numa) {
        epoll_bind_statck(sock->wakeup);
    }

    do {
        __atomic_store_n(&wakeup->in_wait, true, __ATOMIC_RELEASE);
        lwip_num = epoll_lwip_event(wakeup, events, maxevents);

        if (__atomic_load_n(&wakeup->have_kernel_event, __ATOMIC_ACQUIRE)) {
            kernel_num = posix_api->epoll_wait_fn(epfd, &events[lwip_num], maxevents - lwip_num, 0);
            if (!kernel_num) {
                __atomic_store_n(&wakeup->have_kernel_event, false, __ATOMIC_RELEASE);
            }
        }

        if (lwip_num + kernel_num > 0) {
            break;
        }

        if (timeout == 0) {
            break;
        }
    } while (lstack_block_wait(wakeup, timeout) == 0);

    __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);
    wakeup->stat.app_events += lwip_num;
    wakeup->stat.kernel_events += kernel_num;

    return lwip_num + kernel_num;
}

static int32_t init_poll_wakeup_data(struct wakeup_poll *wakeup)
{
    if (sem_init(&wakeup->wait, 0, 0) != 0) {
        GAZELLE_RETURN(EINVAL);
    }
    __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);

    for (uint32_t i = 0; i < PROTOCOL_STACK_MAX; i++) {
        list_init_node(&wakeup->wakeup_list[i]);
    }

    wakeup->epollfd = posix_api->epoll_create_fn(POLL_KERNEL_EVENTS);
    if (wakeup->epollfd < 0) {
        GAZELLE_RETURN(EINVAL);
    }

    wakeup->type = WAKEUP_POLL;

    wakeup->last_fds = calloc(POLL_KERNEL_EVENTS, sizeof(struct pollfd));
    if (wakeup->last_fds == NULL) {
        GAZELLE_RETURN(EINVAL);
    }
    wakeup->last_max_nfds = POLL_KERNEL_EVENTS;

    wakeup->events = calloc(POLL_KERNEL_EVENTS, sizeof(struct epoll_event));
    if (wakeup->events == NULL) {
        free(wakeup->last_fds);
        wakeup->last_fds = NULL;
        GAZELLE_RETURN(EINVAL);
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    list_init_node(&wakeup->poll_list);
    pthread_spin_lock(&stack_group->poll_list_lock);
    list_add_node(&wakeup->poll_list, &stack_group->poll_list);
    pthread_spin_unlock(&stack_group->poll_list_lock);

    int32_t stack_count[PROTOCOL_STACK_MAX] = {0};
    uint16_t bind_id = find_max_cnt_stack(stack_count, stack_group->stack_num, wakeup->bind_stack);
    change_epollfd_kernel_thread(wakeup, wakeup->bind_stack, stack_group->stacks[bind_id]);
    wakeup->bind_stack = stack_group->stacks[bind_id];
    if (get_global_cfg_params()->app_bind_numa) {
        bind_to_stack_numa(wakeup->bind_stack);
    }

    return 0;
}

static int resize_kernel_poll(struct wakeup_poll *wakeup, nfds_t nfds)
{
    if (wakeup->last_fds) {
        free(wakeup->last_fds);
    }
    wakeup->last_fds = calloc(nfds, sizeof(struct pollfd));
    if (wakeup->last_fds == NULL) {
        LSTACK_LOG(ERR, LSTACK, "calloc failed errno=%d\n", errno);
        return -1;
    }

    if (wakeup->events) {
        free(wakeup->events);
    }
    wakeup->events = calloc(nfds, sizeof(struct epoll_event));
    if (wakeup->events == NULL) {
        LSTACK_LOG(ERR, LSTACK, "calloc failed errno=%d\n", errno);
        free(wakeup->last_fds);
        wakeup->last_fds = NULL;
        return -1;
    }

    wakeup->last_max_nfds = nfds;
    return 0;
}

static void poll_bind_statck(struct wakeup_poll *wakeup, int32_t *stack_count)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    uint16_t bind_id = find_max_cnt_stack(stack_count, stack_group->stack_num, wakeup->bind_stack);
    if (wakeup->bind_stack && wakeup->bind_stack->queue_id == bind_id) {
        return;
    }

    change_epollfd_kernel_thread(wakeup, wakeup->bind_stack, stack_group->stacks[bind_id]);
    bind_to_stack_numa(stack_group->stacks[bind_id]);
    wakeup->bind_stack = stack_group->stacks[bind_id];
}

static void update_kernel_poll(struct wakeup_poll *wakeup, uint32_t index, struct pollfd *new_fd)
{
    posix_api->epoll_ctl_fn(wakeup->epollfd, EPOLL_CTL_DEL, wakeup->last_fds[index].fd, NULL);

    if (new_fd == NULL) {
        return;
    }

    struct epoll_event event;
    event.data.u32 = index;
    event.events = new_fd->events;
    if (posix_api->epoll_ctl_fn(wakeup->epollfd, EPOLL_CTL_ADD, new_fd->fd, &event) != 0) {
        LSTACK_LOG(ERR, LSTACK, "epoll_ctl_fn errno=%d\n", errno);
    }
}

static int poll_init(struct wakeup_poll *wakeup, struct pollfd *fds, nfds_t nfds)
{
    int32_t stack_count[PROTOCOL_STACK_MAX] = {0};
    int32_t poll_change = 0;
    int ret = 0;

    /* poll fds num more, recalloc fds size */
    if (nfds > wakeup->last_max_nfds) {
        ret = resize_kernel_poll(wakeup, nfds);
        if (ret < 0) {
            return -1;
        }
        poll_change = 1;
    }

    if (nfds < wakeup->last_nfds) {
        poll_change = 1;
    }

    for (uint32_t i = 0; i < nfds; i++) {
        int32_t fd = fds[i].fd;
        fds[i].revents = 0;
        struct lwip_sock *sock = lwip_get_socket(fd);

        if (fd == wakeup->last_fds[i].fd && fds[i].events == wakeup->last_fds[i].events) {
            /* fd close then socket may get same fd. */
            if (sock == NULL || sock->wakeup != NULL) {
                continue;
            }
        }

        if (POSIX_IS_CLOSED(sock) || POSIX_HAS_TYPE(sock, POSIX_KERNEL)) {
            update_kernel_poll(wakeup, i, fds + i);
        }

        wakeup->last_fds[i].fd = fd;
        wakeup->last_fds[i].events = fds[i].events;
        poll_change = 1;

        while (!POSIX_IS_CLOSED(sock)) {
            sock->epoll_events = fds[i].events | POLLERR;
            sock->wakeup = wakeup;
            stack_count[sock->stack->stack_idx]++;
            sock = sock->listen_next;
        }
    }

    if (poll_change == 0) {
        return 0;
    }
    wakeup->last_nfds = nfds;

    if (get_global_cfg_params()->app_bind_numa) {
        poll_bind_statck(wakeup, stack_count);
    }
    return 0;
}

struct wakeup_poll* poll_construct_wakeup(void)
{
    static PER_THREAD struct wakeup_poll *wakeup = NULL;
    if (wakeup == NULL) {
        wakeup = calloc(1, sizeof(struct wakeup_poll));
        if (wakeup == NULL) {
            LSTACK_LOG(ERR, LSTACK, "calloc failed errno=%d\n", errno);
            return NULL;
        }

        if (init_poll_wakeup_data(wakeup) < 0) {
            free(wakeup);
            return NULL;
        }
    }
    return wakeup;
}

int32_t lstack_poll(struct pollfd *fds, nfds_t nfds, int32_t timeout)
{
    struct wakeup_poll *wakeup = poll_construct_wakeup();
    if (wakeup == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    if (poll_init(wakeup, fds, nfds) < 0) {
        free(wakeup);
        GAZELLE_RETURN(EINVAL);
    }

    int32_t kernel_num = 0;
    int32_t lwip_num = 0;

    do {
        __atomic_store_n(&wakeup->in_wait, true, __ATOMIC_RELEASE);
        lwip_num = poll_lwip_event(fds, nfds);

        if (__atomic_load_n(&wakeup->have_kernel_event, __ATOMIC_ACQUIRE)) {
            kernel_num = posix_api->epoll_wait_fn(wakeup->epollfd, wakeup->events, nfds, 0);
            for (int32_t i = 0; i < kernel_num; i++) {
                uint32_t index = wakeup->events[i].data.u32;
                fds[index].revents = wakeup->events[i].events;
            }
            if (!kernel_num) {
                __atomic_store_n(&wakeup->have_kernel_event, false, __ATOMIC_RELEASE);
            }
        }

        if (lwip_num + kernel_num > 0) {
            break;
        }

        if (timeout == 0) {
            break;
        }
    } while (lstack_block_wait(wakeup, timeout) == 0);

    __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);
    wakeup->stat.app_events += lwip_num;
    wakeup->stat.kernel_events += kernel_num;

    return lwip_num + kernel_num;
}

static void select_set_revent_fdset(struct pollfd *fds, nfds_t nfds, fd_set *eventfds, uint32_t event)
{
    FD_ZERO(eventfds);

    /* Set the fd_set parameter based on the actual revents. */
    for (int i = 0; i < nfds; i++) {
        if (fds[i].revents & event) {
            FD_SET(fds[i].fd, eventfds);
        }
    }
}

static void fds_poll2select(struct pollfd *fds, nfds_t nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
    if (fds == NULL || nfds == 0) {
        return;
    }
    
    if (readfds) {
        select_set_revent_fdset(fds, nfds, readfds, EPOLLIN);
    }
    if (writefds) {
        select_set_revent_fdset(fds, nfds, writefds, EPOLLOUT);
    }
    if (exceptfds) {
        select_set_revent_fdset(fds, nfds, exceptfds, EPOLLERR);
    }
}

static inline int timeval_to_ms(struct timeval *timeval, int32_t *timeout)
{
    if (!timeval) {
        *timeout = -1;
        return 0;
    }
    if (unlikely((timeval->tv_sec < 0 || timeval->tv_usec < 0 || timeval->tv_usec >= 1000000))) {
        return -1;
    }
    *timeout = timeval->tv_sec * 1000 + timeval->tv_usec / 1000;
    return 0;
}

static nfds_t fds_select2poll(int maxfd, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct pollfd *fds)
{
    struct pollfd *pollfds = fds;
    nfds_t nfds = 0;

    for (int i = 0; i < maxfd; i++) {
        if (readfds && FD_ISSET(i, readfds)) {
            pollfds[nfds].events = POLLIN;
        }
        if (writefds && FD_ISSET(i, writefds)) {
            pollfds[nfds].events |= POLLOUT;
        }
        if (exceptfds && FD_ISSET(i, exceptfds)) {
            pollfds[nfds].events |= POLLERR;
        }
        if (pollfds[nfds].events > 0) {
            pollfds[nfds].fd = i;
            nfds++;
        }
    }
    return nfds;
}

int lstack_select(int maxfd, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeval)
{
    if (maxfd < 0 || maxfd > FD_SETSIZE) {
        LSTACK_LOG(ERR, LSTACK, "select input param error, fd num=%d\n", maxfd);
        GAZELLE_RETURN(EINVAL);
    }
    
    /* Convert the select parameter to the poll parameter. */
    struct pollfd fds[FD_SETSIZE] = { 0 };
    nfds_t nfds = fds_select2poll(maxfd, readfds, writefds, exceptfds, fds);
    int timeout = 0;
    if (timeval_to_ms(timeval, &timeout)) {
        LSTACK_LOG(ERR, LSTACK, "select input param timeout error.\n");
        GAZELLE_RETURN(EINVAL);
    }

    int event_num = lstack_poll(fds, nfds, timeout);
    
    /* After poll, set select fd_set by fds.revents. */
    fds_poll2select(fds, nfds, readfds, writefds, exceptfds);

    return event_num;
}
