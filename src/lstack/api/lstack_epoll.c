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
#include <time.h>
#include <poll.h>
#include <stdatomic.h>
#include <pthread.h>

#include <lwip/lwipsock.h>
#include <lwip/sockets.h>
#include <lwip/eventpoll.h>
#include <lwip/api.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>
#include <lwip/posix_api.h>

#include "lstack_ethdev.h"
#include "lstack_stack_stat.h"
#include "lstack_cfg.h"
#include "lstack_log.h"
#include "dpdk_common.h"
#include "gazelle_base_func.h"
#include "lstack_lwip.h"
#include "lstack_protocol_stack.h"
#include "posix/lstack_epoll.h"

#define EPOLL_KERNEL_INTERVAL   10 /* ms */
#define SEC_TO_NSEC             1000000000
#define SEC_TO_MSEC             1000
#define MSEC_TO_NSEC            1000000
#define POLL_KERNEL_EVENTS      32

static void update_epoll_max_stack(struct wakeup_poll *wakeup);
static void change_epollfd_kernel_thread(struct wakeup_poll *wakeup, struct protocol_stack *old_stack,
    struct protocol_stack *new_stack);

void add_sock_event(struct lwip_sock *sock, uint32_t event)
{
    struct wakeup_poll *wakeup = sock->wakeup;
    if (wakeup == NULL || wakeup->type == WAKEUP_CLOSE || (event & sock->epoll_events) == 0) {
        return;
    }

    if (wakeup->type == WAKEUP_EPOLL) {
        pthread_spin_lock(&wakeup->event_list_lock);

        /* app thread have read/write, event is outdated */
        if (event == EPOLLIN && sock->conn->state != NETCONN_LISTEN && !NETCONN_IS_DATAIN(sock)) {
            pthread_spin_unlock(&wakeup->event_list_lock);
            return;
        }
        if (event == EPOLLOUT && !NETCONN_IS_OUTIDLE(sock)) {
            pthread_spin_unlock(&wakeup->event_list_lock);
            return;
        }

        sock->events |= (event == EPOLLERR) ? (EPOLLIN | EPOLLERR) : (event & sock->epoll_events);
        if (list_is_null(&sock->event_list)) {
            list_add_node(&wakeup->event_list, &sock->event_list);
        }
        pthread_spin_unlock(&wakeup->event_list_lock);
    }

    struct protocol_stack *stack = sock->stack;
    if (list_is_null(&wakeup->wakeup_list[stack->stack_idx])) {
        list_add_node(&stack->wakeup_list, &wakeup->wakeup_list[stack->stack_idx]);
    }
}

void wakeup_stack_epoll(struct protocol_stack *stack, bool wakeup_thread_enable)
{
    struct list_node *node, *temp;

    list_for_each_safe(node, temp, &stack->wakeup_list) {
        /* When temp is NULL, find the tail node in the wekeup_list and connect it to the back of the node */
        if (unlikely(temp == NULL)) {
            struct list_node *nod = &stack->wakeup_list;
            while (nod->prev && nod->prev != node) {
                nod = nod->prev;
            }
            nod->prev = node;
            node->next = nod;
            temp = nod;
        }

        struct wakeup_poll *wakeup = container_of((node - stack->stack_idx), struct wakeup_poll, wakeup_list);

        if (!wakeup_thread_enable) {
            if (__atomic_load_n(&wakeup->in_wait, __ATOMIC_ACQUIRE)) {
                __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);
                rte_mb();
                pthread_mutex_unlock(&wakeup->wait);
                stack->stats.wakeup_events++;
            }
        } else {
            gazelle_light_ring_enqueue_busrt(stack->wakeup_ring, (void **)&wakeup, 1);
            stack->stats.wakeup_events++;
        }

        list_del_node_null(&wakeup->wakeup_list[stack->stack_idx]);
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
        if (sock->conn && CONN_TYPE_IS_LIBOS(sock->conn)) {
            event |= EPOLLOUT;
        }
    }

    if (sock->errevent > 0) {
        event |= EPOLLERR | EPOLLIN;
    }

    return event;
}

static void raise_pending_events(struct wakeup_poll *wakeup, struct lwip_sock *sock)
{
    uint32_t event = 0;

    if (NETCONN_IS_DATAIN(sock) || NETCONN_IS_ACCEPTIN(sock)) {
        event |= EPOLLIN;
    }

    if (NETCONN_IS_OUTIDLE(sock)) {
        /* lwip_netconn_do_connected set LIBOS FLAGS when connected */
        if (sock->conn && CONN_TYPE_IS_LIBOS(sock->conn)) {
            event |= EPOLLOUT;
        }
    }

    if (sock->errevent > 0) {
        event |= EPOLLERR | EPOLLIN;
    }

    if (event) {
        pthread_spin_lock(&wakeup->event_list_lock);
        sock->events = event;
        if (wakeup->type == WAKEUP_EPOLL && (sock->events & sock->epoll_events) &&
            list_is_null(&sock->event_list)) {
            list_add_node(&wakeup->event_list, &sock->event_list);
        }
        pthread_spin_unlock(&wakeup->event_list_lock);
    }
}

int32_t lstack_do_epoll_create(int32_t fd)
{
    if (fd < 0) {
        return fd;
    }

    struct lwip_sock *sock = get_socket_by_fd(fd);
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
        init_list_node_null(&wakeup->wakeup_list[i]);
    }

    if (pthread_mutex_init(&wakeup->wait, NULL) != 0) {
        posix_api->close_fn(fd);
        free(wakeup);
        GAZELLE_RETURN(EINVAL);
    }
    pthread_mutex_trylock(&wakeup->wait);
    __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    init_list_node_null(&wakeup->poll_list);
    pthread_spin_lock(&stack_group->poll_list_lock);
    list_add_node(&stack_group->poll_list, &wakeup->poll_list);
    pthread_spin_unlock(&stack_group->poll_list_lock);

    init_list_node(&wakeup->event_list);
    pthread_spin_init(&wakeup->event_list_lock, PTHREAD_PROCESS_PRIVATE);

    wakeup->type = WAKEUP_EPOLL;
    wakeup->epollfd = fd;
    sock->wakeup = wakeup;

    update_epoll_max_stack(wakeup);
    change_epollfd_kernel_thread(wakeup, wakeup->bind_stack, wakeup->max_stack);
    wakeup->bind_stack = wakeup->max_stack;
    if (get_global_cfg_params()->app_bind_numa) {
        bind_to_stack_numa(wakeup->bind_stack);
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

int32_t lstack_epoll_close(int32_t fd)
{
    struct lwip_sock *sock = get_socket_by_fd(fd);
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

    stack_broadcast_clean_epoll(wakeup);

    struct list_node *node, *temp;
    pthread_spin_lock(&wakeup->event_list_lock);
    list_for_each_safe(node, temp, &wakeup->event_list) {
        struct lwip_sock *sock = container_of(node, struct lwip_sock, event_list);
        list_del_node_null(&sock->event_list);
    }
    pthread_spin_unlock(&wakeup->event_list_lock);
    pthread_spin_destroy(&wakeup->event_list_lock);

    pthread_spin_lock(&stack_group->poll_list_lock);
    list_del_node_null(&wakeup->poll_list);
    pthread_spin_unlock(&stack_group->poll_list_lock);

    pthread_mutex_destroy(&wakeup->wait);

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

int32_t lstack_epoll_ctl(int32_t epfd, int32_t op, int32_t fd, struct epoll_event *event)
{
    LSTACK_LOG(DEBUG, LSTACK, "op=%d events: fd: %d\n", op, fd);

    if (epfd < 0 || fd < 0 || epfd == fd || (event == NULL && op != EPOLL_CTL_DEL)) {
        LSTACK_LOG(ERR, LSTACK, "fd=%d epfd=%d op=%d\n", fd, epfd, op);
        GAZELLE_RETURN(EINVAL);
    }

    struct lwip_sock *epoll_sock = get_socket_by_fd(epfd);
    if (epoll_sock == NULL || epoll_sock->wakeup == NULL) {
        return posix_api->epoll_ctl_fn(epfd, op, fd, event);
    }


    struct wakeup_poll *wakeup = epoll_sock->wakeup;
    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        return posix_api->epoll_ctl_fn(epfd, op, fd, event);
    }

    if (CONN_TYPE_HAS_HOST(sock->conn)) {
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
                list_del_node_null(&sock->event_list);
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

static int32_t epoll_lwip_event(struct wakeup_poll *wakeup, struct epoll_event *events, uint32_t maxevents)
{
    int32_t event_num = 0;
    struct list_node *node, *temp;

    pthread_spin_lock(&wakeup->event_list_lock);

    list_for_each_safe(node, temp, &wakeup->event_list) {
        struct lwip_sock *sock = container_of(node, struct lwip_sock, event_list);

        if ((sock->epoll_events & sock->events) == 0) {
            list_del_node_null(&sock->event_list);
            continue;
        }

        if (sock->epoll_events & EPOLLET) {
            list_del_node_null(&sock->event_list);
        }

        /* EPOLLONESHOT: generate event after epoll_ctl add/mod event again
           epoll_event set 0 avoid generating event util epoll_ctl set epoll_event a valu */
        if (sock->epoll_events & EPOLLONESHOT) {
            list_del_node_null(&sock->event_list);
            sock->epoll_events = 0;
        }

        events[event_num].events = sock->events & sock->epoll_events;
        events[event_num].data = sock->ep_data;
        event_num++;

        if (event_num >= maxevents) {
            break;
        }
    }

    pthread_spin_unlock(&wakeup->event_list_lock);

    wakeup->stat.app_events += event_num;
    return event_num;
}

static int32_t poll_lwip_event(struct pollfd *fds, nfds_t nfds)
{
    int32_t event_num = 0;

    for (uint32_t i = 0; i < nfds; i++) {
        /* sock->listen_next pointerto next stack listen */
        int32_t fd = fds[i].fd;
        struct lwip_sock *sock = get_socket_by_fd(fd);
        while (sock && sock->conn) {
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

int32_t lstack_epoll_wait(int32_t epfd, struct epoll_event* events, int32_t maxevents, int32_t timeout)
{
    struct lwip_sock *sock = get_socket_by_fd(epfd);
    if (sock == NULL || sock->wakeup == NULL) {
        return posix_api->epoll_wait_fn(epfd, events, maxevents, timeout);
    }

    struct wakeup_poll *wakeup = sock->wakeup;
    int32_t kernel_num = 0;
    int32_t lwip_num = 0;
    int32_t ret = 0;

    if (get_global_cfg_params()->app_bind_numa) {
        epoll_bind_statck(sock->wakeup);
    }

    do {
        __atomic_store_n(&wakeup->in_wait, true, __ATOMIC_RELEASE);
        lwip_num = epoll_lwip_event(wakeup, events, maxevents);
        wakeup->stat.app_events += lwip_num;

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

        if (timeout < 0) {
            ret = pthread_mutex_lock(&wakeup->wait);
        } else {
            struct timespec epoll_time;
            ms_to_timespec(&epoll_time, timeout);
            ret = pthread_mutex_timedlock(&wakeup->wait, &epoll_time);
        }
    } while (ret == 0);

    __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);
    return lwip_num + kernel_num;
}

static int32_t init_poll_wakeup_data(struct wakeup_poll *wakeup)
{
    if (pthread_mutex_init(&wakeup->wait, NULL) != 0) {
        GAZELLE_RETURN(EINVAL);
    }
    pthread_mutex_trylock(&wakeup->wait);
    __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);

    for (uint32_t i = 0; i < PROTOCOL_STACK_MAX; i++) {
        init_list_node_null(&wakeup->wakeup_list[i]);
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
        GAZELLE_RETURN(EINVAL);
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    init_list_node_null(&wakeup->poll_list);
    pthread_spin_lock(&stack_group->poll_list_lock);
    list_add_node(&stack_group->poll_list, &wakeup->poll_list);
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

static void resize_kernel_poll(struct wakeup_poll *wakeup, nfds_t nfds)
{
    if (wakeup->last_fds) {
        free(wakeup->last_fds);
    }
    wakeup->last_fds = calloc(nfds, sizeof(struct pollfd));
    if (wakeup->last_fds == NULL) {
        LSTACK_LOG(ERR, LSTACK, "calloc failed errno=%d\n", errno);
    }

    if (wakeup->events) {
        free(wakeup->events);
    }
    wakeup->events = calloc(nfds, sizeof(struct epoll_event));
    if (wakeup->events == NULL) {
        LSTACK_LOG(ERR, LSTACK, "calloc failed errno=%d\n", errno);
    }

    wakeup->last_max_nfds = nfds;
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

static void poll_init(struct wakeup_poll *wakeup, struct pollfd *fds, nfds_t nfds)
{
    int32_t stack_count[PROTOCOL_STACK_MAX] = {0};
    int32_t poll_change = 0;

    /* poll fds num more, recalloc fds size */
    if (nfds > wakeup->last_max_nfds) {
        resize_kernel_poll(wakeup, nfds);
        poll_change = 1;
    }

    if (nfds < wakeup->last_nfds) {
        poll_change = 1;
    }

    for (uint32_t i = 0; i < nfds; i++) {
        int32_t fd = fds[i].fd;
        fds[i].revents = 0;
        struct lwip_sock *sock = get_socket_by_fd(fd);

        if (fd == wakeup->last_fds[i].fd && fds[i].events == wakeup->last_fds[i].events) {
            /* fd close then socket may get same fd. */
            if (sock == NULL || sock->wakeup != NULL) {
                continue;
            }
        }
        wakeup->last_fds[i].fd = fd;
        wakeup->last_fds[i].events = fds[i].events;
        poll_change = 1;

        if (sock == NULL || sock->conn == NULL || CONN_TYPE_HAS_HOST(sock->conn)) {
            update_kernel_poll(wakeup, i, fds + i);
        }

        while (sock && sock->conn) {
            sock->epoll_events = fds[i].events | POLLERR;
            sock->wakeup = wakeup;
            stack_count[sock->stack->stack_idx]++;
            sock = sock->listen_next;
        }
    }

    if (poll_change == 0) {
        return;
    }
    wakeup->last_nfds = nfds;

    if (get_global_cfg_params()->app_bind_numa) {
        poll_bind_statck(wakeup, stack_count);
    }
}

int32_t lstack_poll(struct pollfd *fds, nfds_t nfds, int32_t timeout)
{
    static PER_THREAD struct wakeup_poll *wakeup = NULL;
    if (wakeup == NULL) {
        wakeup = calloc(1, sizeof(struct wakeup_poll));
        if (wakeup == NULL) {
            GAZELLE_RETURN(EINVAL);
        }

        if (init_poll_wakeup_data(wakeup) < 0) {
            free(wakeup);
            GAZELLE_RETURN(EINVAL);
        }
    }

    poll_init(wakeup, fds, nfds);

    int32_t kernel_num = 0;
    int32_t lwip_num = 0;
    int32_t ret;

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

        if (timeout < 0) {
            ret = pthread_mutex_lock(&wakeup->wait);
        } else {
            struct timespec epoll_time;
            ms_to_timespec(&epoll_time, timeout);
            ret = pthread_mutex_timedlock(&wakeup->wait, &epoll_time);
        }
    } while (ret == 0);

    __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);
    return lwip_num + kernel_num;
}
