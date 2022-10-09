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
#define POLL_KERNEL_EVENTS      128

void add_sock_event(struct lwip_sock *sock, uint32_t event)
{
    struct wakeup_poll *wakeup = sock->wakeup;
    if (wakeup == NULL || (event & sock->epoll_events) == 0) {
        return;
    }

    wakeup->have_event = true;
    sock->stack->have_event = true;

    if (wakeup->type == WAKEUP_POLL) {
        return;
    }

    pthread_spin_lock(&wakeup->event_list_lock);
    sock->events |= (event == EPOLLERR) ? (EPOLLIN | EPOLLERR) : (event & sock->epoll_events);
    if (list_is_null(&sock->event_list)) {
        list_add_node(&wakeup->event_list, &sock->event_list);
    }
    pthread_spin_unlock(&wakeup->event_list_lock);
}

void wakeup_epoll(struct protocol_stack *stack, struct wakeup_poll *wakeup)
{
    if (__atomic_load_n(&wakeup->in_wait, __ATOMIC_ACQUIRE)) {
        uint64_t tmp = 1;
        posix_api->write_fn(wakeup->eventfd, &tmp, sizeof(tmp));
        stack->stats.wakeup_events++;
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
    sock->events = update_events(sock);
    if (sock->events) {
        add_sock_event(sock, sock->events);
    }
}

int32_t lstack_epoll_create(int32_t size)
{
    int32_t fd = posix_api->epoll_create_fn(size);
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

    wakeup->eventfd = eventfd(0, EFD_NONBLOCK);
    if (wakeup->eventfd < 0) {
        LSTACK_LOG(ERR, LSTACK, "eventfd fail=%d errno=%d\n", wakeup->eventfd, errno);
        posix_api->close_fn(fd);
        free(wakeup);
        GAZELLE_RETURN(EINVAL);
    }

    struct epoll_event event;
    event.data.fd = wakeup->eventfd;
    event.events = EPOLLIN | EPOLLET;
    if (posix_api->epoll_ctl_fn(fd, EPOLL_CTL_ADD, wakeup->eventfd, &event) < 0) {
        LSTACK_LOG(ERR, LSTACK, "ctl eventfd errno=%d\n", errno);
        posix_api->close_fn(fd);
        free(wakeup);
        GAZELLE_RETURN(EINVAL);
    }

    init_list_node(&wakeup->event_list);
    pthread_spin_init(&wakeup->event_list_lock, PTHREAD_PROCESS_PRIVATE);

    wakeup->type = WAKEUP_EPOLL;
    wakeup->epollfd = fd;
    sock->wakeup = wakeup;

    return fd;
}

int32_t lstack_epoll_close(int32_t fd)
{
    posix_api->close_fn(fd);

    struct lwip_sock *sock = get_socket_by_fd(fd);
    if (sock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "fd=%d sock is NULL errno=%d\n", fd, errno);
        GAZELLE_RETURN(EINVAL);
    }

    if (sock->wakeup) {
        if (sock->wakeup->bind_stack) {
            unregister_wakeup(sock->wakeup->bind_stack, sock->wakeup);
        }
        posix_api->close_fn(sock->wakeup->eventfd);
        pthread_spin_destroy(&sock->wakeup->event_list_lock);
        free(sock->wakeup);
    }
    sock->wakeup = NULL;

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
        return last_stack->queue_id;
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
        wakeup->have_kernel_fd = true;
        return posix_api->epoll_ctl_fn(epfd, op, fd, event);
    }

    if (CONN_TYPE_HAS_HOST(sock->conn)) {
        wakeup->have_kernel_fd = true;
        int32_t ret = posix_api->epoll_ctl_fn(epfd, op, fd, event);
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "fd=%d epfd=%d op=%d\n", fd, epfd, op);
        }
    }

    do {
        switch (op) {
            case EPOLL_CTL_ADD:
                sock->wakeup = wakeup;
                wakeup->stack_fd_cnt[sock->stack->queue_id]++;
                /* fall through */
            case EPOLL_CTL_MOD:
                sock->epoll_events = event->events | EPOLLERR | EPOLLHUP;
                sock->ep_data = event->data;
                raise_pending_events(wakeup, sock);
                break;
            case EPOLL_CTL_DEL:
                sock->epoll_events = 0;
                wakeup->stack_fd_cnt[sock->stack->queue_id]--;
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

        if (sock->epoll_events == 0) {
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

        events[event_num].events = sock->events;
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

static void epoll_bind_statck(struct wakeup_poll *wakeup)
{
    /* all fd is kernel, set rand stack */
    if (wakeup->bind_stack == NULL && wakeup->max_stack == NULL) {
        update_epoll_max_stack(wakeup);
    }

    if (wakeup->bind_stack != wakeup->max_stack && wakeup->max_stack) {
        if (get_global_cfg_params()->app_bind_numa) {
            bind_to_stack_numa(wakeup->max_stack);
        }
        if (wakeup->bind_stack) {
            unregister_wakeup(wakeup->bind_stack, wakeup);
        }
        wakeup->bind_stack = wakeup->max_stack;
        register_wakeup(wakeup->bind_stack, wakeup);
    }
}

static bool del_event_fd(struct epoll_event* events, int32_t eventnum, int32_t eventfd)
{
    for (int32_t i = 0; i < eventnum; i++) {
        if (events[i].data.fd == eventfd) {
            events[i].data.u64 = events[eventnum - 1].data.u64;
            events[i].events = events[eventnum - 1].events;
            return true;
        }
    }

    return false;
}

int32_t lstack_epoll_wait(int32_t epfd, struct epoll_event* events, int32_t maxevents, int32_t timeout)
{
    struct lwip_sock *sock = get_socket_by_fd(epfd);
    if (sock == NULL || sock->wakeup == NULL) {
        return posix_api->epoll_wait_fn(epfd, events, maxevents, timeout);
    }

    struct wakeup_poll *wakeup = sock->wakeup;
    int32_t kernel_num = 0;

    epoll_bind_statck(sock->wakeup);

    __atomic_store_n(&wakeup->in_wait, true, __ATOMIC_RELEASE);
    rte_mb();

    int32_t lwip_num = epoll_lwip_event(wakeup, events, maxevents);
    wakeup->stat.app_events += lwip_num;
    if (!wakeup->have_kernel_fd && lwip_num > 0) {
        return lwip_num;
    }

    if (lwip_num > 0) {
        __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);
        rte_mb();
        kernel_num = posix_api->epoll_wait_fn(epfd, &events[lwip_num], maxevents - lwip_num, 0);
    } else {
        kernel_num = posix_api->epoll_wait_fn(epfd, &events[lwip_num], maxevents - lwip_num, timeout);
        rte_mb();
        __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);
    }

    if (kernel_num <= 0) {
        return (lwip_num > 0) ? lwip_num : kernel_num;
    }

    if (del_event_fd(&events[lwip_num], kernel_num, wakeup->eventfd)) {
        kernel_num--;
        if (lwip_num == 0) {
            lwip_num = epoll_lwip_event(wakeup, &events[kernel_num], maxevents - kernel_num);
        }
    }

    return lwip_num + kernel_num;
}

static int32_t init_poll_wakeup_data(struct wakeup_poll *wakeup)
{
    wakeup->type = WAKEUP_POLL;

    wakeup->eventfd = eventfd(0, EFD_NONBLOCK);
    if (wakeup->eventfd < 0) {
        LSTACK_LOG(ERR, LSTACK, "eventfd failed errno=%d\n", errno);
        GAZELLE_RETURN(EINVAL);
    }

    wakeup->last_fds = calloc(POLL_KERNEL_EVENTS, sizeof(struct pollfd));
    if (wakeup->last_fds == NULL) {
        LSTACK_LOG(ERR, LSTACK, "calloc failed errno=%d\n", errno);
        posix_api->close_fn(wakeup->eventfd);
        GAZELLE_RETURN(EINVAL);
    }

    wakeup->last_fds[0].fd = wakeup->eventfd;
    wakeup->last_fds[0].events = POLLIN;
    wakeup->last_max_nfds = POLL_KERNEL_EVENTS;

    return 0;
}

static void resize_kernel_poll(struct wakeup_poll *wakeup, nfds_t nfds)
{
    if (wakeup->last_fds) {
        free(wakeup->last_fds);
    }
    wakeup->last_fds = calloc(nfds + 1, sizeof(struct pollfd));
    if (wakeup->last_fds == NULL) {
        LSTACK_LOG(ERR, LSTACK, "calloc failed errno=%d\n", errno);
    }

    wakeup->last_fds[0].fd = wakeup->eventfd;
    wakeup->last_fds[0].events = POLLIN;
    wakeup->last_max_nfds = nfds;
}

static void poll_bind_statck(struct wakeup_poll *wakeup, int32_t *stack_count)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    uint16_t bind_id = find_max_cnt_stack(stack_count, stack_group->stack_num, wakeup->bind_stack);
    if (wakeup->bind_stack && wakeup->bind_stack->queue_id == bind_id) {
        return;
    }

    if (wakeup->bind_stack) {
        unregister_wakeup(wakeup->bind_stack, wakeup);
    }
    
    if (get_global_cfg_params()->app_bind_numa) {
        bind_to_stack_numa(stack_group->stacks[bind_id]);
    }
    wakeup->bind_stack = stack_group->stacks[bind_id];
    register_wakeup(wakeup->bind_stack, wakeup);
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

    for (uint32_t i = 0; i < nfds; i++) {
        int32_t fd = fds[i].fd;
        fds[i].revents = 0;
        struct lwip_sock *sock = get_socket_by_fd(fd);

        if (fd == wakeup->last_fds[i + 1].fd && fds[i].events == wakeup->last_fds[i + 1].events) {
            /* fd close then socket may get same fd. */
            if (sock == NULL || sock->wakeup != NULL) {
                continue;
            }
        }
        wakeup->last_fds[i + 1].fd = fd;
        wakeup->last_fds[i + 1].events = fds[i].events;
        poll_change = 1;

        while (sock && sock->conn) {
            if (sock->epoll_events != (fds[i].events | POLLERR)) {
                sock->epoll_events = fds[i].events | POLLERR;
            }
            if (sock->wakeup != wakeup) {
                sock->wakeup = wakeup;
            }

            stack_count[sock->stack->queue_id]++;
            /* listenfd list */
            sock = sock->listen_next;
        }
    }

    if (poll_change == 0) {
        return;
    }
    wakeup->last_nfds = nfds + 1;

    poll_bind_statck(wakeup, stack_count);
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

    __atomic_store_n(&wakeup->in_wait, true, __ATOMIC_RELEASE);
    rte_mb();

    int32_t lwip_num = poll_lwip_event(fds, nfds);
    wakeup->stat.app_events += lwip_num;
    if (lwip_num >= nfds) {
        __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);
        return lwip_num;
    }

    int32_t kernel_num = 0;
    if (lwip_num > 0) {
        __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);
        rte_mb();
        kernel_num = posix_api->poll_fn(wakeup->last_fds, wakeup->last_nfds, 0);
    } else {
        kernel_num = posix_api->poll_fn(wakeup->last_fds, wakeup->last_nfds, timeout);
        rte_mb();
        __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);
    }

    if (kernel_num <= 0) {
        return (lwip_num > 0) ? lwip_num : kernel_num;
    }

    for (nfds_t i = 0; i < nfds; i++) {
        if (fds[i].revents == 0 && wakeup->last_fds[i + 1].revents != 0) {
            fds[i].revents = wakeup->last_fds[i + 1].revents;
        }
    }

    if (wakeup->last_fds[0].revents) {
        if (lwip_num == 0) {
            lwip_num = poll_lwip_event(fds, nfds);
        }
        kernel_num--;
    }

    return kernel_num + lwip_num;
}
