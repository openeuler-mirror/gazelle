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

#include <lwip/lwipsock.h>
#include <lwip/sockets.h>
#include <lwip/eventpoll.h>
#include <lwip/api.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>
#include <lwip/posix_api.h>

#include "lstack_compiler.h"
#include "lstack_ethdev.h"
#include "lstack_stack_stat.h"
#include "lstack_cfg.h"
#include "lstack_log.h"
#include "gazelle_base_func.h"
#include "lstack_lwip.h"
#include "lstack_protocol_stack.h"
#include "posix/lstack_epoll.h"

#define EPOLL_KERNEL_INTERVAL   10 /* ms */
#define SEC_TO_NSEC             1000000000
#define SEC_TO_MSEC             1000
#define MSEC_TO_NSEC            1000000
#define EPOLL_MAX_EVENTS        512
#define POLL_KERNEL_EVENTS      32

static PER_THREAD struct wakeup_poll g_wakeup_poll = {0};
static bool g_use_epoll = false; /* FIXME: when no epoll close prepare event for performance testing */

void add_epoll_event(struct netconn *conn, uint32_t event)
{
    /* conn sock nerver null, because lwip call this func */
    struct lwip_sock *sock = get_socket(conn->socket);

    if ((event & sock->epoll_events) == 0) {
        return;
    }

    sock->events |= event & sock->epoll_events;

#ifdef GAZELLE_USE_EPOLL_EVENT_STACK
    if (g_use_epoll && list_is_empty(&sock->event_list)) {
        list_add_node(&sock->stack->event_list, &sock->event_list);
    }
#endif

    if (sock->wakeup) {
        sock->stack->stats.wakeup_events++;
        if (get_protocol_stack_group()->wakeup_enable) {
            rte_ring_sp_enqueue(sock->stack->wakeup_ring, &sock->wakeup->event_sem);
        } else {
            sem_post(&sock->wakeup->event_sem);
        }
    }
}

static inline uint32_t update_events(struct lwip_sock *sock)
{
    uint32_t event = 0;

    if (sock->epoll_events & EPOLLIN) {
        if (sock->attach_fd > 0 && NETCONN_IS_ACCEPTIN(sock)) {
            event |= EPOLLIN;
        }

        if (sock->attach_fd < 0 && NETCONN_IS_DATAIN(sock)) {
            event |= EPOLLIN;
        }
    }

    if ((sock->epoll_events & EPOLLOUT) && NETCONN_IS_OUTIDLE(sock)) {
        event |= EPOLLOUT;
    }

    if ((sock->epoll_events & EPOLLERR) && (sock->events & EPOLLERR)) {
        event |= EPOLLERR | EPOLLIN;
    }

    return event;
}

#ifdef GAZELLE_USE_EPOLL_EVENT_STACK
void update_stack_events(struct protocol_stack *stack)
{
    if (!g_use_epoll) {
        return;
    }

    struct list_node *node, *temp;
    list_for_each_safe(node, temp, &stack->event_list) {
        struct lwip_sock *sock = container_of(node, struct lwip_sock, event_list);

        sock->events = update_events(sock);
        if (sock->events != 0) {
            continue;
        }

        if (pthread_spin_trylock(&stack->event_lock)) {
            continue;
        }
        list_del_node_init(&sock->event_list);
        pthread_spin_unlock(&stack->event_lock);
    }
}
#endif

static void raise_pending_events(struct lwip_sock *sock)
{
    struct lwip_sock *attach_sock = (sock->attach_fd > 0) ? get_socket_by_fd(sock->attach_fd) : sock;
    if (attach_sock == NULL) {
        return;
    }

    attach_sock->events = update_events(attach_sock);
    if (attach_sock->events & attach_sock->epoll_events) {
        rpc_call_addevent(attach_sock->stack, attach_sock);
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

    struct wakeup_poll *wakeup = malloc(sizeof(struct wakeup_poll));
    if (wakeup == NULL) {
        posix_api->close_fn(fd);
        GAZELLE_RETURN(EINVAL);
    }
    memset_s(wakeup, sizeof(struct wakeup_poll), 0, sizeof(struct wakeup_poll));

    init_list_node(&wakeup->event_list);
    wakeup->epollfd = fd;
    sem_init(&wakeup->event_sem, 0, 0);
    sock->wakeup = wakeup;

    g_use_epoll = true;
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

    /* first bind and all stack same. choice tick as queue_id, avoid all bind to statck_0.*/
    static uint16_t tick = 0;
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

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        epoll_sock->wakeup->have_kernel_fd = true;
        return posix_api->epoll_ctl_fn(epfd, op, fd, event);
    }

    if (CONN_TYPE_HAS_HOST(sock->conn)) {
        epoll_sock->wakeup->have_kernel_fd = true;
        int32_t ret = posix_api->epoll_ctl_fn(epfd, op, fd, event);
        if (ret < 0) {
            return ret;
        }
    }

    do {
        switch (op) {
            case EPOLL_CTL_ADD:
                sock->wakeup = epoll_sock->wakeup;
                if (sock->stack) {
                    epoll_sock->wakeup->stack_fd_cnt[sock->stack->queue_id]++;
                }
                if (list_is_empty(&sock->event_list)) {
                    list_add_node(&sock->wakeup->event_list, &sock->event_list);
                }
                /* fall through */
            case EPOLL_CTL_MOD:
                sock->epoll_events = event->events | EPOLLERR | EPOLLHUP;
                sock->ep_data = event->data;
                if (sock->conn && NETCONNTYPE_GROUP(netconn_type(sock->conn)) == NETCONN_TCP) {
                    raise_pending_events(sock);
                }
                break;
            case EPOLL_CTL_DEL:
                list_del_node_init(&sock->event_list);
                sock->epoll_events = 0;
                if (sock->stack) {
                    epoll_sock->wakeup->stack_fd_cnt[sock->stack->queue_id]--;
                }
                break;
            default:
                GAZELLE_RETURN(EINVAL);
        }
        fd = sock->nextfd;
        sock = get_socket(fd);
    } while (fd > 0 && sock != NULL);

    update_epoll_max_stack(epoll_sock->wakeup);
    return 0;
}

#ifdef GAZELLE_USE_EPOLL_EVENT_STACK
static int32_t epoll_lwip_event(struct wakeup_poll *wakeup, struct epoll_event *events, uint32_t maxevents)
{
    int32_t event_num = 0;
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    maxevents = LWIP_MIN(EPOLL_MAX_EVENTS, maxevents);
    for (uint32_t i = 0; i < stack_group->stack_num && event_num < maxevents; i++) {
        struct protocol_stack *stack = stack_group->stacks[i];
        int32_t start_event_num = event_num;

        if (pthread_spin_trylock(&stack->event_lock)) {
            continue;
        }

        struct list_node *node, *temp;
        list_for_each_safe(node, temp, &stack->event_list) {
            struct lwip_sock *sock = container_of(node, struct lwip_sock, event_list);

            uint32_t event = sock->events & sock->epoll_events;
            if (event == 0 || sock->wait_close) {
                continue;
            }

            events[event_num].events = event;
            events[event_num].data = sock->ep_data;
            event_num++;

            if (event_num >= maxevents) {
                break;
            }
        }

        pthread_spin_unlock(&stack->event_lock);

        __sync_fetch_and_add(&stack->stats.app_events, event_num - start_event_num);
    }

    return event_num;
}
#else
static int32_t epoll_lwip_event(struct wakeup_poll *wakeup, struct epoll_event *events, uint32_t maxevents)
{
    int32_t event_num = 0;
    struct list_node *node, *temp;
    list_for_each_safe(node, temp, &wakeup->event_list) {
        struct lwip_sock *sock = container_of(node, struct lwip_sock, event_list);
        if (sock->conn == NULL) {
            list_del_node_init(&sock->event_list);
            continue;
        }

        struct lwip_sock *temp_sock = sock;
        do {
            struct lwip_sock *attach_sock = (temp_sock->attach_fd > 0) ? get_socket(temp_sock->attach_fd) : temp_sock;
            if (attach_sock == NULL || temp_sock->wait_close) {
                temp_sock = (temp_sock->nextfd > 0) ? get_socket(temp_sock->nextfd) : NULL;
                continue;
            }

            uint32_t event = update_events(attach_sock);
            if (event != 0) {
                events[event_num].events = event;
                events[event_num].data = temp_sock->ep_data;
                event_num++;
                if (event_num >= maxevents) {
                    break;
                }
            }

            temp_sock = (temp_sock->nextfd > 0) ? get_socket(temp_sock->nextfd) : NULL;
        } while (temp_sock);
    }

    return event_num;
}
#endif

static int32_t poll_lwip_event(struct pollfd *fds, nfds_t nfds)
{
    int32_t event_num = 0;

    for (uint32_t i = 0; i < nfds; i++) {
        /* listenfd nextfd pointerto next stack listen, others nextfd=-1 */
        int32_t fd = fds[i].fd;
        while (fd > 0) {
            struct lwip_sock *sock = get_socket(fd);
            if (sock == NULL) {
                break;
            }

            /* attach listen is empty, all event in attached listen. attached listen attach_fd is self */
            struct lwip_sock *attach_sock = (sock->attach_fd > 0) ? get_socket(sock->attach_fd) : sock;
            if (attach_sock == NULL || sock->wait_close) {
                fd = sock->nextfd;
                continue;
            }

            uint32_t events = update_events(attach_sock);
            if (events) {
                fds[i].revents = events;
                __sync_fetch_and_add(&sock->stack->stats.app_events, 1);
                event_num++;
                break;
            }

            fd = sock->nextfd;
        }
    }

    return event_num;
}

static void ms_to_timespec(struct timespec *timespec, int32_t timeout)
{
    clock_gettime(CLOCK_REALTIME, timespec);
    timespec->tv_sec += timeout / SEC_TO_MSEC;
    timespec->tv_nsec += (timeout % SEC_TO_MSEC) * MSEC_TO_NSEC;
    timespec->tv_sec += timespec->tv_nsec / SEC_TO_NSEC;
    timespec->tv_nsec = timespec->tv_nsec % SEC_TO_NSEC;
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
    event.data.ptr = &wakeup->event_sem;
    event.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLET;
    if (posix_api->epoll_ctl_fn(new_stack->epollfd, EPOLL_CTL_ADD, wakeup->epollfd, &event) != 0) {
        LSTACK_LOG(ERR, LSTACK, "epoll_ctl_fn errno=%d\n", errno);
    }
}

static void epoll_bind_statck(struct wakeup_poll *wakeup)
{
    /* all fd is kernel, set rand stack */
    if (wakeup->bind_stack == NULL && wakeup->max_stack== NULL) {
        update_epoll_max_stack(wakeup);
    }

    if (wakeup->bind_stack != wakeup->max_stack && wakeup->max_stack) {
        bind_to_stack_numa(wakeup->max_stack);
        change_epollfd_kernel_thread(wakeup, wakeup->bind_stack, wakeup->max_stack);
        wakeup->bind_stack = wakeup->max_stack;
    }
}

int32_t lstack_epoll_wait(int32_t epfd, struct epoll_event* events, int32_t maxevents, int32_t timeout)
{
    struct lwip_sock *sock = get_socket_by_fd(epfd);
    if (sock == NULL || sock->wakeup == NULL) {
        return posix_api->epoll_wait_fn(epfd, events, maxevents, timeout);
    }

    int32_t event_num = 0;
    int32_t ret;

    struct timespec epoll_time;
    if (timeout >= 0) {
        ms_to_timespec(&epoll_time, timeout);
    }

    epoll_bind_statck(sock->wakeup);

    do {
        event_num += epoll_lwip_event(sock->wakeup, &events[event_num], maxevents - event_num);

        if (sock->wakeup->have_kernel_fd) {
            event_num += posix_api->epoll_wait_fn(epfd, &events[event_num], maxevents - event_num, 0);
        }

        if (event_num > 0) {
            break;
        }

        if (timeout < 0) {
            ret = sem_wait(&sock->wakeup->event_sem);
        } else {
            ret = sem_timedwait(&sock->wakeup->event_sem, &epoll_time);
        }
    } while (ret == 0);

    return event_num;
}

static void init_poll_wakeup_data(struct wakeup_poll *wakeup)
{
    sem_init(&wakeup->event_sem, 0, 0);

    wakeup->last_fds = calloc(POLL_KERNEL_EVENTS, sizeof(struct pollfd));
    if (wakeup->last_fds == NULL) {
        LSTACK_LOG(ERR, LSTACK, "calloc failed errno=%d\n", errno);
    }

    wakeup->events = calloc(POLL_KERNEL_EVENTS, sizeof(struct epoll_event));
    if (wakeup->events == NULL) {
        LSTACK_LOG(ERR, LSTACK, "calloc failed errno=%d\n", errno);
    }

    wakeup->last_max_nfds = POLL_KERNEL_EVENTS;

    wakeup->epollfd = posix_api->epoll_create_fn(POLL_KERNEL_EVENTS);
    if (wakeup->epollfd < 0) {
        LSTACK_LOG(ERR, LSTACK, "epoll_create_fn errno=%d\n", errno);
    }
}

static void resize_kernel_poll(struct wakeup_poll *wakeup, nfds_t nfds)
{
    wakeup->last_fds = realloc(wakeup->last_fds, nfds * sizeof(struct pollfd));
    if (wakeup->last_fds == NULL) {
        LSTACK_LOG(ERR, LSTACK, "calloc failed errno=%d\n", errno);
    }

    wakeup->events = realloc(wakeup->events, nfds * sizeof(struct epoll_event));
    if (wakeup->events == NULL) {
        LSTACK_LOG(ERR, LSTACK, "calloc failed errno=%d\n", errno);
    }

    wakeup->last_max_nfds = nfds;
    memset_s(wakeup->last_fds, nfds * sizeof(struct pollfd), 0, nfds * sizeof(struct pollfd));
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

    wakeup->last_fds[index].fd = new_fd->fd;
    wakeup->last_fds[index].events = new_fd->events;

    wakeup->have_kernel_fd = true;
}

static void poll_init(struct wakeup_poll *wakeup, struct pollfd *fds, nfds_t nfds)
{
    if (!wakeup->init) {
        wakeup->init = true;
        init_poll_wakeup_data(wakeup);
    } else {
        while (sem_trywait(&wakeup->event_sem) == 0) {}
    }

    if (nfds > wakeup->last_max_nfds) {
        resize_kernel_poll(wakeup, nfds);
    }

    int32_t stack_count[PROTOCOL_STACK_MAX] = {0};
    int32_t poll_change = 0;

    /* poll fds num less, del old fd */
    for (uint32_t i = nfds; i < wakeup->last_nfds; i++) {
        update_kernel_poll(wakeup, i, NULL);
        poll_change = 1;
    }

    for (uint32_t i = 0; i < nfds; i++) {
        fds[i].revents = 0;

        if (fds[i].fd == wakeup->last_fds[i].fd && fds[i].events == wakeup->last_fds[i].events) {
            continue;
        }
        poll_change = 1;

        int32_t fd = fds[i].fd;
        struct lwip_sock *sock = get_socket(fd);
        if (sock == NULL || CONN_TYPE_HAS_HOST(sock->conn)) {
            update_kernel_poll(wakeup, i, fds + i);
        }

        do {
            sock = get_socket(fd);
            if (sock == NULL || sock->conn == NULL) {
                break;
            }
            sock->epoll_events = fds[i].events | POLLERR;
            sock->wakeup = wakeup;

            /* listenfd list */
            fd = sock->nextfd;
            stack_count[sock->stack->queue_id]++;
        } while (fd > 0);
    }

    wakeup->last_nfds = nfds;
    if (poll_change == 0) {
        return;
    }

    poll_bind_statck(wakeup, stack_count);
}

int32_t lstack_poll(struct pollfd *fds, nfds_t nfds, int32_t timeout)
{
    poll_init(&g_wakeup_poll, fds, nfds);

    int32_t event_num = 0;
    int32_t ret;

    struct timespec poll_time;
    if (timeout >= 0) {
        ms_to_timespec(&poll_time, timeout);
    }

    /* when epfd > 0 is epoll type */
    do {
        event_num += poll_lwip_event(fds, nfds);

        /* reduce syscall epoll_wait */
        if (g_wakeup_poll.have_kernel_fd) {
            int32_t kernel_num = posix_api->epoll_wait_fn(g_wakeup_poll.epollfd, g_wakeup_poll.events, nfds, 0);
            for (int32_t i = 0; i < kernel_num; i++) {
                uint32_t index = g_wakeup_poll.events[i].data.u32;
                fds[index].revents = g_wakeup_poll.events[i].events;
            }
            event_num += kernel_num >= 0 ? kernel_num : 0;
        }

        if (event_num > 0) {
            break;
        }

        if (timeout < 0) {
            ret = sem_wait(&g_wakeup_poll.event_sem);
        } else {
            ret = sem_timedwait(&g_wakeup_poll.event_sem, &poll_time);
        }
    } while (ret == 0);

    return event_num;
}
