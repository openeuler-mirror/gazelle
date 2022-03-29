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

#define EPOLL_KERNEL_INTERVAL   10 /* ms */
#define EPOLL_NSEC_TO_SEC       1000000000
#define EPOLL_MAX_EVENTS        512

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
    sem_init(&wakeup->event_sem, 0, 0);

    sock->wakeup = wakeup;
    init_list_node(&wakeup->event_list);

    g_use_epoll = true;
    return fd;
}

int32_t lstack_epoll_close(int32_t fd)
{
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

int32_t lstack_epoll_ctl(int32_t epfd, int32_t op, int32_t fd, struct epoll_event *event)
{
    LSTACK_LOG(DEBUG, LSTACK, "op=%d events: fd: %d\n", op, fd);

    if (epfd < 0 || fd < 0 || epfd == fd || (event == NULL && op != EPOLL_CTL_DEL)) {
        LSTACK_LOG(ERR, LSTACK, "fd=%d epfd=%d op=%d\n", fd, epfd, op);
        GAZELLE_RETURN(EINVAL);
    }

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        return posix_api->epoll_ctl_fn(epfd, op, fd, event);
    }

    if (CONN_TYPE_HAS_HOST(sock->conn)) {
        int32_t ret = posix_api->epoll_ctl_fn(epfd, op, fd, event);
        if (ret < 0) {
            return ret;
        }
    }

    struct lwip_sock *epoll_sock = get_socket_by_fd(epfd);
    if (epoll_sock == NULL || epoll_sock->wakeup == NULL) {
        LSTACK_LOG(ERR, LSTACK, "epfd=%d\n", fd);
        GAZELLE_RETURN(EINVAL);
    }

    uint32_t events = event->events | EPOLLERR | EPOLLHUP;
    do {
        switch (op) {
            case EPOLL_CTL_ADD:
                sock->wakeup = epoll_sock->wakeup;
                if (list_is_empty(&sock->event_list)) {
                    list_add_node(&sock->wakeup->event_list, &sock->event_list);
                }
                /* fall through */
            case EPOLL_CTL_MOD:
                sock->epoll_events = events;
                sock->ep_data = event->data;
                if (sock->conn && NETCONNTYPE_GROUP(netconn_type(sock->conn)) == NETCONN_TCP) {
                    raise_pending_events(sock);
                }
                break;
            case EPOLL_CTL_DEL:
                list_del_node_init(&sock->event_list);
                sock->epoll_events = 0;
                break;
            default:
                GAZELLE_RETURN(EINVAL);
        }
        fd = sock->nextfd;
        sock = get_socket(fd);
    } while (fd > 0 && sock != NULL);

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

static inline bool have_kernel_fd(int32_t epfd, struct pollfd *fds, nfds_t nfds)
{
    /* when epfd > 0 is epoll type */
    for (uint32_t i = 0; i < nfds && epfd < 0; i++) {
        if (get_socket(fds[i].fd) == NULL) {
            return true;
        }
    }

    return false;
}

static inline int32_t poll_kernel_event(struct pollfd *fds, nfds_t nfds)
{
    int32_t event_num = 0;

    for (uint32_t i = 0; i < nfds; i++) {
        /* lwip event */
        if (get_socket(fds[i].fd) != NULL || fds[i].fd < 0) {
            continue;
        }

        int32_t ret = posix_api->poll_fn(&fds[i], 1, 0);
        if (ret < 0) {
            if (errno != EINTR) {
                return ret;
            }
        } else {
            event_num += ret;
        }
    }

    return event_num;
}

static int32_t get_event(struct wakeup_poll *wakeup, int32_t epfd, void *out, int32_t maxevents, int32_t timeout)
{
    struct pollfd *fds = (struct pollfd *)out;
    struct epoll_event *events = (struct epoll_event *)out;
    bool have_kernel = have_kernel_fd(epfd, fds, maxevents);
    int32_t event_num = 0;
    int32_t poll_time = 0;
    int32_t ret;

    /* when epfd > 0 is epoll type */
    do {
        event_num += (epfd > 0) ? epoll_lwip_event(wakeup, &events[event_num], maxevents - event_num) :
            poll_lwip_event(fds, maxevents);

        if (have_kernel) {
            int32_t event_kernel_num = (epfd > 0) ?
                posix_api->epoll_wait_fn(epfd, &events[event_num], maxevents - event_num, 0) :
                poll_kernel_event(fds, maxevents);
            if (event_kernel_num < 0) {
                return event_kernel_num;
            }
            event_num += event_kernel_num;
            if (timeout >= 0 && poll_time >= timeout) {
                break;
            }
            poll_time += EPOLL_KERNEL_INTERVAL;
        }

        if (event_num > 0) {
            break;
        }

        int32_t interval = (have_kernel) ? EPOLL_KERNEL_INTERVAL : timeout;
        struct timespec epoll_interval;
        clock_gettime(CLOCK_REALTIME, &epoll_interval);
        epoll_interval.tv_sec += interval / 1000;
        epoll_interval.tv_nsec += (interval % 1000) * 1000000;
        epoll_interval.tv_sec += epoll_interval.tv_nsec / 1000000000;
        epoll_interval.tv_nsec = epoll_interval.tv_nsec % 1000000000;

        if (timeout < 0 && !have_kernel) {
            ret = sem_wait(&wakeup->event_sem);
        } else {
            ret = sem_timedwait(&wakeup->event_sem, &epoll_interval);
        }

        if (!have_kernel && ret < 0) {
            break;
        }
    } while (event_num <= maxevents);

    return event_num;
}

int32_t lstack_epoll_wait(int32_t epfd, struct epoll_event* events, int32_t maxevents, int32_t timeout)
{
    /* avoid the starvation of epoll events from both netstack */
    maxevents = LWIP_MIN(LWIP_EPOOL_MAX_EVENTS, maxevents);

    struct lwip_sock *sock = get_socket_by_fd(epfd);
    if (sock == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    if (sock->wakeup == NULL) {
        return posix_api->epoll_wait_fn(epfd, events, maxevents, timeout);
    }

    return get_event(sock->wakeup, epfd, events, maxevents, timeout);
}

static void poll_init(struct pollfd *fds, nfds_t nfds, struct wakeup_poll *wakeup)
{
    int32_t stack_count[PROTOCOL_STACK_MAX] = {0};

    if (!wakeup->init) {
        wakeup->init = true;
        sem_init(&wakeup->event_sem, 0, 0);
    } else {
        while (sem_trywait(&wakeup->event_sem) == 0) {}
    }

    for (uint32_t i = 0; i < nfds; i++) {
        int32_t fd = fds[i].fd;
        fds[i].revents = 0;

        do {
            struct lwip_sock *sock = get_socket(fd);
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

    if (wakeup->bind_stack) {
        return;
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    uint32_t bind_id = 0;
    for (uint32_t i = 0; i < stack_group->stack_num; i++) {
        if (stack_count[i] > stack_count[bind_id]) {
            bind_id = i;
        }
    }

    bind_to_stack_numa(stack_group->stacks[bind_id]);
    wakeup->bind_stack = stack_group->stacks[bind_id];
}

int32_t lstack_poll(struct pollfd *fds, nfds_t nfds, int32_t timeout)
{
    poll_init(fds, nfds, &g_wakeup_poll);

    return get_event(&g_wakeup_poll, -1, fds, nfds, timeout);
}
