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

#include <lwip/lwipsock.h>
#include <lwip/sockets.h>
#include <lwip/eventpoll.h>
#include <lwip/api.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>

#include "lstack_compiler.h"
#include "lstack_ethdev.h"
#include "lstack_stack_stat.h"
#include "lstack_cfg.h"
#include "lstack_log.h"
#include "gazelle_base_func.h"
#include "lstack_weakup.h"
#include "lstack_lwip.h"
#include "lstack_protocol_stack.h"

#define EPOLL_INTERVAL_10MS 10000000

static PER_THREAD struct weakup_poll g_weakup_poll = {0};

enum POLL_TYPE {
    TYPE_POLL,
    TYPE_EPOLL,
};

static inline bool check_event_vaild(struct lwip_sock *sock, uint32_t event)
{
    if ((event & EPOLLIN) && !NETCONN_IS_ACCEPTIN(sock) && !NETCONN_IS_DATAIN(sock)) {
        event &= ~EPOLLIN;
    }

    if ((event & EPOLLOUT) && !NETCONN_IS_DATAOUT(sock)) {
        event &= ~EPOLLOUT;
    }

    return (event) ? true : false;
}

static inline bool report_events(struct lwip_sock *sock, uint32_t event)
{
    /* error event */
    if ((event & EPOLLERR) || (event & EPOLLHUP) || (event & EPOLLRDHUP)) {
        return true;
    }

    if (sock->have_event) {
        return false;
    }

    return check_event_vaild(sock, event);
}

void add_epoll_event(struct netconn *conn, uint32_t event)
{
    /* conn sock nerver null, because lwip call this func */
    struct lwip_sock *sock = get_socket(conn->socket);

    /* shadow_fd event notice listen_fd */
    if (sock->shadowed_sock) {
        sock = sock->shadowed_sock;
    }

    if ((event & sock->epoll_events) == 0) {
        return;
    }
    sock->events |= event & sock->epoll_events;

    /* sock not in monitoring */
    if (!sock->weakup) {
        return;
    }

    if (report_events(sock, event)) {
        sock->have_event = true;
        weakup_enqueue(sock->stack->weakup_ring, sock);
        sock->stack->stats.weakup_events++;
    }
}

static void raise_pending_events(struct lwip_sock *sock)
{
    if (!sock->conn) {
        return;
    }

    struct lwip_sock *attach_sock = NULL;
    if (sock->attach_fd > 0 && sock->attach_fd != sock->conn->socket) {
        attach_sock = get_socket_by_fd(sock->attach_fd);
        if (attach_sock == NULL) {
            return;
        }
    } else {
        attach_sock = sock;
    }

    struct netconn *conn = attach_sock->conn;
    struct tcp_pcb *tcp = conn->pcb.tcp;
    if ((tcp == NULL) || (tcp->state < ESTABLISHED)) {
        return;
    }

    uint32_t event = 0;
    if (sock->epoll_events & EPOLLIN) {
        if (attach_sock->recv_lastdata || rte_ring_count(attach_sock->recv_ring) || NETCONN_IS_ACCEPTIN(attach_sock)) {
            event |= EPOLLIN;
        }
    }

    if (sock->epoll_events & EPOLLOUT) {
        if ((attach_sock->sendevent > 0) ||
            ((tcp_sndbuf(conn->pcb.tcp) > TCP_SNDLOWAT) && (tcp_sndqueuelen(conn->pcb.tcp) < TCP_SNDQUEUELOWAT))) {
            event |= EPOLLOUT;
        }
    }

    if (sock->errevent > 0) {
        event |= POLLERR | POLLIN;
    }

    if (event != 0) {
        sock->events |= event;
        rte_ring_mp_enqueue(sock->weakup->event_ring, (void *)sock);
        sem_post(&sock->weakup->event_sem);
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

    struct weakup_poll *weakup = malloc(sizeof(struct weakup_poll));
    if (weakup == NULL) {
        posix_api->close_fn(fd);
        GAZELLE_RETURN(EINVAL);
    }

    memset_s(weakup, sizeof(struct weakup_poll), 0, sizeof(struct weakup_poll));
    sem_init(&weakup->event_sem, 0, 0);

    weakup->event_ring = create_ring("RING_EVENT", VDEV_EVENT_QUEUE_SZ, RING_F_SC_DEQ, fd);
    if (weakup->event_ring == NULL) {
        posix_api->close_fn(fd);
        GAZELLE_RETURN(ENOMEM);
    }

    sock->weakup = weakup;

    return fd;
}

int32_t lstack_epoll_close(int32_t fd)
{
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
    if (epoll_sock == NULL || epoll_sock->weakup == NULL) {
        LSTACK_LOG(ERR, LSTACK, "epfd=%d\n", fd);
        GAZELLE_RETURN(EINVAL);
    }

    uint32_t events = event->events | EPOLLERR | EPOLLHUP;
    do {
        switch (op) {
            case EPOLL_CTL_ADD:
                sock->weakup = epoll_sock->weakup;
                /* fall through */
            case EPOLL_CTL_MOD:
                sock->epoll_events = events;
                sock->ep_data = event->data;
                if (sock->conn && NETCONNTYPE_GROUP(netconn_type(sock->conn)) == NETCONN_TCP) {
                    raise_pending_events(sock);
                }
                break;
            case EPOLL_CTL_DEL:
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

static inline int32_t save_poll_event(struct pollfd *fds, uint32_t maxevents, struct lwip_sock *sock, int32_t event_num)
{
    for (uint32_t i = 0; i < maxevents; i++) {
        /* fds[i].revents != 0, the events is kernel events */
        if (fds[i].fd == sock->conn->socket && fds[i].revents == 0) {
            fds[i].revents = sock->events;
            event_num++;
            break;
        }
    }

    return event_num;
}

static bool remove_event(enum POLL_TYPE etype, struct lwip_sock **sock_list, int32_t event_num, struct lwip_sock *sock)
{
    /* close sock */
    if (sock->stack == NULL) {
        return true;
    }

    /* remove duplicate event */
    for (uint32_t i = 0; i < event_num && etype == TYPE_EPOLL; i++) {
        if (sock_list[i] == sock) {
            return true;
        }
    }

    return !check_event_vaild(sock, sock->events);
}

static int32_t get_lwip_events(struct weakup_poll *weakup, void *out, uint32_t maxevents, enum POLL_TYPE etype)
{
    struct epoll_event *events = (struct epoll_event *)out;
    struct pollfd *fds = (struct pollfd *)out;

    uint32_t events_cnt = rte_ring_count(weakup->event_ring);
    if (events_cnt == 0) {
        return 0;
    }

    if (etype == TYPE_EPOLL) {
        maxevents = LWIP_MIN(EPOLL_MAX_EVENTS, maxevents);
    }
    events_cnt = LWIP_MIN(events_cnt, maxevents);
    int32_t event_num = 0;
    struct lwip_sock *sock = NULL;

    while (event_num < events_cnt) {
        int32_t ret = rte_ring_sc_dequeue(weakup->event_ring, (void **)&sock);
        if (ret != 0) {
            break;
        }
        sock->have_event = false;

        if (remove_event(etype, weakup->sock_list, event_num, sock)) {
            if (sock->stack) {
                sock->stack->stats.remove_event++;
            }
            continue;
        }

        if (etype == TYPE_EPOLL) {
            events[event_num].events = sock->events;
            events[event_num].data = sock->ep_data;
            weakup->sock_list[event_num] = sock;
            event_num++;
        } else {
            /* save one event at a time */
            event_num = save_poll_event(fds, maxevents, sock, event_num);
        }

        sock->stack->stats.app_events++;
        sem_trywait(&weakup->event_sem); /* each event post sem, so every read down sem */
    }

    return event_num;
}

static inline int32_t remove_kernel_invaild_events(struct pollfd *fds, int32_t nfds, int32_t event_count)
{
    int32_t real_count = 0;

    for (int i = 0; i < nfds && real_count < event_count; i++) {
        if (fds[i].fd < 0 || fds[i].revents == 0) {
            continue;
        }

        struct lwip_sock *sock = get_socket(fds[i].fd);
        if (sock && CONN_TYPE_IS_LIBOS(sock->conn)) {
            fds[i].revents = 0;
        } else {
            real_count++;
        }
    }

    return real_count;
}

static int32_t poll_event(struct weakup_poll *weakup, int32_t epfd, void *out, int32_t maxevents, int32_t timeout)
{
    struct epoll_event *events = (struct epoll_event *)out;
    struct pollfd *fds = (struct pollfd *)out;
    int32_t event_num = 0;
    int32_t event_kernel_num = 0;
    struct timespec epoll_interval = {
        .tv_sec = 0,
        .tv_nsec = EPOLL_INTERVAL_10MS,
    };
    uint32_t start_time = sys_now();

    do {
        /* epoll_wait type */
        if (epfd > 0) {
            event_num += get_lwip_events(weakup, &events[event_num], maxevents - event_num, TYPE_EPOLL);
            if (event_num >= maxevents) {
                break;
            }

            event_kernel_num = posix_api->epoll_wait_fn(epfd, &events[event_num], maxevents - event_num, 0);
            if (event_kernel_num < 0) {
                break;
            }
            event_num += event_kernel_num;
        } else {
            /* for poll events, we need to distiguish kernel events and gazelle events */
            event_kernel_num = posix_api->poll_fn(fds, maxevents, 0);
            if (event_kernel_num < 0) {
                break;
            }
            event_kernel_num = remove_kernel_invaild_events(fds, maxevents, event_kernel_num);
            event_num += event_kernel_num;

            event_num += get_lwip_events(weakup, fds, maxevents, TYPE_POLL);
        }

        if (event_num > 0) {
            break;
        }

        sem_timedwait(&weakup->event_sem, &epoll_interval);
        if (timeout > 0) {
            timeout = update_timeout(timeout, start_time);
        }
    } while (timeout != 0);

    return (event_kernel_num < 0) ? event_kernel_num : event_num;
}

static int32_t poll_init(struct pollfd *fds, nfds_t nfds, struct weakup_poll *weakup)
{
    int32_t stack_id = 0;
    int32_t stack_count[PROTOCOL_STACK_MAX] = {0};

    if (weakup->event_ring == NULL) {
        weakup->event_ring = create_ring("POLL_EVENT", VDEV_EVENT_QUEUE_SZ, RING_F_SC_DEQ, rte_gettid());
        if (weakup->event_ring == NULL) {
            GAZELLE_RETURN(ENOMEM);
        }
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
            sock->weakup = weakup;

            raise_pending_events(sock);

            stack_count[sock->stack->queue_id]++;

            /* listenfd list */
            fd = sock->nextfd;
        } while (fd > 0);
    }

    for (uint32_t i = 0; i < get_protocol_stack_group()->stack_num; i++) {
        if (stack_count[i] > stack_count[stack_id]) {
            stack_id = i;
        }
    }

    bind_to_stack_numa(stack_id);

    return 0;
}

int32_t lstack_epoll_wait(int32_t epfd, struct epoll_event* events, int32_t maxevents, int32_t timeout)
{
    /* avoid the starvation of epoll events from both netstack */
    maxevents = LWIP_MIN(LWIP_EPOOL_MAX_EVENTS, maxevents);

    struct lwip_sock *sock = get_socket_by_fd(epfd);
    if (sock == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    if (sock->weakup == NULL) {
        return posix_api->epoll_wait_fn(epfd, events, maxevents, timeout);
    }

    return poll_event(sock->weakup, epfd, events, maxevents, timeout);
}

int32_t lstack_poll(struct pollfd *fds, nfds_t nfds, int32_t timeout)
{
    int32_t ret = poll_init(fds, nfds, &g_weakup_poll);
    if (ret != 0) {
        return -1;
    }

    return poll_event(&g_weakup_poll, -1, fds, nfds, timeout);
}
