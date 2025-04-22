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
#include <time.h>
#include <pthread.h>

#include <rte_cycles.h>

#include <lwip/sockets.h>
#include <lwip/lwipgz_sock.h>
#include <lwip/lwipgz_posix_api.h>

#include "lstack_epoll.h"
#include "common/dpdk_common.h"
#include "common/gazelle_base_func.h"
#include "lstack_preload.h"
#include "lstack_cfg.h"
#include "lstack_log.h"
#include "lstack_protocol_stack.h"

#define POLL_MAX_EVENTS         32

static PER_THREAD struct sock_wait *g_sk_wait = NULL;


static int rtc_sock_wait_timedwait(struct sock_wait *sk_wait, int timeout, uint32_t start)
{
    stack_polling(0);

    if (timeout > 0 && timeout <= (int)(sys_now() - start)) {
        timeout = 0;
    } else if (timeout < 0) {
        errno = 0;
    }
    return timeout;
}

static int rtw_sock_wait_timedwait(struct sock_wait *sk_wait, int timeout, uint32_t start)
{
    /* when sem interrupted by signals, errno = EINTR */
    return sys_sem_wait_internal(&sk_wait->sem, timeout);
}

static void rtc_epoll_notify_event(struct sock_wait *sk_wait, struct sock_event *sk_event, 
    unsigned pending, int stack_id)
{
    sk_event->pending |= pending;
    if (list_node_null(&sk_event->event_node)) {
        list_add_node(&sk_event->event_node, &sk_wait->epcb.event_list);
    }
}

static void rtc_epoll_remove_event(struct sock_wait *sk_wait, struct sock_event *sk_event, unsigned pending)
{
    sk_event->pending &= ~pending;
    if (sk_event->pending == 0) {
        list_del_node(&sk_event->event_node);
    }
}

static void rtw_epoll_notify_event(struct sock_wait *sk_wait, struct sock_event *sk_event, 
    unsigned pending, int stack_id)
{
#if SOCK_WAIT_BATCH_NOTIFY
    if (likely(stack_id >= 0)) {
        lwip_wait_add_notify(sk_wait, sk_event, pending, stack_id);
        return;
    }
#endif /* SOCK_WAIT_BATCH_NOTIFY */

    rte_spinlock_lock(&sk_wait->epcb.lock);
    sk_event->pending |= pending;
    if (list_node_null(&sk_event->event_node)) {
        list_add_node(&sk_event->event_node, &sk_wait->epcb.event_list);
    }
    rte_spinlock_unlock(&sk_wait->epcb.lock);

    sys_sem_signal_internal(&sk_wait->sem);
}

static void rtw_epoll_remove_event(struct sock_wait *sk_wait, struct sock_event *sk_event, unsigned pending)
{
    rte_spinlock_lock(&sk_wait->epcb.lock);
    sk_event->pending &= ~pending;
    if (sk_event->pending == 0) {
        list_del_node(&sk_event->event_node);
    }
    rte_spinlock_unlock(&sk_wait->epcb.lock);
}

static void rtc_poll_notify_event(struct sock_wait *sk_wait, struct sock_event *sk_event, 
    unsigned pending, int stack_id)
{
}
static void rtc_poll_remove_event(struct sock_wait *sk_wait, struct sock_event *sk_event, unsigned pending)
{
}
static void rtw_poll_notify_event(struct sock_wait *sk_wait, struct sock_event *sk_event, 
    unsigned pending, int stack_id)
{
#if SOCK_WAIT_BATCH_NOTIFY
    if (likely(stack_id >= 0)) {
        lwip_wait_add_notify(sk_wait, NULL, 0, stack_id);
        return;
    }
#endif /* SOCK_WAIT_BATCH_NOTIFY */
    sys_sem_signal_internal(&sk_wait->sem);
}
static void rtw_poll_remove_event(struct sock_wait *sk_wait, struct sock_event *sk_event, unsigned pending)
{
}

/* Cannot support the same sock being waited by both epoll/poll/select or multiple epollfd. */
static void sock_wait_check_change(struct sock_wait *new_sk_wait, struct sock_wait *old_sk_wait)
{
    if (old_sk_wait == NULL || new_sk_wait == old_sk_wait ||
        old_sk_wait->type == WAIT_CLOSE) {
        return;
    }

    if (new_sk_wait->type & WAIT_EPOLL) {
        if (old_sk_wait->type & WAIT_EPOLL) {
            LSTACK_LOG(ERR, LSTACK, "Cannot support the same sock being waited by multiple epollfd! \n");
        } else {
            LSTACK_LOG(ERR, LSTACK, "Cannot support the same sock being waited by both epoll/poll/select! \n");
        }
    }
}


static int epoll_cb_init(struct epoll_cb *epcb)
{
    list_init_head(&epcb->event_list);
    rte_spinlock_init(&epcb->lock);
    return 0;
}

static void epoll_cb_free(struct epoll_cb *epcb)
{
    struct list_node *node, *temp;
    struct sock_event *sk_event;

    rte_spinlock_lock(&epcb->lock);

    list_for_each_node(node, temp, &epcb->event_list) {
        sk_event = list_entry(node, struct sock_event, event_node);
        list_del_node(&sk_event->event_node);
    }

    rte_spinlock_unlock(&epcb->lock);
}

static int epoll_create_internal(int epfd)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    bool rtc_mode = get_global_cfg_params()->stack_mode_rtc;
    struct sock_wait *sk_wait;
    struct lwip_sock *epsock;

    epsock = lwip_get_socket(epfd);
    if (epsock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "epfd=%d sock is NULL errno=%d\n", epfd, errno);
        GAZELLE_RETURN(EINVAL);
    }

    /* calloc will memset to zero */
    sk_wait = calloc(1, sizeof(struct sock_wait));
    if (sk_wait == NULL) {
        LSTACK_LOG(ERR, LSTACK, "calloc null\n");
        GAZELLE_RETURN(EINVAL);
    }

    sk_wait->type = WAIT_EPOLL;
    sock_wait_common_init(sk_wait);
    sock_wait_kernel_init(sk_wait, epfd, stack_group->stack_num);
    epoll_cb_init(&sk_wait->epcb);

    if (rtc_mode) {
        sk_wait->timedwait_fn = rtc_sock_wait_timedwait;
        sk_wait->notify_fn = rtc_epoll_notify_event;
        sk_wait->remove_fn = rtc_epoll_remove_event;
    } else {
        sk_wait->timedwait_fn = rtw_sock_wait_timedwait;
        sk_wait->notify_fn = rtw_epoll_notify_event;
        sk_wait->remove_fn = rtw_epoll_remove_event;
    }

    epsock->sk_wait = sk_wait;
    return 0;
}

static int epoll_close_internal(int epfd)
{
    struct sock_wait *sk_wait;
    struct lwip_sock *epsock;

    epsock = lwip_get_socket(epfd);
    if (epsock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "epfd=%d sock is NULL errno=%d\n", epfd, errno);
        GAZELLE_RETURN(EINVAL);
    }

    sk_wait = epsock->sk_wait;
    if (sk_wait == NULL) {
        return 0;
    }

    sk_wait->type = WAIT_CLOSE;
    epoll_cb_free(&sk_wait->epcb);

    sock_wait_kernel_free(sk_wait);
    sock_wait_common_free(sk_wait);

    sk_wait->timedwait_fn = NULL;
    sk_wait->notify_fn = NULL;
    sk_wait->remove_fn = NULL;

    /* FIXME: set all 'sock->sk_wait = NULL' before free. */
    free(sk_wait);
    epsock->sk_wait = NULL;

    return 0;
}

int lstack_epoll_create1(int flags)
{
    int epfd = posix_api->epoll_create1_fn(flags);
    if (epfd != -1) {
        if (epoll_create_internal(epfd) != 0) {
            posix_api->close_fn(epfd);
            epfd = -1;
        }
    }
    return epfd;
}

int lstack_epoll_create(int size)
{
    /* Since Linux 2.6.8, the size argument is ignored, 
     * but must be greater than zero. */
    return size <= 0 ? -1 : lstack_epoll_create1(0);
}

int lstack_epoll_close(int epfd)
{
    epoll_close_internal(epfd);
    return posix_api->close_fn(epfd);
}

int epoll_ctl_kernel_event(int epfd, int op, int fd, struct epoll_event *event, 
    struct sock_wait *sk_wait)
{
    int ret;

    ret = posix_api->epoll_ctl_fn(epfd, op, fd, event);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "epoll_ctl_fn failed, fd=%d epfd=%d op=%d\n", fd, epfd, op);
        return ret;
    }
    if (op == EPOLL_CTL_ADD) {
        sk_wait->kernel_nfds++;
    } else if (op == EPOLL_CTL_DEL) {
        sk_wait->kernel_nfds--;
    }

    return ret;
}

int lstack_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    int ret;
    struct lwip_sock *epsock = lwip_get_socket(epfd);
    struct lwip_sock *sock = lwip_get_socket(fd);
    struct sock_wait *sk_wait = epsock->sk_wait;
    struct sock_event *sk_event;
    unsigned pending;

    if (epfd < 0 || fd < 0 || epfd == fd || \
        (event == NULL && op != EPOLL_CTL_DEL)) {
        LSTACK_LOG(ERR, LSTACK, "fd=%d epfd=%d op=%d\n", fd, epfd, op);
        GAZELLE_RETURN(EINVAL);
    }

    LWIP_DEBUGF(SOCKETS_DEBUG, ("%s(epfd=%d, op=%d, fd=%d, event=%p)\n",
                __FUNCTION__, epfd, op, fd, event));

    enum posix_type sk_type = select_sock_posix_path(sock);
    if (sk_type & POSIX_KERNEL) {   /* has POSIX_KERNEL */
        ret = epoll_ctl_kernel_event(epfd, op, fd, event, sk_wait);
        if (ret != 0 ||
            sk_type == POSIX_KERNEL) {  /* is POSIX_KERNEL */
            return ret;
        }
    }

    for (; sock != NULL; sock = sock->listen_next) {
        sk_event = &sock->sk_event;

        switch (op) {
        case EPOLL_CTL_ADD:
            sock_wait_check_change(sk_wait, sock->sk_wait);
            sock->sk_wait = sk_wait;
            /* fall through */
        case EPOLL_CTL_MOD:
            sk_event->events = event->events | EPOLLERR | EPOLLHUP;
            sk_event->ep_data = event->data;

            pending = sock_event_hold_pending(sock, WAIT_EPOLL, NETCONN_EVT_RCVPLUS, 0)  |
                      sock_event_hold_pending(sock, WAIT_EPOLL, NETCONN_EVT_SENDPLUS, 0) |
                      sock_event_hold_pending(sock, WAIT_EPOLL, NETCONN_EVT_ERROR, 0);
            sk_wait->notify_fn(sk_wait, sk_event, pending, -1);

            sk_wait->lwip_nfds++;
            sk_wait->affinity.stack_nfds[sock->stack_id]++;
            break;
        case EPOLL_CTL_DEL:
            sk_event->events = 0;

            pending = sock_event_hold_pending(sock, WAIT_EPOLL, NETCONN_EVT_RCVMINUS, 0)  |
                      sock_event_hold_pending(sock, WAIT_EPOLL, NETCONN_EVT_SENDMINUS, 0) |
                      sock_event_hold_pending(sock, WAIT_EPOLL, NETCONN_EVT_ERROR, 0);
            sk_wait->remove_fn(sk_wait, sk_event, pending);

            sk_wait->lwip_nfds--;
            sk_wait->affinity.stack_nfds[sock->stack_id]--;
            break;
        default:
            GAZELLE_RETURN(EINVAL);
        }
    }

    if (get_global_cfg_params()->app_bind_numa) {
        affinity_update_max_stack(&sk_wait->affinity);
    }
    return 0;
}

static int epoll_scan_lwip_event(struct epoll_cb *epcb, struct epoll_event *events, int maxevents)
{
    bool rtc_mode = get_global_cfg_params()->stack_mode_rtc;
    struct list_node *node, *temp;
    struct sock_event *sk_event;
    int num = 0;

    if (!rtc_mode)
        rte_spinlock_lock(&epcb->lock);

    list_for_each_node(node, temp, &epcb->event_list) {
        sk_event = list_entry(node, struct sock_event, event_node);
        if (num >= maxevents) {
            /* move list head after the current node, 
             * and start traversing from this node next time */
            list_del_node(&epcb->event_list);
            list_add_node(&epcb->event_list, node);
            break;
        }

        if ((sk_event->events & sk_event->pending) == 0) {
            // LSTACK_LOG(WARNING, LSTACK, "get empty event\n");
            list_del_node(node);
            continue;
        }

        events[num].events = sk_event->pending;
        events[num].data = sk_event->ep_data;
        num++;

        if (sk_event->events & EPOLLET) {
            sk_event->pending = 0;
            list_del_node(node);
        }

        /* EPOLLONESHOT: generate event after epoll_ctl add/mod event again,
         * epoll_event set 0 avoid generating event util epoll_ctl reset epoll_event */
        if (sk_event->events & EPOLLONESHOT) {
            sk_event->events = 0;
            list_del_node(node);
        }
    }

    if (!rtc_mode)
        rte_spinlock_unlock(&epcb->lock);

    return num;
}

int lstack_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout)
{
    bool rtc_mode = get_global_cfg_params()->stack_mode_rtc;
    struct lwip_sock *epsock = lwip_get_socket(epfd);
    struct sock_wait *sk_wait = epsock->sk_wait;
    int kernel_num = 0;
    int lwip_num = 0;
    int lwip_maxevents;
    uint32_t start;

    if (unlikely(epfd < 0)) {
        GAZELLE_RETURN(EBADF);
    }
    if (unlikely(events == NULL || maxevents <= 0 || timeout < -1)) {
        GAZELLE_RETURN(EINVAL);
    }

    if (get_global_cfg_params()->app_bind_numa) {
        affinity_bind_stack(sk_wait, &sk_wait->affinity);
    }

    /* avoid RTC app process events for a long time */
    if (rtc_mode && maxevents > POLL_MAX_EVENTS) {
        maxevents = POLL_MAX_EVENTS;
    }
    /* avoid the starvation of poll events from both kernel and lwip */
    lwip_maxevents = sk_wait->kernel_nfds > 0 ? 
                     (maxevents >> 1) + 1 : maxevents;

    start = sys_now();

    /* RTC try to recv polling. */
    sk_wait->timedwait_fn(sk_wait, 0, start);
    do {
        if (likely(sk_wait->lwip_nfds > 0)) {
            lwip_num = epoll_scan_lwip_event(&sk_wait->epcb, events, lwip_maxevents);
        }

        if (sk_wait->kernel_nfds > 0 && rte_atomic16_read(&sk_wait->kernel_pending)) {
            kernel_num = posix_api->epoll_wait_fn(
                sk_wait->epfd, &events[lwip_num], maxevents - lwip_num, 0);
            if (unlikely(kernel_num == 0) && errno != EINTR && errno != EAGAIN) {
                rte_atomic16_set(&sk_wait->kernel_pending, false);
            }
        }

        if (lwip_num + kernel_num > 0) {
            break;
        }

        timeout = sk_wait->timedwait_fn(sk_wait, timeout, start);
    } while (timeout > 0 || (timeout < 0 && errno == 0));

    sk_wait->stat.app_events += lwip_num;
    sk_wait->stat.kernel_events += kernel_num;

    return lwip_num + kernel_num;
}

static void poll_cb_free(struct poll_cb *pcb)
{
    if (pcb->lwip_p_fds != NULL) {
        free(pcb->lwip_p_fds);
        pcb->lwip_p_fds = NULL;
    }
    if (pcb->kernel_fds != NULL) {
        free(pcb->kernel_fds);
        pcb->kernel_fds = NULL;
    }
}

static int poll_cb_init(struct poll_cb *pcb, int nfds)
{
    if (nfds <= 0)
        return 0;

    pcb->lwip_p_fds = calloc(1, sizeof(*pcb->lwip_p_fds) * nfds);
    pcb->kernel_fds = calloc(1, sizeof(*pcb->kernel_fds) * nfds);

    if (pcb->lwip_p_fds == NULL || pcb->kernel_fds == NULL) {
        poll_cb_free(pcb);
        return -1;
    }

    pcb->max_nfds = nfds;
    return 0;
}

static int poll_init_wait(struct sock_wait *sk_wait, int nfds)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    bool rtc_mode = get_global_cfg_params()->stack_mode_rtc;
    int epfd;

    epfd = posix_api->epoll_create_fn(POLL_MAX_EVENTS);
    if (epfd < 0) {
        LSTACK_LOG(ERR, LSTACK, "epoll_create failed, errno %d\n", errno);
        return -1;
    }

    sk_wait->type = WAIT_POLL;
    sock_wait_common_init(sk_wait);
    sock_wait_kernel_init(sk_wait, epfd, stack_group->stack_num);

    if (rtc_mode) {
        sk_wait->timedwait_fn = rtc_sock_wait_timedwait;
        sk_wait->notify_fn = rtc_poll_notify_event;
        sk_wait->remove_fn = rtc_poll_remove_event;
    } else {
        sk_wait->timedwait_fn = rtw_sock_wait_timedwait;
        sk_wait->notify_fn = rtw_poll_notify_event;
        sk_wait->remove_fn = rtw_poll_remove_event;
    }

    return poll_cb_init(&sk_wait->pcb, nfds);
}

static void poll_free_wait(struct sock_wait *sk_wait)
{
    sk_wait->type = WAIT_CLOSE;
    poll_cb_free(&sk_wait->pcb);

    posix_api->close_fn(sk_wait->epfd);
    sock_wait_kernel_free(sk_wait);
    sock_wait_common_free(sk_wait);

    sk_wait->timedwait_fn = NULL;
    sk_wait->notify_fn = NULL;
    sk_wait->remove_fn = NULL;
}

void poll_destruct_wait(void)
{
    if (unlikely(g_sk_wait == NULL)) {
        return;
    }

    poll_free_wait(g_sk_wait);

    /* FIXME: set all 'sock->sk_wait = NULL' before free. */
    free(g_sk_wait);
    g_sk_wait = NULL;
}

struct sock_wait *poll_construct_wait(int nfds)
{
    if (unlikely(g_sk_wait == NULL)) {
        g_sk_wait = calloc(1, sizeof(struct sock_wait));
        if (g_sk_wait == NULL) {
            LSTACK_LOG(ERR, LSTACK, "calloc failed errno=%d\n", errno);
            return NULL;
        }

        if (poll_init_wait(g_sk_wait, nfds) < 0) {
            free(g_sk_wait);
            return NULL;
        }
    }

    /* resize poll_cb */
    if (g_sk_wait->pcb.max_nfds < nfds) {
        poll_cb_free(&g_sk_wait->pcb);
        if (poll_cb_init(&g_sk_wait->pcb, nfds) != 0) {
            return NULL;
        }
    }

    return g_sk_wait;
}

static int poll_ctl_kernel_event(int epfd, int fds_id,
    const struct pollfd *new_fds, const struct pollfd *old_fds)
{
    int ret;
    struct epoll_event epevent;

    LWIP_DEBUGF(SOCKETS_DEBUG, ("%s(epfd=%d, old_fd=%d, new_fd=%d)\n",
                __FUNCTION__, epfd, old_fds->fd, new_fds->fd));

    epevent.data.fd = fds_id;
    epevent.events = new_fds->events;

    /* EPOLL_CTL_MOD may not be any events, but why? */
    if (old_fds->fd == 0) {
        ret = posix_api->epoll_ctl_fn(epfd, EPOLL_CTL_ADD, new_fds->fd, &epevent);
    } else {
        ret = posix_api->epoll_ctl_fn(epfd, EPOLL_CTL_DEL, old_fds->fd, NULL);
        ret |= posix_api->epoll_ctl_fn(epfd, EPOLL_CTL_ADD, new_fds->fd, &epevent);
    }

    if (ret != 0 && errno != EINTR && errno != ENOENT) {
        LSTACK_LOG(ERR, LSTACK, "epoll_ctl failed, errno %d, new_fd %d, old_fd %d\n", 
            errno, new_fds->fd, old_fds->fd);
    }
    return ret;
}

static int poll_wait_kernel_event(int epfd, struct pollfd *fds, int maxevents)
{
    struct epoll_event epevents[POLL_MAX_EVENTS];
    int num = 0;
    int i, fds_id;

    num = posix_api->epoll_wait_fn(epfd, epevents, maxevents, 0);
    for (i = 0; i < num; ++i) {
        fds_id = epevents[i].data.fd;
        fds[fds_id].revents = epevents[i].events;
    }

    return num;
}

static void poll_prepare_wait(struct sock_wait *sk_wait, struct pollfd *fds, nfds_t nfds)
{
    struct poll_cb *pcb = &sk_wait->pcb;
    struct lwip_sock *sock;
    enum posix_type sk_type;
    int fd, i;

    sk_wait->lwip_nfds = 0;
    sk_wait->kernel_nfds = 0;
    memset_s(&sk_wait->affinity.stack_nfds, sizeof(sk_wait->affinity.stack_nfds),
             0, sizeof(sk_wait->affinity.stack_nfds));

    for (i = 0; i < nfds; ++i) {
        fd = fds[i].fd;
        sock = lwip_get_socket(fd);
        sk_type = select_sock_posix_path(sock);

        if (sk_type & POSIX_KERNEL) {
            poll_ctl_kernel_event(sk_wait->epfd, i, &fds[i], 
                &pcb->kernel_fds[sk_wait->kernel_nfds]);
            pcb->kernel_fds[sk_wait->kernel_nfds] = fds[i];
            sk_wait->kernel_nfds++;
        }

        if (sk_type & POSIX_LWIP) {
            pcb->lwip_p_fds[sk_wait->lwip_nfds] = &fds[i];
            sk_wait->lwip_nfds++;

            for (; sock != NULL; sock = sock->listen_next) {
                sock->sk_event.events = fds[i].events | POLLERR;
                sock_wait_check_change(sk_wait, sock->sk_wait);
                sock->sk_wait = sk_wait;
                sk_wait->affinity.stack_nfds[sock->stack_id]++;
            }
        }
    }

    if (get_global_cfg_params()->app_bind_numa) {
        affinity_update_max_stack(&sk_wait->affinity);
        affinity_bind_stack(sk_wait, &sk_wait->affinity);
    }

    return;
}

static int poll_scan_lwip_event(struct poll_cb *pcb, int nfds, int maxevents)
{
    struct lwip_sock *sock;
    struct pollfd *fds;
    int num = 0;
    int i;

    for (i = 0; i < nfds && num < maxevents; ++i) {
        fds = pcb->lwip_p_fds[i];
        sock = lwip_get_socket(fds->fd);

        for (; !POSIX_IS_CLOSED(sock); sock = sock->listen_next) {
            fds->revents = sock_event_hold_pending(sock, WAIT_POLL, NETCONN_EVT_RCVPLUS, 0)  | 
                           sock_event_hold_pending(sock, WAIT_POLL, NETCONN_EVT_SENDPLUS, 0) | 
                           sock_event_hold_pending(sock, WAIT_POLL, NETCONN_EVT_ERROR, 0);
            if (fds->revents != 0) {
                num++;
                break;
            }
        }
    }

    return num;
}

int lstack_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    struct sock_wait *sk_wait;
    int kernel_num = 0;
    int lwip_num = 0;
    uint32_t start;

    if (unlikely(fds == NULL || nfds == 0 || timeout < -1)) {
        GAZELLE_RETURN(EINVAL);
    }

    sk_wait = poll_construct_wait(nfds);
    if (unlikely(sk_wait == NULL)) {
        return -1;
    }
    poll_prepare_wait(sk_wait, fds, nfds);

    if (sk_wait->lwip_nfds == 0 && sk_wait->kernel_nfds > 0) {
        return posix_api->poll_fn(fds, nfds, timeout);
    }

    start = sys_now();

    /* RTC try to recv polling. */
    sk_wait->timedwait_fn(sk_wait, 0, start);
    do {
        if (sk_wait->lwip_nfds > 0) {
            lwip_num = poll_scan_lwip_event(&sk_wait->pcb, sk_wait->lwip_nfds, nfds);
        }

        if (sk_wait->kernel_nfds > 0 && rte_atomic16_read(&sk_wait->kernel_pending)) {
            kernel_num = poll_wait_kernel_event(sk_wait->epfd, fds, sk_wait->kernel_nfds);
            if (kernel_num == 0 && errno != EINTR && errno != EAGAIN) {
                rte_atomic16_set(&sk_wait->kernel_pending, false);
            }
        }

        if (lwip_num + kernel_num > 0) {
            break;
        }

        timeout = sk_wait->timedwait_fn(sk_wait, timeout, start);
    } while (timeout > 0 || (timeout < 0 && errno == 0));

    sk_wait->stat.app_events += lwip_num;
    sk_wait->stat.kernel_events += kernel_num;

    return lwip_num + kernel_num;
}

/* refer to linux kernel */
#define POLLIN_SET  (EPOLLRDNORM | EPOLLRDBAND | EPOLLIN | EPOLLHUP | EPOLLERR)
#define POLLOUT_SET (EPOLLWRBAND | EPOLLWRNORM | EPOLLOUT | EPOLLERR)
#define POLLEX_SET  (EPOLLPRI)

static int fds_select2poll(struct pollfd *fds, int maxfd,
    fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
    int nfds = 0;

    for (int i = 0; i < maxfd; i++) {
        if (readfds && FD_ISSET(i, readfds)) {
            fds[nfds].events = POLLIN_SET;
        }
        if (writefds && FD_ISSET(i, writefds)) {
            fds[nfds].events |= POLLOUT_SET;
        }
        if (exceptfds && FD_ISSET(i, exceptfds)) {
            fds[nfds].events |= POLLEX_SET;
        }
        if (fds[nfds].events > 0) {
            fds[nfds].fd = i;
            nfds++;
        }
    }

    return nfds;
}

static void fds_poll2select(const struct pollfd *fds, int nfds,
    fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
    if (readfds)
        FD_ZERO(readfds);
    if (writefds)
        FD_ZERO(writefds);
    if (exceptfds)
        FD_ZERO(exceptfds);

    for (int i = 0; i < nfds; ++i) {
        if (readfds && fds[i].revents & POLLIN_SET) {
            FD_SET(fds[i].fd, readfds);
        }
        if (writefds && fds[i].revents & POLLOUT_SET) {
            FD_SET(fds[i].fd, writefds);
        }
        if (exceptfds && fds[i].revents & POLLEX_SET) {
            FD_SET(fds[i].fd, exceptfds);
        }
    }
}

static inline int timeval2ms(struct timeval *timeval)
{
    if (timeval == NULL) {
        return -1;
    }
    return timeval->tv_sec * MS_PER_S + timeval->tv_usec / (US_PER_S / MS_PER_S);
}

int lstack_select(int nfds, fd_set *readfds, fd_set *writefds,
    fd_set *exceptfds, struct timeval *timeout)
{
    struct pollfd poll_fds[FD_SETSIZE] = {0};
    int poll_nfds, num;
    int time_ms;

    if (unlikely(nfds < 0 || nfds > FD_SETSIZE)) {
        LSTACK_LOG(ERR, LSTACK, "select invalid args, nfds=%d\n", nfds);
        GAZELLE_RETURN(EINVAL);
    }
    if (timeout != NULL && unlikely(timeout->tv_sec < 0 || timeout->tv_usec < 0)) {
        LSTACK_LOG(ERR, LSTACK, "select invalid args, timeout\n");
        GAZELLE_RETURN(EINVAL);
    }
    /* empty fds, just timeout */
    if (!readfds && !writefds && !exceptfds) {
        return posix_api->select_fn(nfds, readfds, writefds, exceptfds, timeout);
    }

    time_ms = timeval2ms(timeout);

    poll_nfds = fds_select2poll(poll_fds, nfds, readfds, writefds, exceptfds);
    num = lstack_poll(poll_fds, poll_nfds, time_ms);
    fds_poll2select(poll_fds, poll_nfds, readfds, writefds, exceptfds);

    return num;
}

void epoll_api_init(posix_api_t *api)
{
    api->epoll_create1_fn = lstack_epoll_create1;
    api->epoll_create_fn  = lstack_epoll_create;
    api->epoll_ctl_fn     = lstack_epoll_ctl;
    api->epoll_wait_fn    = lstack_epoll_wait;

    api->poll_fn          = lstack_poll;
    api->select_fn        = lstack_select;
}

bool sock_event_wait(struct lwip_sock *sock, enum netconn_evt evt, bool noblocking)
{
    bool rtc_mode = get_global_cfg_params()->stack_mode_rtc;
    uint32_t start;
    int timeout;
    unsigned pending = 0;

    if (!rtc_mode && noblocking)
        return false;

    if (unlikely(sock->sk_wait == NULL) || sock->sk_wait->type == WAIT_CLOSE) {
        sock->sk_wait = poll_construct_wait(0);
    }
    if (!(sock->sk_wait->type & WAIT_BLOCK)) {
        sock->sk_wait->type |= WAIT_BLOCK;
        rte_wmb();
    }

    if (rtc_mode) {
        /* RTC try to recv polling. */
        sock->sk_wait->timedwait_fn(sock->sk_wait, 0, 0);
        return true;
    }

    timeout = sock->conn->recv_timeout == 0 ? -1 : sock->conn->recv_timeout;
    start = sys_now();
    do {
        pending = sock_event_hold_pending(sock, WAIT_BLOCK, evt, 0) |
                  sock_event_hold_pending(sock, WAIT_BLOCK, NETCONN_EVT_ERROR, 0);
        if (pending != 0) {
            break;
        }
        timeout = sock->sk_wait->timedwait_fn(sock->sk_wait, timeout, start);
    } while (timeout > 0 || (timeout < 0 && errno == 0));

    if (errno == ETIMEDOUT) {
        errno = EAGAIN;
    }

    if (evt == NETCONN_EVT_SENDPLUS) {
        /* remove WAIT_BLOCK type */
        sock->sk_wait->type &= ~WAIT_BLOCK;
    }
    return pending != 0;
}
