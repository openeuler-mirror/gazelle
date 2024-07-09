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

#ifndef _GAZELLE_EPOLL_H_
#define _GAZELLE_EPOLL_H_

#include <poll.h>
#include <stdbool.h>
#include <semaphore.h>
#include <pthread.h>

#include <lwip/list.h>

#include "common/gazelle_dfx_msg.h"
#include "common/gazelle_opt.h"

#ifdef __cplusplus
extern "C" {
#endif

enum wakeup_type {
    WAKEUP_EPOLL = 0,
    WAKEUP_POLL,
    WAKEUP_CLOSE,
};

struct protocol_stack;
struct wakeup_poll {
    /* stack thread read frequently */
    enum wakeup_type type;
    sem_t wait;
    bool in_wait;
    struct list_node wakeup_list[PROTOCOL_STACK_MAX];
    bool have_kernel_event;
    char pad __rte_cache_aligned;

    struct gazelle_wakeup_stat stat;
    struct protocol_stack *bind_stack;
    struct list_node poll_list;

    /* poll */
    struct pollfd *last_fds;
    nfds_t last_nfds;
    nfds_t last_max_nfds;
    struct epoll_event *events;

    /* epoll */
    int32_t epollfd; /* epoll kernel fd */
    int32_t stack_fd_cnt[PROTOCOL_STACK_MAX];
    struct protocol_stack *max_stack;
    struct list_node event_list;
    pthread_spinlock_t event_list_lock;
};

struct netconn;
struct lwip_sock;

void add_sock_event(struct lwip_sock *sock, uint32_t event);
void add_sock_event_nolock(struct lwip_sock *sock, uint32_t event);
void del_sock_event(struct lwip_sock *sock, uint32_t event);
void del_sock_event_nolock(struct lwip_sock *sock, uint32_t event);

void wakeup_stack_epoll(struct protocol_stack *stack);

int32_t lstack_epoll_create(int32_t size);
int32_t lstack_epoll_create1(int32_t flags);
int32_t lstack_rtw_epoll_ctl(int32_t epfd, int32_t op, int32_t fd, struct epoll_event *event);
int32_t lstack_rtc_epoll_ctl(int32_t epfd, int32_t op, int32_t fd, struct epoll_event *event);
int32_t lstack_rtw_epoll_wait(int32_t epfd, struct epoll_event *events, int32_t maxevents, int32_t timeout);
int32_t lstack_rtc_epoll_wait(int32_t epfd, struct epoll_event* events, int32_t maxevents, int32_t timeout);
int32_t lstack_poll(struct pollfd *fds, nfds_t nfds, int32_t timeout);
int lstack_select(int maxfd, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeval);

int32_t lstack_block_wait(struct wakeup_poll *wakeup, int32_t timeout);

static inline void lstack_block_wakeup(struct wakeup_poll *wakeup)
{
    if (wakeup && __atomic_load_n(&wakeup->in_wait, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&wakeup->in_wait, false, __ATOMIC_RELEASE);
        rte_mb();
        sem_post(&wakeup->wait);
    }
}

#ifdef __cplusplus
}
#endif

#endif /* _GAZELLE_EPOLL_H_ */
