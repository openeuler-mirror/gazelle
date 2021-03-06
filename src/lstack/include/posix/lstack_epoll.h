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

#include "gazelle_dfx_msg.h"
#include "gazelle_opt.h"

#ifdef __cplusplus
extern "C" {
#endif

enum wakeup_type {
    WAKEUP_EPOLL = 0,
    WAKEUP_POLL,
};

struct protocol_stack;
struct wakeup_poll {
    /* stack thread read frequently */
    sem_t event_sem __rte_cache_aligned;
    enum wakeup_type type __rte_cache_aligned;
    volatile bool have_kernel_event __rte_cache_aligned;
    struct gazelle_wakeup_stat stat __rte_cache_aligned;
    char pad __rte_cache_aligned;

    bool init;
    struct protocol_stack *bind_stack;
    int32_t epollfd; /* epoll kernel fd, ctl add into gazelle_kernel_event thread */
    struct wakeup_poll *next;

    /* poll */
    struct pollfd *last_fds;
    nfds_t last_nfds;
    nfds_t last_max_nfds;
    struct epoll_event *events;

    /* epoll */
    int32_t stack_fd_cnt[PROTOCOL_STACK_MAX];
    struct protocol_stack *max_stack;
    struct list_node event_list;
    pthread_spinlock_t event_list_lock;
};

struct netconn;
void add_epoll_event(struct netconn *conn, uint32_t event);
int32_t lstack_epoll_create(int32_t size);
int32_t lstack_epoll_ctl(int32_t epfd, int32_t op, int32_t fd, struct epoll_event *event);
int32_t lstack_epoll_wait(int32_t epfd, struct epoll_event *events, int32_t maxevents, int32_t timeout);
int32_t lstack_poll(struct pollfd *fds, nfds_t nfds, int32_t timeout);

#ifdef __cplusplus
}
#endif

#endif /* _GAZELLE_EPOLL_H_ */
