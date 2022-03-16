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

#ifndef __GAZELLE_WEAKUP_THREAD_H__
#define __GAZELLE_WEAKUP_THREAD_H__

#include <rte_ring.h>
#include "lstack_dpdk.h"

#define EPOLL_MAX_EVENTS    512

struct weakup_poll {
    sem_t event_sem;
    struct lwip_sock *sock_list[EPOLL_MAX_EVENTS];
    struct rte_ring *event_ring;
    struct rte_ring *self_ring;
};

#define WEAKUP_MAX           (32)

static inline void wakeup_list_sock(struct list_node *wakeup_list)
{
    struct list_node *node, *temp;

    list_for_each_safe(node, temp, wakeup_list) {
        struct lwip_sock *sock = container_of(node, struct lwip_sock, wakeup_list);

        struct weakup_poll *weakup = sock->weakup;
        struct protocol_stack *stack = sock->stack;
        if (weakup == NULL || stack == NULL) {
            list_del_node_init(&sock->wakeup_list);
            continue;
        }

        int32_t ret = rte_ring_mp_enqueue(weakup->event_ring, (void *)sock);
        if (ret == 0) {
            list_del_node_init(&sock->wakeup_list);
            sem_post(&weakup->event_sem);
            stack->stats.lwip_events++;
        } else {
            break;
        }
    }
}

static inline int32_t weakup_attach_sock(struct list_node *attach_list)
{
    struct list_node *node, *temp;
    int32_t wakeuped = -1;

    list_for_each_safe(node, temp, attach_list) {
        struct lwip_sock *sock = container_of(node, struct lwip_sock, attach_list);

        struct weakup_poll *weakup = sock->weakup;
        struct protocol_stack *stack = sock->stack;
        if (weakup == NULL || stack == NULL) {
            continue;
        }

        int32_t ret = rte_ring_mp_enqueue(weakup->event_ring, (void *)sock);
        if (ret == 0) {
            sem_post(&weakup->event_sem);
            stack->stats.lwip_events++;
            wakeuped = 0;
        }
    }

    return wakeuped;
}

static inline void weakup_thread(struct rte_ring *weakup_ring, struct list_node *wakeup_list)
{
    struct lwip_sock *sock;

    for (uint32_t i = 0; i < WEAKUP_MAX; ++i) {
        int32_t ret = rte_ring_sc_dequeue(weakup_ring, (void **)&sock);
        if (ret != 0) {
            break;
        }

        struct weakup_poll *weakup = sock->weakup;
        struct protocol_stack *stack = sock->stack;
        if (weakup == NULL || stack == NULL) {
            continue;
        }

        ret = rte_ring_mp_enqueue(weakup->event_ring, (void *)sock);
        if (ret == 0) {
            sem_post(&weakup->event_sem);
            stack->stats.lwip_events++;
        }

        /* listen notice attach sock */
        int32_t wakeuped = -1;
        if (!list_is_empty(&sock->attach_list)) {
            wakeuped = weakup_attach_sock(&sock->attach_list);
        }

        /* notice any epoll enough */
        if (ret != 0 && wakeuped != 0) {
            if (list_is_empty(&sock->wakeup_list)) {
                list_add_node(wakeup_list, &sock->wakeup_list);
            }
            break;
        }
    }
}

static inline __attribute__((always_inline))
int weakup_enqueue(struct rte_ring *weakup_ring, struct lwip_sock *sock)
{
    return rte_ring_sp_enqueue(weakup_ring, (void *)sock);
}

#endif
