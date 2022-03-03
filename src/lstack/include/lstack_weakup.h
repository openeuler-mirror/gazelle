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

#ifndef __LIBOS_WEAKUP_THREAD_H__
#define __LIBOS_WEAKUP_THREAD_H__

#include <rte_ring.h>
#include "lstack_dpdk.h"

#define EPOLL_MAX_EVENTS    256

struct weakup_poll {
    sem_t event_sem;
    struct lwip_sock *sock_list[EPOLL_MAX_EVENTS];
    struct rte_ring *event_ring;
};

#define WEAKUP_MAX           (32)

static inline __attribute__((always_inline)) void weakup_attach_sock(struct lwip_sock *sock)
{
    struct list_node *list = &(sock->attach_list);
    struct list_node *node, *temp;
    struct lwip_sock *attach_sock;
    int32_t ret;

    list_for_each_safe(node, temp, list) {
        attach_sock = container_of(node, struct lwip_sock, attach_list);
        if (attach_sock->weakup == NULL) {
            continue;
        }

        ret = rte_ring_mp_enqueue(attach_sock->weakup->event_ring, (void *)attach_sock);
        if (ret == 0) {
            sem_post(&attach_sock->weakup->event_sem);
            attach_sock->stack->stats.lwip_events++;
        }
    }
}

static inline __attribute__((always_inline)) void weakup_thread(struct rte_ring *weakup_ring)
{
    uint32_t num;
    struct lwip_sock *sock[WEAKUP_MAX];
    int32_t ret;

    num = rte_ring_sc_dequeue_burst(weakup_ring, (void **)sock, WEAKUP_MAX, NULL);
    for (uint32_t i = 0; i < num; ++i) {
        ret = rte_ring_mp_enqueue(sock[i]->weakup->event_ring, (void *)sock[i]);
        if (ret == 0) {
            sem_post(&sock[i]->weakup->event_sem);
            sock[i]->stack->stats.lwip_events++;
        }

        /* listen notice attach sock */
        if (!list_is_empty(&sock[i]->attach_list)) {
            weakup_attach_sock(sock[i]);
        }
    }
}

static inline __attribute__((always_inline))
int weakup_enqueue(struct rte_ring *weakup_ring, struct lwip_sock *sock)
{
    int ret = rte_ring_sp_enqueue(weakup_ring, (void *)sock);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, failed\n", gettid());
        return -1;
    }

    return 0;
}

#endif
