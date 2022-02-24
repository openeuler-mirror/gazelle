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

struct weakup_poll {
    sem_t event_sem;
    struct rte_ring *event_ring;
};

#define WEAKUP_MAX           (32)

static inline __attribute__((always_inline))
void weakup_thread(struct rte_ring *weakup_ring)
{
    uint32_t num;
    struct lwip_sock *sock[WEAKUP_MAX];

    num = rte_ring_sc_dequeue_burst(weakup_ring, (void **)sock, WEAKUP_MAX, NULL);
    for (uint32_t i = 0; i < num; ++i) {
        rte_ring_sp_enqueue(sock[i]->weakup->event_ring, (void *)sock[i]);
        sem_post(&sock[i]->weakup->event_sem);
        sock[i]->stack->stats.lwip_events++;
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
