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

#ifndef _GAZELLE_SK_SLEEP_H
#define _GAZELLE_SK_SLEEP_H


#include <pthread.h>

#include <lwip/lwipgz_list.h>

struct sk_sleep {
    pthread_spinlock_t lock; /* mutually exclusive access for linked lists */
    struct list_node head;
    int32_t node_count;
    struct sk_sleep_node *preallocated_node; /* Preallocated nodes in the memory pool */
};

struct sk_sleep_node {
    struct list_node list_node;
    int epollfd; /* find the thread that needs to be awakened */
    void *priv; /* lwip sock */
    uint32_t events; /* type of monitoring: read, write, and errors */
    uint32_t revents; /* ready events */
    void (*func)(struct sk_sleep_node *);
    #define READY   0x1
    #define NO_FREE 0x2
    uint32_t flags; /* event ready flag */
};

void sk_sleep_set_ready(struct sk_sleep *sk_sleep, struct sk_sleep_node *n);

static inline void sk_sleep_clear_ready(struct sk_sleep_node *n)
{
    n->flags &= ~READY;
}

static inline bool sk_sleep_is_ready(struct sk_sleep_node *n)
{
    return (n->flags & READY);
}

/* sk_sleep APIs */
struct sk_sleep *sk_sleep_init(void);
void sk_sleep_uninit(struct sk_sleep *sk_sleep);
void sk_sleep_add_node(struct sk_sleep *sk_sleep, struct sk_sleep_node *n);
void sk_sleep_remove_node(struct sk_sleep *sk_sleep, struct sk_sleep_node *n);
void sk_sleep_wakeup_all_by_events(struct sk_sleep *sk_sleep, uint32_t events);
void sk_sleep_wakeup_node(struct sk_sleep *sk_sleep, struct sk_sleep_node *node);

#endif /* _GAZELLE_SK_SLEEP_H_ */

