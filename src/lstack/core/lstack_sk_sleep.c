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
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <malloc.h>

#include <lwip/lwipgz_list.h>

#include "lstack_sk_sleep.h"


struct sk_sleep *sk_sleep_init(void)
{
    struct sk_sleep *sk_sleep = malloc(sizeof(struct sk_sleep));
    if (sk_sleep == NULL) {
        return NULL;
    }

    pthread_spin_init(&sk_sleep->lock, PTHREAD_PROCESS_PRIVATE);
    list_init_head(&sk_sleep->head);
    sk_sleep->node_count = 0;
    
    sk_sleep->preallocated_node = (struct sk_sleep_node *)malloc(sizeof(struct sk_sleep_node));
    if (sk_sleep->preallocated_node == NULL) {
        free(sk_sleep);
        return NULL;
    }

    return sk_sleep;
}

void sk_sleep_uninit(struct sk_sleep *sk_sleep)
{
     /* clean up sk_sleep related resources */
    pthread_spin_lock(&sk_sleep->lock);
    struct list_node *current_node, *temp_node;
    list_for_each_node(current_node, temp_node, &sk_sleep->head) {
        struct sk_sleep_node *sk_node = list_entry(current_node, struct sk_sleep_node, list_node);
        list_del_node(&sk_node->list_node);
        sk_node->func(sk_node);
        if (!(sk_node->flags & NO_FREE)) {
            free(sk_node);
        }
    }
    pthread_spin_unlock(&sk_sleep->lock);

    pthread_spin_destroy(&sk_sleep->lock);
    free(sk_sleep->preallocated_node);
    free(sk_sleep);
}

void sk_sleep_add_node(struct sk_sleep *sk_sleep, struct sk_sleep_node *n)
{
    bool no_free;
    struct sk_sleep_node *new_node;

    pthread_spin_lock(&sk_sleep->lock);
    if (sk_sleep->node_count == 0) {
        /* when there is only one node member in the linked list */
        new_node = sk_sleep->preallocated_node;
        no_free = true;
    } else {
        new_node = (struct sk_sleep_node *)malloc(sizeof(struct sk_sleep_node));
        no_free = false;
    }
    *new_node = *n; /* copy node content */
    if (no_free) {
        new_node->flags |= NO_FREE;
    }

    list_add_node(&new_node->list_node, &sk_sleep->head);
    sk_sleep->node_count++;
    pthread_spin_unlock(&sk_sleep->lock);
}

void sk_sleep_remove_node(struct sk_sleep *sk_sleep, struct sk_sleep_node *n)
{
    struct list_node *node, *temp;
    pthread_spin_lock(&sk_sleep->lock);

    list_for_each_node(node, temp, &sk_sleep->head) {
        struct sk_sleep_node *sn = list_entry(node, struct sk_sleep_node, list_node);
        if (sn->epollfd == n->epollfd && sn->events == n->events) {
            n->revents = sn->revents;
            list_del_node(&sn->list_node);
            sk_sleep->node_count--;
            if (sn->flags & READY) {
                n->flags |= READY;
            }
            if (!(sn->flags & NO_FREE)) {
                free(sn);
            }
            pthread_spin_unlock(&sk_sleep->lock);
            return;
        }
    }

    pthread_spin_unlock(&sk_sleep->lock);

    return;
}

void sk_sleep_wakeup_all_by_events(struct sk_sleep *sk_sleep, uint32_t events)
{
    struct list_node *node, *temp;
    pthread_spin_lock(&sk_sleep->lock);
    list_for_each_node(node, temp, &sk_sleep->head) {
        struct sk_sleep_node *n = list_entry(node, struct sk_sleep_node, list_node);
        if (n->events & events) {
            n->flags |= READY;
            n->revents = (n->events & events);
            n->func(n);
        }
    }
    pthread_spin_unlock(&sk_sleep->lock);
}

void sk_sleep_wakeup_node(struct sk_sleep *sk_sleep, struct sk_sleep_node *node)
{
   sk_sleep_set_ready(sk_sleep, node);
   node->func(node);
}

void sk_sleep_set_ready(struct sk_sleep *sk_sleep, struct sk_sleep_node *n)
{
    struct list_node *node, *temp;
    pthread_spin_lock(&sk_sleep->lock);
    list_for_each_node(node, temp, &sk_sleep->head) {
        struct sk_sleep_node *sn = list_entry(node, struct sk_sleep_node, list_node);
        if ((sn->events & n->events) && (sn->epollfd == n->epollfd)) {
            sn->flags |= READY;
            sn->revents = n->revents;
        }
    }
    pthread_spin_unlock(&sk_sleep->lock);
}

