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

#ifndef __GAZELLE_LOCKLESS_QUEUE_H__
#define __GAZELLE_LOCKLESS_QUEUE_H__

#include <stdbool.h>

/* multi-producers single-consumer queue */

typedef struct lockless_queue_node {
    struct lockless_queue_node *volatile next;
} lockless_queue_node;

typedef struct lockless_queue {
    lockless_queue_node  *volatile head __attribute__((__aligned__(64)));
    lockless_queue_node           *tail __attribute__((__aligned__(64)));
    lockless_queue_node            stub __attribute__((__aligned__(64)));
} lockless_queue;


static inline void lockless_queue_node_set_poped(lockless_queue_node *node)
{
    node->next = node;
}

static inline bool lockless_queue_node_is_poped(lockless_queue_node *node)
{
    return node->next == node;
}

static inline bool lockless_queue_node_test_poped(lockless_queue_node *node)
{
    /* 
     * if (node->next == node) {
     *     node->next = NULL;
     *     return 1;
     * } else {
     *     return 0;
     * }
     */
    return !!__atomic_compare_exchange_n(
        (volatile uint64_t *)&node->next, (uint64_t *)&node, (uint64_t)NULL, 
        false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE);
}

static inline void lockless_queue_init(lockless_queue *queue)
{
    queue->head = &queue->stub;
    queue->tail = &queue->stub;
    queue->stub.next = NULL;
}

static inline bool lockless_queue_empty(lockless_queue *queue)
{
    return (queue->head == queue->tail) && (queue->tail == &queue->stub);
}

static inline int32_t lockless_queue_count(lockless_queue *queue)
{
    if (lockless_queue_empty(queue)) {
        return 0;
    }

    lockless_queue_node *tail = queue->tail;
    if (tail == &queue->stub) {
        tail = queue->stub.next;
    }

    int32_t count = 0;
    while (tail) {
        tail = tail->next;
        count++;
    }

    return count;
}

/*
 * tail      head
 *   \_ stub _/
 * 
 * tail    old_head    head
 *   \_ stub _/   node _/
 * 
 * tail                head
 *   \_ stub  ->  node _/
 */
static inline void lockless_queue_mpsc_push(lockless_queue *queue, lockless_queue_node *node)
{
    lockless_queue_node *old_head;

    node->next = NULL;

    old_head = (lockless_queue_node *)__atomic_exchange_n((void **)&queue->head, (void*)node, __ATOMIC_ACQ_REL);

    __atomic_store_n(&old_head->next, node, __ATOMIC_RELEASE);
}

static inline void lockless_queue_mpsc_test_push(lockless_queue *queue, lockless_queue_node *node)
{
    lockless_queue_node *old_head;

    if (!lockless_queue_node_test_poped(node))
        return;

    old_head = (lockless_queue_node *)__atomic_exchange_n((void **)&queue->head, (void*)node, __ATOMIC_ACQ_REL);

    __atomic_store_n(&old_head->next, node, __ATOMIC_RELEASE);
}

static inline lockless_queue_node* lockless_queue_mpsc_pop(lockless_queue* queue)
{
    lockless_queue_node *tail = queue->tail;
    lockless_queue_node *next = tail->next;
    lockless_queue_node *head;

    /*
     * step1. dequeue stub.
     * tail                          head
     *   \_ stub  ->  node  ->  node _/
     */
    if (tail == &queue->stub) {
        if (next == NULL) {
            return NULL;
        }
        queue->tail = next;
        tail = next;
        next = next->next;
    }

    /*
     * step2. dequeue tail.
     * tail      next-\    head
     *   \_ node  ->  node _/
     */
    if (next) {
        queue->tail = next;
        lockless_queue_node_set_poped(tail);
        return tail;
    }

    /*
     * step3. enqueue ing.
     * tail    old_head    head
     *   \_ node _/   node _/
     */
    head = queue->head;
    if (tail != head) {
        return NULL;
    }

    /*
     * step4. only one node, enqueue stub and dequeue node.
     * tail      head
     *   \_ node _/
     */
    lockless_queue_mpsc_push(queue, &queue->stub);

    next = tail->next;
    if (next) {
        queue->tail = next;
        lockless_queue_node_set_poped(tail);
        return tail;
    }

    return NULL;
}

#endif
