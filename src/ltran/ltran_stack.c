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

#include <malloc.h>
#include <rte_mbuf.h>

#include "ltran_instance.h"
#include "ltran_log.h"
#include "ltran_jhash.h"
#include "gazelle_base_func.h"
#include "ltran_stack.h"

struct gazelle_stack_htable *g_stack_htable = NULL;
struct gazelle_stack_htable *gazelle_get_stack_htable(void)
{
    return g_stack_htable;
}

void gazelle_set_stack_htable(struct gazelle_stack_htable *htable)
{
    g_stack_htable = htable;
}

struct gazelle_stack_hbucket *gazelle_stack_hbucket_get_by_tid(struct gazelle_stack_htable *stack_htable, uint32_t tid);

struct gazelle_stack_htable *gazelle_stack_htable_create(uint32_t max_stack_num)
{
    struct gazelle_stack_htable *stack_htable;
    uint32_t i;

    stack_htable = calloc(1, sizeof(struct gazelle_stack_htable));
    if (stack_htable == NULL) {
        return NULL;
    }

    for (i = 0; i < GAZELLE_MAX_STACK_HTABLE_SIZE; i++) {
        INIT_HLIST_HEAD(&stack_htable->array[i].chain);
        stack_htable->array[i].chain_size = 0;
    }
    stack_htable->cur_stack_num = 0;
    stack_htable->max_stack_num = max_stack_num;

    return stack_htable;
}

void gazelle_stack_htable_destroy(void)
{
    struct hlist_node *node = NULL;
    struct gazelle_stack *stack = NULL;
    uint32_t i;
    struct gazelle_stack_htable *stack_htable = g_stack_htable;

    if (stack_htable == NULL) {
        return;
    }

    for (i = 0; i < GAZELLE_MAX_STACK_HTABLE_SIZE; i++) {
        node = stack_htable->array[i].chain.first;
        while (node != NULL) {
            stack = hlist_entry(node, typeof(*stack), stack_node);
            node = node->next;
            hlist_del_init(&stack->stack_node);
            free(stack);
        }
    }

    GAZELLE_FREE(g_stack_htable);
}

struct gazelle_stack_hbucket *gazelle_stack_hbucket_get_by_tid(struct gazelle_stack_htable *stack_htable, uint32_t tid)
{
    uint32_t index;
    index = tid_hash_fn(tid) % GAZELLE_MAX_STACK_HTABLE_SIZE;
    return &stack_htable->array[index];
}

const struct gazelle_stack *gazelle_stack_get_by_tid(const struct gazelle_stack_htable *stack_htable, uint32_t tid)
{
    uint32_t index;
    const struct gazelle_stack *stack = NULL;
    const struct gazelle_stack_hbucket *stack_hbucket = NULL;
    struct hlist_node *node = NULL;
    const struct hlist_head *head = NULL;

    index = tid_hash_fn(tid) % GAZELLE_MAX_STACK_HTABLE_SIZE;
    stack_hbucket = &stack_htable->array[index];
    if (stack_hbucket == NULL) {
        return NULL;
    }

    head = &stack_hbucket->chain;
    hlist_for_each_entry(stack, node, head, stack_node) {
        if ((stack->tid == tid) && INSTANCE_IS_ON(stack)) {
            return stack;
        }
    }

    return NULL;
}

struct gazelle_stack *gazelle_stack_add_by_tid(struct gazelle_stack_htable *stack_htable, uint32_t tid)
{
    struct gazelle_stack_hbucket *stack_hbucket = NULL;
    struct gazelle_stack *stack = NULL;

    if (stack_htable->cur_stack_num == stack_htable->max_stack_num) {
        LTRAN_ERR("cur_stack_num=%u is max num.\n", stack_htable->cur_stack_num);
        return NULL;
    }

    stack_hbucket = gazelle_stack_hbucket_get_by_tid(stack_htable, tid);
    if (stack_hbucket == NULL) {
        LTRAN_ERR("tid=%u stack_hbucket is null\n", tid);
        return NULL;
    }

    stack = calloc(1, sizeof(struct gazelle_stack));
    if (stack == NULL) {
        LTRAN_ERR("malloc fail.\n");
        return NULL;
    }

    stack->index = -1;
    stack->tid = tid;
    stack->instance_reg_tick = INSTANCE_REG_TICK_INIT_VAL;
    stack->instance_cur_tick = instance_cur_tick_init_val();

    hlist_add_head(&stack->stack_node, &stack_hbucket->chain);
    stack_htable->cur_stack_num++;
    stack_hbucket->chain_size++;

    return stack;
}

void gazelle_stack_del_by_tid(struct gazelle_stack_htable *stack_htable, uint32_t tid)
{
    struct gazelle_stack *stack = NULL;
    struct gazelle_stack_hbucket *stack_hbucket = NULL;
    struct hlist_node *node = NULL;
    struct hlist_head *head = NULL;
    uint32_t backup_size;
    uint32_t index;
    uint32_t i;

    stack_hbucket = gazelle_stack_hbucket_get_by_tid(stack_htable, tid);
    if (stack_hbucket == NULL) {
        return;
    }

    head = &stack_hbucket->chain;
    hlist_for_each_entry(stack, node, head, stack_node) {
        if (stack->tid == tid) {
            break;
        }
    }

    if (stack == NULL) {
        return;
    }

    backup_size = PACKET_READ_SIZE * BACKUP_SIZE_FACTOR;
    /* free mubfs used by lstack */
    for (i = 0; i < stack->pkt_cnt; i++) {
        if (stack->pkt_buf[i] != NULL) {
            rte_pktmbuf_free(stack->pkt_buf[i]);
        }
    }
    for (i = 0; i < stack->backup_pkt_cnt; i++) {
        index = (stack->backup_start + i) % backup_size;
        if (stack->backup_pkt_buf[index] != NULL) {
            rte_pktmbuf_free(stack->backup_pkt_buf[index]);
        }
    }

    hlist_del_init(&stack->stack_node);
    stack_htable->cur_stack_num--;
    stack_hbucket->chain_size--;

    free(stack);
}

