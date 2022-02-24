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

#ifndef __GAZELLE_STACK_H__
#define __GAZELLE_STACK_H__

#include <lwip/hlist.h>

#include "ltran_jhash.h"
#include "ltran_stat.h"

struct gazelle_stack {
    // key
    int32_t index;
    uint32_t tid;

    /* instance_reg_tick==instance_cur_tick:instance on; instance_reg_tick!=instance_cur_tick:instance off */
    volatile int32_t *instance_cur_tick;
    int32_t instance_reg_tick;

    // forward
    struct rte_ring *reg_ring;
    struct rte_ring *tx_ring;
    struct rte_ring *rx_ring;
    struct rte_mbuf *pkt_buf[PACKET_READ_SIZE];
    uint32_t pkt_cnt;
    struct rte_mbuf *backup_pkt_buf[PACKET_READ_SIZE * BACKUP_SIZE_FACTOR];
    uint32_t backup_pkt_cnt;
    uint32_t backup_start;
    struct hlist_node stack_node;
    struct gazelle_stat_lstack_total stack_stats;
};

struct gazelle_stack_hbucket {
    uint32_t chain_size;
    struct hlist_head chain;
};

struct gazelle_stack_htable {
    uint32_t cur_stack_num;
    uint32_t max_stack_num;
    struct gazelle_stack_hbucket array[GAZELLE_MAX_STACK_HTABLE_SIZE];
};

void gazelle_set_stack_htable(struct gazelle_stack_htable *htable);
struct gazelle_stack_htable *gazelle_get_stack_htable(void);

void gazelle_stack_htable_destroy(void);
struct gazelle_stack_htable *gazelle_stack_htable_create(uint32_t max_stack_num);

const struct gazelle_stack *gazelle_stack_get_by_tid(const struct gazelle_stack_htable *stack_htable, uint32_t tid);

void gazelle_stack_del_by_tid(struct gazelle_stack_htable *stack_htable, uint32_t tid);
struct gazelle_stack *gazelle_stack_add_by_tid(struct gazelle_stack_htable *stack_htable, uint32_t tid);

#endif

