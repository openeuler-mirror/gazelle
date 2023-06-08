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

#ifndef __GAZELLE_TCP_CONN_H__
#define __GAZELLE_TCP_CONN_H__

#include <lwip/hlist.h>
#include <stdint.h>
#include <stdbool.h>
#include <lwip/reg_sock.h>

#include "gazelle_opt.h"

struct gazelle_tcp_conn {
    uint32_t tid;
    struct gazelle_tcp_sock *sock;
    struct gazelle_stack *stack;
    struct gazelle_quintuple quintuple;

    /* instance_reg_tick==instance_cur_tick:instance on; instance_reg_tick!=instance_cur_tick:instance off */
    volatile int32_t *instance_cur_tick;
    int32_t instance_reg_tick;

    // tcp_handle create conn when pkt match socktable. when pkt don't accept and timout expire, del conn.
    // ltran_tcp_conn.h define interval and times
    int16_t conn_timeout;

    struct hlist_node conn_node;
};

struct gazelle_tcp_conn_hbucket {
    uint32_t chain_size;
    struct hlist_head chain;
};

struct gazelle_tcp_conn_htable {
    uint32_t cur_conn_num;
    uint32_t max_conn_num;
    struct gazelle_tcp_conn_hbucket array[GAZELLE_MAX_CONN_HTABLE_SIZE];
};

struct gazelle_tcp_conn_htable *gazelle_get_tcp_conn_htable(void);
void gazelle_set_tcp_conn_htable(struct gazelle_tcp_conn_htable *htable);


struct gazelle_tcp_conn_htable *gazelle_tcp_conn_htable_create(uint32_t max_conn_num);
void gazelle_tcp_conn_htable_destroy(void);

struct gazelle_tcp_conn_hbucket *gazelle_conn_hbucket_get(struct gazelle_tcp_conn_htable *conn_htable,
    const struct gazelle_quintuple *quintuple);
struct gazelle_tcp_conn *gazelle_conn_add_by_quintuple(struct gazelle_tcp_conn_htable *conn_htable,
    struct gazelle_quintuple *quintuple);
struct gazelle_tcp_conn *gazelle_conn_get_by_quintuple(struct gazelle_tcp_conn_htable *conn_htable,
    struct gazelle_quintuple *quintuple);

void gazelle_conn_del_by_quintuple(struct gazelle_tcp_conn_htable *conn_htable, struct gazelle_quintuple *quintuple);

#endif
