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

#ifndef __GAZELLE_TCP_SOCK_H__
#define __GAZELLE_TCP_SOCK_H__

#include <lwip/hlist.h>
#include <pthread.h>
#include <stdint.h>

#include "common/gazelle_opt.h"

struct gazelle_stack;
struct gazelle_tcp_sock {
    // key
    uint32_t ip;
    uint32_t tid;
    uint16_t port;

    /* instance_reg_tick==instance_cur_tick:instance on; instance_reg_tick!=instance_cur_tick:instance off */
    volatile int32_t *instance_cur_tick;
    int32_t instance_reg_tick;

    // data
    struct gazelle_stack *stack;
    uint32_t tcp_con_num;

    // list node in gazelle_tcp_sock_hbucket
    struct hlist_node tcp_sock_node;
};

struct gazelle_tcp_sock_hbucket {
    uint32_t chain_size;
    struct hlist_head chain;
};

struct gazelle_tcp_sock_htable {
    pthread_mutex_t mlock;
    uint32_t cur_tcp_sock_num;
    uint32_t max_tcp_sock_num;
    struct gazelle_tcp_sock_hbucket array[GAZELLE_MAX_TCP_SOCK_HTABLE_SIZE];
};


void gazelle_set_tcp_sock_htable(struct gazelle_tcp_sock_htable *htable);
struct gazelle_tcp_sock_htable *gazelle_get_tcp_sock_htable(void);
void gazelle_tcp_sock_htable_destroy(void);
struct gazelle_tcp_sock_htable *gazelle_tcp_sock_htable_create(uint32_t max_tcp_sock_num);
struct gazelle_tcp_sock *gazelle_sock_get_by_min_conn(struct gazelle_tcp_sock_htable *tcp_sock_htable,
    uint32_t ip, uint16_t port);
void gazelle_sock_del_by_ipporttid(struct gazelle_tcp_sock_htable *tcp_sock_htable, uint32_t ip, uint16_t port,
    uint32_t tid);
struct gazelle_tcp_sock *gazelle_sock_add_by_ipporttid(struct gazelle_tcp_sock_htable *tcp_sock_htable, uint32_t ip,
    uint16_t port, uint32_t tid);
#endif
