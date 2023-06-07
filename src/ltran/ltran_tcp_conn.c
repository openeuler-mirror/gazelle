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

#include <securec.h>

#include <rte_malloc.h>

#include "ltran_jhash.h"
#include "ltran_instance.h"
#include "ltran_tcp_conn.h"

struct gazelle_tcp_conn_htable *g_tcp_conn_htable = NULL;
struct gazelle_tcp_conn_htable *gazelle_get_tcp_conn_htable(void)
{
    return g_tcp_conn_htable;
}

void gazelle_set_tcp_conn_htable(struct gazelle_tcp_conn_htable *htable)
{
    g_tcp_conn_htable = htable;
}

struct gazelle_tcp_conn_htable *gazelle_tcp_conn_htable_create(uint32_t max_conn_num)
{
    struct gazelle_tcp_conn_htable *conn_htable = NULL;
    uint32_t i;

    conn_htable = rte_malloc(NULL, sizeof(struct gazelle_tcp_conn_htable), RTE_CACHE_LINE_SIZE);
    if (conn_htable == NULL) {
        return NULL;
    }

    for (i = 0; i < GAZELLE_MAX_CONN_HTABLE_SIZE; i++) {
        INIT_HLIST_HEAD(&conn_htable->array[i].chain);
        conn_htable->array[i].chain_size = 0;
    }
    conn_htable->cur_conn_num = 0;
    conn_htable->max_conn_num = max_conn_num;

    return conn_htable;
}

void gazelle_tcp_conn_htable_destroy(void)
{
    struct hlist_node *node = NULL;
    struct gazelle_tcp_conn *conn = NULL;
    uint32_t i;
    struct gazelle_tcp_conn_htable *conn_htable = g_tcp_conn_htable;

    if (conn_htable == NULL) {
        return;
    }

    for (i = 0; i < GAZELLE_MAX_CONN_HTABLE_SIZE; i++) {
        node = conn_htable->array[i].chain.first;
        while (node != NULL) {
            conn = hlist_entry(node, typeof(*conn), conn_node);
            node = node->next;
            hlist_del_init(&conn->conn_node);
            rte_free(conn);
        }
    }

    g_tcp_conn_htable = NULL;
    rte_free(conn_htable);
}

struct gazelle_tcp_conn_hbucket *gazelle_conn_hbucket_get(struct gazelle_tcp_conn_htable *conn_htable,
    const struct gazelle_quintuple *quintuple)
{
    uint32_t index;
    index = tuple_hash_fn(quintuple->src_ip, quintuple->src_port, quintuple->dst_ip, quintuple->dst_port) %
                           GAZELLE_MAX_CONN_HTABLE_SIZE;
    return &conn_htable->array[index];
}

struct gazelle_tcp_conn *gazelle_conn_add_by_quintuple(struct gazelle_tcp_conn_htable *conn_htable,
    struct gazelle_quintuple *quintuple)
{
    int32_t ret;
    struct gazelle_tcp_conn_hbucket *conn_hbucket = NULL;
    struct gazelle_tcp_conn *conn = NULL;

    /* avoid reinit */
    conn = gazelle_conn_get_by_quintuple(conn_htable, quintuple);
    if (conn != NULL) {
        return conn;
    }

    if (conn_htable->cur_conn_num == conn_htable->max_conn_num) {
        return NULL;
    }

    conn_hbucket = gazelle_conn_hbucket_get(conn_htable, quintuple);
    if (conn_hbucket == NULL) {
        return NULL;
    }

    conn = rte_malloc(NULL, sizeof(struct gazelle_tcp_conn), RTE_CACHE_LINE_SIZE);
    if (conn == NULL) {
        return NULL;
    }

    ret = memcpy_s(&conn->quintuple, sizeof(struct gazelle_quintuple), quintuple, sizeof(*quintuple));
    if (ret != 0) {
        rte_free(conn);
        return NULL;
    }

    conn->instance_reg_tick = INSTANCE_REG_TICK_INIT_VAL;
    conn->instance_cur_tick = instance_cur_tick_init_val();
    conn->sock = NULL;

    hlist_add_head(&conn->conn_node, &conn_hbucket->chain);
    conn_htable->cur_conn_num++;
    conn_hbucket->chain_size++;

    return conn;
}

struct gazelle_tcp_conn *gazelle_conn_get_by_quintuple(struct gazelle_tcp_conn_htable *conn_htable,
    struct gazelle_quintuple *quintuple)
{
    struct gazelle_tcp_conn *conn = NULL;
    struct gazelle_tcp_conn_hbucket *conn_hbucket = NULL;
    struct hlist_node *node = NULL;
    struct hlist_head *head = NULL;

    conn_hbucket = gazelle_conn_hbucket_get(conn_htable, quintuple);
    if (conn_hbucket == NULL) {
        return NULL;
    }

    head = &conn_hbucket->chain;
    hlist_for_each_entry(conn, node, head, conn_node) {
        if (!INSTANCE_IS_ON(conn)) {
            continue;
        }
        if (memcmp(&conn->quintuple, quintuple, sizeof(struct gazelle_quintuple)) == 0) {
            return conn;
        }
    }
    return NULL;
}

void gazelle_conn_del_by_quintuple(struct gazelle_tcp_conn_htable *conn_htable, struct gazelle_quintuple *quintuple)
{
    struct gazelle_tcp_conn *conn = NULL;
    struct gazelle_tcp_conn_hbucket *conn_hbucket = NULL;
    struct hlist_node *node = NULL;
    struct hlist_head *head = NULL;

    conn_hbucket = gazelle_conn_hbucket_get(conn_htable, quintuple);
    if (conn_hbucket == NULL) {
        return;
    }

    head = &conn_hbucket->chain;
    hlist_for_each_entry(conn, node, head, conn_node) {
        if (memcmp(&conn->quintuple, quintuple, sizeof(struct gazelle_quintuple)) == 0) {
            break;
        }
    }

    if (conn == NULL) {
        return;
    }

    hlist_del_init(&conn->conn_node);
    rte_free(conn);
    conn_htable->cur_conn_num--;
    conn_hbucket->chain_size--;
}

