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

#include <stdlib.h>

#include <lwip/hlist.h>

#include "ltran_tcp_conn.h"
#include "ltran_instance.h"
#include "ltran_base.h"
#include "ltran_jhash.h"
#include "gazelle_base_func.h"
#include "ltran_tcp_sock.h"

struct gazelle_tcp_sock_htable *g_tcp_sock_htable = NULL;
struct gazelle_tcp_sock_htable *gazelle_get_tcp_sock_htable(void)
{
    return g_tcp_sock_htable;
}

void gazelle_set_tcp_sock_htable(struct gazelle_tcp_sock_htable *htable)
{
    g_tcp_sock_htable = htable;
}

static struct gazelle_tcp_sock_hbucket *gazelle_hbucket_get_by_ipport(struct gazelle_tcp_sock_htable *tcp_sock_htable,
    uint32_t ip, uint16_t port);

struct gazelle_tcp_sock_htable *gazelle_tcp_sock_htable_create(uint32_t max_tcp_sock_num)
{
    uint32_t i;
    struct gazelle_tcp_sock_htable *tcp_sock_htable = NULL;

    tcp_sock_htable = calloc(1, sizeof(struct gazelle_tcp_sock_htable));
    if (tcp_sock_htable == NULL) {
        return NULL;
    }

    if (pthread_mutex_init(&tcp_sock_htable->mlock, NULL) != 0) {
        free(tcp_sock_htable);
        return NULL;
    }

    for (i = 0; i < GAZELLE_MAX_TCP_SOCK_HTABLE_SIZE; i++) {
        INIT_HLIST_HEAD(&tcp_sock_htable->array[i].chain);
        tcp_sock_htable->array[i].chain_size = 0;
    }
    tcp_sock_htable->cur_tcp_sock_num = 0;
    tcp_sock_htable->max_tcp_sock_num = max_tcp_sock_num;

    return tcp_sock_htable;
}

void gazelle_tcp_sock_htable_destroy(void)
{
    struct gazelle_tcp_sock *tcp_sock = NULL;
    struct hlist_node *node = NULL;
    struct gazelle_tcp_sock_htable *tcp_sock_htable = g_tcp_sock_htable;
    uint32_t i;

    if (tcp_sock_htable == NULL) {
        return;
    }
    (void)pthread_mutex_destroy(&tcp_sock_htable->mlock);

    for (i = 0; i < GAZELLE_MAX_TCP_SOCK_HTABLE_SIZE; i++) {
        node = tcp_sock_htable->array[i].chain.first;
        while (node != NULL) {
            tcp_sock = hlist_entry(node, typeof(*tcp_sock), tcp_sock_node);
            node = node->next;
            hlist_del_init(&tcp_sock->tcp_sock_node);
            free(tcp_sock);
        }
    }

    GAZELLE_FREE(g_tcp_sock_htable);
}

static struct gazelle_tcp_sock_hbucket *gazelle_hbucket_get_by_ipport(struct gazelle_tcp_sock_htable *tcp_sock_htable,
    uint32_t ip, uint16_t port)
{
    uint32_t index = ip_port_hash_fn(ip, port) % GAZELLE_MAX_TCP_SOCK_HTABLE_SIZE;
    return &tcp_sock_htable->array[index];
}

static void recover_sock_info_from_conn(struct gazelle_tcp_sock *tcp_sock)
{
    uint32_t count = 0;
    struct gazelle_tcp_conn *conn = NULL;
    struct hlist_node *node = NULL;
    struct hlist_head *head = NULL;
    struct gazelle_tcp_conn_htable *conn_htable = gazelle_get_tcp_conn_htable();

    for (int32_t i = 0; i < GAZELLE_MAX_CONN_HTABLE_SIZE; i++) {
        head = &conn_htable->array[i].chain;

        hlist_for_each_entry(conn, node, head, conn_node) {
            if ((conn->quintuple.dst_ip.u_addr.ip4.addr != tcp_sock->ip) ||
                (conn->quintuple.dst_port != tcp_sock->port) || (conn->tid != tcp_sock->tid)) {
                continue;
            }
            count++;
            if (conn->sock == NULL) {
                conn->sock = tcp_sock;
            }
        }
    }
    tcp_sock->tcp_con_num = count;
}


struct gazelle_tcp_sock *gazelle_sock_add_by_ipporttid(struct gazelle_tcp_sock_htable *tcp_sock_htable, uint32_t ip,
    uint16_t port, uint32_t tid)
{
    struct gazelle_tcp_sock *tcp_sock = NULL;
    struct hlist_node *node = NULL;
    struct hlist_head *head = NULL;
    struct gazelle_tcp_sock_hbucket *tcp_sock_hbucket = NULL;

    tcp_sock_hbucket = gazelle_hbucket_get_by_ipport(tcp_sock_htable, ip, port);
    if (tcp_sock_hbucket == NULL) {
        return NULL;
    }

    /* avoid reinit */
    head = &tcp_sock_hbucket->chain;
    hlist_for_each_entry(tcp_sock, node, head, tcp_sock_node) {
        if ((tcp_sock->tid == tid) && INSTANCE_IS_ON(tcp_sock)) {
            return tcp_sock;
        }
    }

    if (tcp_sock_htable->cur_tcp_sock_num == tcp_sock_htable->max_tcp_sock_num) {
        return NULL;
    }

    tcp_sock = calloc(1, sizeof(struct gazelle_tcp_sock));
    if (tcp_sock == NULL) {
        return NULL;
    }

    tcp_sock->ip = ip;
    tcp_sock->tid = tid;
    tcp_sock->port = port;
    tcp_sock->instance_reg_tick = INSTANCE_REG_TICK_INIT_VAL;
    tcp_sock->instance_cur_tick = instance_cur_tick_init_val();

    hlist_add_head(&tcp_sock->tcp_sock_node, &tcp_sock_hbucket->chain);
    tcp_sock_htable->cur_tcp_sock_num++;
    tcp_sock_hbucket->chain_size++;
    recover_sock_info_from_conn(tcp_sock);

    return tcp_sock;
}

void gazelle_sock_del_by_ipporttid(struct gazelle_tcp_sock_htable *tcp_sock_htable, uint32_t ip, uint16_t port,
    uint32_t tid)
{
    struct gazelle_tcp_sock *tcp_sock = NULL;
    struct hlist_node *node = NULL;
    struct hlist_head *head = NULL;
    struct gazelle_tcp_sock_hbucket *tcp_sock_hbucket = NULL;

    tcp_sock_hbucket = gazelle_hbucket_get_by_ipport(tcp_sock_htable, ip, port);
    if (tcp_sock_hbucket == NULL) {
        return;
    }

    head = &tcp_sock_hbucket->chain;
    hlist_for_each_entry(tcp_sock, node, head, tcp_sock_node) {
        if (tcp_sock->tid == tid) {
            break;
        }
    }

    if (tcp_sock == NULL) {
        return;
    }

    hlist_del_init(&tcp_sock->tcp_sock_node);
    free(tcp_sock);
    tcp_sock_htable->cur_tcp_sock_num--;
    tcp_sock_hbucket->chain_size--;
}

struct gazelle_tcp_sock *gazelle_sock_get_by_min_conn(struct gazelle_tcp_sock_htable *tcp_sock_htable,
    uint32_t ip, uint16_t port)
{
    struct gazelle_tcp_sock_hbucket *tcp_sock_hbucket = NULL;
    struct gazelle_tcp_sock *tcp_sock_tmp = NULL;
    struct gazelle_tcp_sock *tcp_sock = NULL;
    struct hlist_node *node = NULL;
    struct hlist_head *head = NULL;
    uint32_t min_tcp_con = GAZELLE_STACK_MAX_TCP_CON_NUM;

    tcp_sock_hbucket = gazelle_hbucket_get_by_ipport(tcp_sock_htable, ip, port);
    if (tcp_sock_hbucket == NULL) {
        return NULL;
    }

    head = &tcp_sock_hbucket->chain;

    hlist_for_each_entry(tcp_sock, node, head, tcp_sock_node) {
        if (!INSTANCE_IS_ON(tcp_sock)) {
            continue;
        }
        /* because bucket=hash(ip,port)%array_size tcp_sock maybe have other ip.port */
        if ((tcp_sock->port != port) || (tcp_sock->ip != ip)) {
            continue;
        }
        if (tcp_sock->tcp_con_num < min_tcp_con) {
            tcp_sock_tmp = tcp_sock;
            min_tcp_con = tcp_sock->tcp_con_num;
        }
    }

    return tcp_sock_tmp;
}
