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
#include <sys/time.h>
#include <pthread.h>

#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_cycles.h>
#include <lwip/lwipgz_hlist.h>

#include "ltran_param.h"
#include "ltran_log.h"
#include "ltran_tcp_sock.h"
#include "ltran_tcp_conn.h"
#include "ltran_instance.h"
#include "ltran_timer.h"

static uint64_t g_cycles_per_us = 0;

uint64_t get_current_time(void)
{
    if (g_cycles_per_us == 0) {
        return 0;
    }

    return (rte_rdtsc() / g_cycles_per_us);
}

void calibrate_time(void)
{
    g_cycles_per_us = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S;
}

void gazelle_detect_sock_logout(struct gazelle_tcp_sock_htable *tcp_sock_htable)
{
    uint32_t i;
    struct gazelle_tcp_sock *tcp_sock = NULL;
    struct hlist_node *node = NULL;

    if (tcp_sock_htable == NULL) {
        return;
    }

    if (pthread_mutex_trylock(&tcp_sock_htable->mlock) != 0) {
        LTRAN_ERR("lock failed, errno %d.\n", errno);
        return;
    }

    for (i = 0; i < GAZELLE_MAX_TCP_SOCK_HTABLE_SIZE; i++) {
        node = tcp_sock_htable->array[i].chain.first;
        while (node != NULL) {
            tcp_sock = hlist_entry(node, typeof(*tcp_sock), tcp_sock_node);
            node = node->next;
            if (!INSTANCE_IS_ON(tcp_sock)) {
                hlist_del_node(&tcp_sock->tcp_sock_node);
                tcp_sock_htable->cur_tcp_sock_num--;
                tcp_sock_htable->array[i].chain_size--;
                LTRAN_DEBUG("delete the tcp sock htable: tid %u ip %u port %u\n",
                    tcp_sock->tid, tcp_sock->ip, (uint32_t)ntohs(tcp_sock->port));
                free(tcp_sock);
            }
        }
    }

    if (pthread_mutex_unlock(&tcp_sock_htable->mlock) != 0) {
        LTRAN_WARN("read tcp_sock_htable: unlock failed, errno %d.\n", errno);
    }
}
void gazelle_detect_conn_logout(struct gazelle_tcp_conn_htable *conn_htable)
{
    struct gazelle_tcp_sock_htable *sock_htable = gazelle_get_tcp_sock_htable();
    struct gazelle_tcp_conn *conn = NULL;
    struct hlist_node *node = NULL;
    uint32_t i;

    if (conn_htable == NULL) {
        return;
    }

    if (pthread_mutex_trylock(&sock_htable->mlock) != 0) {
        LTRAN_ERR("lock failed, errno %d\n", errno);
        return;
    }

    for (i = 0; i < GAZELLE_MAX_CONN_HTABLE_SIZE; i++) {
        node = conn_htable->array[i].chain.first;
        while (node != NULL) {
            conn = hlist_entry(node, typeof(*conn), conn_node);
            node = node->next;
            if (!INSTANCE_IS_ON(conn)) {
                hlist_del_node(&conn->conn_node);
                conn_htable->cur_conn_num--;
                conn_htable->array[i].chain_size--;
                LTRAN_DEBUG("delete the tcp conn htable: tid %u quintuple[%u %u %u %u %u]\n",
                    conn->tid, conn->quintuple.protocol,
                    conn->quintuple.src_ip.u_addr.ip4.addr, (uint32_t)ntohs(conn->quintuple.src_port),
                    conn->quintuple.dst_ip.u_addr.ip4.addr, (uint32_t)ntohs(conn->quintuple.dst_port));
                rte_free(conn);
            }
        }
    }

    if (pthread_mutex_unlock(&sock_htable->mlock) != 0) {
        LTRAN_WARN("unlock failed, errno %d.\n", errno);
    }
}

void gazelle_delete_aging_conn(struct gazelle_tcp_conn_htable *conn_htable)
{
    struct gazelle_tcp_sock_htable *sock_htable = gazelle_get_tcp_sock_htable();
    struct gazelle_tcp_conn *conn = NULL;
    struct hlist_node *node = NULL;
    uint32_t i;

    if (conn_htable == NULL) {
        return;
    }

    if (pthread_mutex_trylock(&sock_htable->mlock) != 0) {
        LTRAN_ERR("lock failed, errno %d\n", errno);
        return;
    }

    for (i = 0; i < GAZELLE_MAX_CONN_HTABLE_SIZE; i++) {
        node = conn_htable->array[i].chain.first;
        while (node != NULL) {
            conn = hlist_entry(node, typeof(*conn), conn_node);
            node = node->next;
            if (conn->conn_timeout < 0) {
                continue;
            }

            conn->conn_timeout--;
            if (conn->conn_timeout > 0) {
                continue;
            }

            hlist_del_node(&conn->conn_node);
            conn_htable->cur_conn_num--;
            conn_htable->array[i].chain_size--;
            if (conn->sock) {
                conn->sock->tcp_con_num--;
            }
            rte_free(conn);
        }
    }

    if (pthread_mutex_unlock(&sock_htable->mlock) != 0) {
        LTRAN_WARN("unlock failed, errno %d.\n", errno);
    }
}
