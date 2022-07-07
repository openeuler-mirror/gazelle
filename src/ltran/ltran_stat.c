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

#include "ltran_stat.h"

#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <rte_ring.h>
#include <netinet/in.h>

#include "ltran_tcp_sock.h"
#include "ltran_tcp_conn.h"
#include "ltran_instance.h"
#include "ltran_log.h"
#include "gazelle_dfx_msg.h"
#include "ltran_timer.h"
#include "ltran_ethdev.h"
#include "dpdk_common.h"
#include "ltran_forward.h"

static uint64_t g_start_time_stamp = 0;
static int32_t g_start_latency = GAZELLE_OFF;
volatile int32_t g_ltran_stop_flag = GAZELLE_FALSE;
static struct statistics g_statistics;

uint64_t get_start_time_stamp(void)
{
    return g_start_time_stamp;
}

void set_start_latency_flag(int32_t flag)
{
    struct gazelle_instance_mgr *instance_mgr = get_instance_mgr();
    struct gazelle_stack** stack_array = NULL;
    struct gazelle_instance *instance = NULL;
    uint32_t i, j;

    if (flag == g_start_latency) {
        return;
    }

    if (flag == GAZELLE_ON) {
        for (i = 0; i < instance_mgr->max_instance_num; i++) {
            instance = instance_mgr->instances[i];
            if (instance == NULL) {
                continue;
            }

            stack_array = instance->stack_array;
            for (j = 0; j < instance->stack_cnt; j++) {
                stack_array[j]->stack_stats.latency_min = ~((uint64_t)0);
                stack_array[j]->stack_stats.latency_max = 0;
                stack_array[j]->stack_stats.latency_pkts = 0;
                stack_array[j]->stack_stats.latency_total = 0;
            }
        }
    }

    g_start_latency = flag;
    g_start_time_stamp = get_current_time();
}

int32_t get_start_latency_flag(void)
{
    return g_start_latency;
}

void set_ltran_stop_flag(int32_t flag)
{
    g_ltran_stop_flag = flag;
    return;
}

int32_t get_ltran_stop_flag(void)
{
    return g_ltran_stop_flag;
}

struct statistics* get_statistics(void)
{
    return &g_statistics;
}

static int32_t gazelle_filling_ltran_stat_total(struct gazelle_stat_ltran_total *stat,
    const struct statistics *total_stat, uint32_t port_num)
{
    if ((stat == NULL) || (total_stat == NULL)) {
        return GAZELLE_ERR;
    }

    (void)memset_s(stat, sizeof(struct gazelle_stat_ltran_total), 0, sizeof(struct gazelle_stat_ltran_total));

    for (uint32_t i = 0; i < port_num; i++) {
        stat->port_list[i].tx = total_stat->port_stats[i].tx;
        stat->port_list[i].rx = total_stat->port_stats[i].rx;
        stat->port_list[i].tx_bytes = total_stat->port_stats[i].tx_bytes;
        stat->port_list[i].rx_bytes = total_stat->port_stats[i].rx_bytes;
        stat->port_list[i].kni_pkt = total_stat->port_stats[i].kni_pkt;
        stat->port_list[i].tx_drop = total_stat->port_stats[i].tx_drop;
        stat->port_list[i].arp_pkt = total_stat->port_stats[i].arp_pkt;
        stat->port_list[i].icmp_pkt = total_stat->port_stats[i].icmp_pkt;
        stat->port_list[i].loglevel = rte_log_get_level(RTE_LOGTYPE_LTRAN);
        stat->port_list[i].tcp_pkt = total_stat->port_stats[i].tcp_pkt;

        for (int32_t j = 0; j <= GAZELLE_PACKET_READ_SIZE; j++) {
            stat->port_list[i].rx_iter_arr[j] = total_stat->port_stats[i].rx_iter_arr[j];
        }
    }

    stat->port_num = port_num;
    return GAZELLE_OK;
}

static int32_t gazelle_filling_ltran_stat_client(struct gazelle_stat_ltran_client *stat,
    const struct gazelle_instance_mgr *total_stat)
{
    struct gazelle_instance *instance = NULL;

    uint16_t* bond_port = get_bond_port();
    if ((stat == NULL) || (total_stat == NULL)) {
        return GAZELLE_ERR;
    }

    (void)memset_s(stat, sizeof(struct gazelle_stat_ltran_client), 0, sizeof(struct gazelle_stat_ltran_client));

    int32_t bond_index;
    for (int32_t i = 0; i < GAZELLE_MAX_CLIENT; i++) {
        instance = total_stat->instances[i];
        if (instance != NULL) {
            stat->client_info[stat->client_num].id = i;
            stat->client_info[stat->client_num].ip.s_addr = instance->ip_addr.s_addr;
            stat->client_info[stat->client_num].pid = instance->pid;
            stat->client_info[stat->client_num].bond_port = GAZELLE_BOND_PORT_DEFAULT;
            stat->client_info[stat->client_num].sockfd = instance->sockfd;
            stat->client_info[stat->client_num].stack_cnt = instance->stack_cnt;
            switch (instance->reg_state) {
                case RQT_REG_PROC_MEM:
                    /* do not break */
                case RQT_REG_PROC_ATT:
                    stat->client_info[stat->client_num].state = GAZELLE_CLIENT_STATE_CONNECTING;
                    break;
                case RQT_REG_THRD_RING:
                    bond_index = instance_match_bond_port(&instance->ethdev);
                    stat->client_info[stat->client_num].bond_port = bond_port[bond_index];
                    stat->client_info[stat->client_num].state = GAZELLE_CLIENT_STATE_NORMAL;
                    break;
                default:
                    stat->client_info[stat->client_num].state = GAZELLE_CLIENT_STATE_RECONNECTING;
            }
            stat->client_num++;
        }
    }

    return GAZELLE_OK;
}

static int32_t gazelle_filling_lstack_stat_total(struct gazelle_stat_lstack_total *stat,
    const struct gazelle_stack *stack)
{
    if ((stat == NULL) || (stack == NULL)) {
        return GAZELLE_ERR;
    }

    (void)memset_s(stat, sizeof(struct gazelle_stat_lstack_total), 0, sizeof(struct gazelle_stat_lstack_total));

    stat->tid = stack->tid;
    stat->index = (uint32_t)stack->index;
    stat->rx = stack->stack_stats.rx;
    stat->rx_drop = stack->stack_stats.rx_drop;
    stat->rx_err = stack->stack_stats.rx_err;
    stat->tx = stack->stack_stats.tx;
    stat->tx_backup = stack->stack_stats.tx_backup;
    stat->tx_err = stack->stack_stats.tx_err;
    stat->rx_bytes = stack->stack_stats.rx_bytes;
    stat->tx_bytes = stack->stack_stats.tx_bytes;
    stat->tx_drop = stack->stack_stats.tx_drop;
    stat->latency_min = stack->stack_stats.latency_min;
    stat->latency_max = stack->stack_stats.latency_max;
    stat->backup_mbuf_cnt = stack->backup_pkt_cnt;
    stat->latency_pkts = stack->stack_stats.latency_pkts;
    stat->latency_total = stack->stack_stats.latency_total;
    stat->reg_ring_cnt = rte_ring_cn_count(stack->reg_ring);
    stat->rx_ring_cnt = gazelle_ring_readover_count(stack->rx_ring);
    stat->tx_ring_cnt = gazelle_ring_readable_count(stack->tx_ring);

    return GAZELLE_OK;
}

void handle_resp_ltran_total(int32_t fd)
{
    int32_t ret;
    uint32_t bond_num = get_bond_num();
    struct gazelle_stat_ltran_total stat;
    ret = gazelle_filling_ltran_stat_total(&stat, get_statistics(), bond_num);
    if (ret != GAZELLE_OK) {
        LTRAN_ERR("filling ltran stat total failed. ret=%d\n", ret);
        return;
    }

    (void)write_specied_len(fd, (char *)&stat, sizeof(struct gazelle_stat_ltran_total));
}

void handle_resp_ltran_sock(int32_t fd)
{
    struct gazelle_tcp_sock *tcp_sock = NULL;
    struct hlist_node *node = NULL;
    struct hlist_head *head = NULL;
    struct gazelle_tcp_sock_htable *sock_htable = gazelle_get_tcp_sock_htable();
    struct gazelle_stat_forward_table forward_table = {0};
    int32_t index = 0;

    if (pthread_mutex_lock(&sock_htable->mlock) != 0) {
        LTRAN_ERR("read tcp_sock_htable: lock failed, errno %d\n", errno);
        return;
    }

    for (int32_t i = 0; i < GAZELLE_MAX_TCP_SOCK_HTABLE_SIZE; i++) {
        head = &sock_htable->array[i].chain;
        hlist_for_each_entry(tcp_sock, node, head, tcp_sock_node) {
            if (index < GAZELLE_LSTACK_MAX_CONN) {
                forward_table.conn_list[index].dst_ip = tcp_sock->ip;
                forward_table.conn_list[index].tid = tcp_sock->tid;
                forward_table.conn_list[index].conn_num = tcp_sock->tcp_con_num;
                forward_table.conn_list[index].dst_port = ntohs(tcp_sock->port);
            }
            /* show detail info in range and show total num */
            index++;
        }
    }
    forward_table.conn_num = (uint32_t)index;

    if (pthread_mutex_unlock(&sock_htable->mlock) != 0) {
        LTRAN_WARN("read tcp_sock_htable: unlock failed, errno %d.\n", errno);
    }
    (void)write_specied_len(fd, (char *)&forward_table, sizeof(struct gazelle_stat_forward_table));
}

void handle_resp_ltran_conn(int32_t fd)
{
    struct hlist_node *node = NULL;
    struct hlist_head *head = NULL;
    struct gazelle_tcp_conn_htable *conn_htable = gazelle_get_tcp_conn_htable();
    struct gazelle_tcp_sock_htable *sock_htable = gazelle_get_tcp_sock_htable();
    struct gazelle_stat_forward_table forward_table = {0};
    struct gazelle_tcp_conn *conn = NULL;
    int32_t index = 0;

    if (pthread_mutex_lock(&sock_htable->mlock) != 0) {
        LTRAN_ERR("read tcp_conn_htable: lock failed, errno %d.\n", errno);
        return;
    }

    for (int32_t i = 0; i < GAZELLE_MAX_CONN_HTABLE_SIZE; i++) {
        head = &conn_htable->array[i].chain;
        hlist_for_each_entry(conn, node, head, conn_node) {
            if (index < GAZELLE_LSTACK_MAX_CONN) {
                forward_table.conn_list[index].protocol = conn->quintuple.protocol;
                forward_table.conn_list[index].tid = conn->tid;
                forward_table.conn_list[index].dst_ip = conn->quintuple.dst_ip;
                forward_table.conn_list[index].src_ip = conn->quintuple.src_ip;
                forward_table.conn_list[index].dst_port = ntohs(conn->quintuple.dst_port);
                forward_table.conn_list[index].src_port = ntohs(conn->quintuple.src_port);
            }
            /* show detail info in range and show total num */
            index++;
        }
    }
    forward_table.conn_num = (uint32_t)index;

    if (pthread_mutex_unlock(&sock_htable->mlock) != 0) {
        LTRAN_WARN("read tcp_conn_htable: unlock failed, errno %d.\n", errno);
    }
    (void)write_specied_len(fd, (char *)&forward_table, sizeof(struct gazelle_stat_forward_table));
}

void handle_resp_ltran_client(int32_t fd)
{
    int32_t ret;
    struct gazelle_stat_ltran_client stat;
    ret = gazelle_filling_ltran_stat_client(&stat, get_instance_mgr());
    if (ret != GAZELLE_OK) {
        LTRAN_ERR("filling ltran stat total failed. ret=%d\n", ret);
        return;
    }

    (void)write_specied_len(fd, (char *)&stat, sizeof(struct gazelle_stat_ltran_client));
}

void set_ltran_log_level(struct gazelle_stat_msg_request *msg)
{
    msg->data.log_level[GAZELLE_LOG_LEVEL_MAX - 1] = '\0';
    if (strcmp(msg->data.log_level, "error") == 0) {
        rte_log_set_level(RTE_LOGTYPE_LTRAN, RTE_LOG_ERR);
        rte_log_set_global_level(RTE_LOG_ERR);
        LTRAN_ERR("ltran log set to error level!\n");
        return;
    }

    if (strcmp(msg->data.log_level, "info") == 0) {
        rte_log_set_level(RTE_LOGTYPE_LTRAN, RTE_LOG_INFO);
        rte_log_set_global_level(RTE_LOG_INFO);
        LTRAN_INFO("ltran log set to info level!\n");
        return;
    }

    if (strcmp(msg->data.log_level, "debug") == 0) {
        rte_log_set_level(RTE_LOGTYPE_LTRAN, RTE_LOG_DEBUG);
        rte_log_set_global_level(RTE_LOG_DEBUG);
        LTRAN_DEBUG("ltran log set to debug level!\n");
        return;
    }
}

void handle_resp_ltran_latency(int32_t fd)
{
    struct gazelle_stat_lstack_total stat;
    struct gazelle_instance *instance = NULL;
    struct gazelle_instance_mgr *instance_mgr = get_instance_mgr();
    int32_t ret;
    uint32_t i, j;

    for (i = 0; i < instance_mgr->max_instance_num; i++) {
        instance = instance_mgr->instances[i];
        if (instance == NULL) {
            continue;
        }

        if (!INSTANCE_IS_ON(instance)) {
            return;
        }

        for (j = 0; j < instance->stack_cnt; j++) {
            ret = gazelle_filling_lstack_stat_total(&stat, instance->stack_array[j]);
            if (ret != GAZELLE_OK) {
                LTRAN_ERR("gazelle_filling_lstack_stat_total failed. ret=%d\n", ret);
                return;
            }
            (void)write_specied_len(fd, (char *)&(instance->ip_addr), sizeof(instance->ip_addr));
            (void)write_specied_len(fd, (char *)&stat, sizeof(struct gazelle_stat_lstack_total));
        }
    }

    // just to send stat.eof the rest is useless
    stat.eof = 1;
    (void)write_specied_len(fd, (char *)&stat, sizeof(instance->ip_addr));
    (void)write_specied_len(fd, (char *)&stat, sizeof(struct gazelle_stat_lstack_total));
}

void handle_resp_lstack_total(const struct gazelle_stat_msg_request *msg, int32_t fd)
{
    struct gazelle_stat_lstack_total stat = {0};
    struct gazelle_instance *instance = NULL;
    int32_t ret;

    instance = gazelle_instance_map_by_ip(get_instance_mgr(), msg->ip.s_addr);
    if (instance == NULL) {
        LTRAN_ERR("Can't find the client ip to check\n");
        return;
    }

    if (!INSTANCE_IS_ON(instance)) {
        return;
    }

    for (uint32_t i = 0; i < instance->stack_cnt; i++) {
        ret = gazelle_filling_lstack_stat_total(&stat, instance->stack_array[i]);
        if (ret != GAZELLE_OK) {
            LTRAN_ERR("gazelle_filling_lstack_stat_total failed. ret=%d.\n", ret);
            return;
        }
        if (i == instance->stack_cnt - 1) {
            stat.eof = 1;
        }
        (void)write_specied_len(fd, (char *)&stat, sizeof(struct gazelle_stat_lstack_total));
    }

    // no client also repond for llt
    if (instance->stack_cnt == 0) {
        stat.eof = 1;
        (void)write_specied_len(fd, (char *)&stat, sizeof(struct gazelle_stat_lstack_total));
    }
}

static int32_t find_sockfd_by_ip(struct gazelle_in_addr ip)
{
    struct gazelle_instance *instance = NULL;

    instance = gazelle_instance_map_by_ip(get_instance_mgr(), ip.s_addr);
    if (instance == NULL) {
        LTRAN_WARN("get null instance by ip %u\n", ip.s_addr);
        return -1;
    }

    return instance->sockfd;
}

void handle_cmd_to_lstack(const struct gazelle_stat_msg_request *msg)
{
    struct gazelle_stack_dfx_data stat = {0};
    int32_t lstack_fd, ret;

    lstack_fd = find_sockfd_by_ip(msg->ip);
    if (lstack_fd < 0) {
        return;
    }

    (void)write_specied_len(lstack_fd, (const char *)msg, sizeof(struct gazelle_stat_msg_request));

    /* wait lstack finish this cmd avoid two write to lstack */
    while (stat.eof == 0) {
        ret = read_specied_len(lstack_fd, (char *)&stat, sizeof(stat));
        if (ret != GAZELLE_OK) {
            return;
        }
    }
}

void handle_resp_lstack_transfer(const struct gazelle_stat_msg_request *msg, int32_t fd)
{
    int32_t lstack_fd;
    struct gazelle_stack_dfx_data stat;
    int32_t cmd_fd = fd;
    int32_t ret;

    lstack_fd = find_sockfd_by_ip(msg->ip);
    if (lstack_fd < 0) {
        return;
    }

    (void)write_specied_len(lstack_fd, (const char *)msg, sizeof(struct gazelle_stat_msg_request));

    (void)memset_s(&stat, sizeof(struct gazelle_stack_dfx_data), 0, sizeof(stat));
    while (stat.eof == 0) {
        ret = read_specied_len(lstack_fd, (char *)&stat, sizeof(stat));
        if (ret != GAZELLE_OK) {
            return;
        }
        (void)write_specied_len(cmd_fd, (char *)&stat, sizeof(stat));
    }

    return;
}
