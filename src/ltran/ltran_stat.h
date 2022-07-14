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

#ifndef __GAZELLE_STAT_H__
#define __GAZELLE_STAT_H__

#include <netinet/in.h>

#include <rte_common.h>

#include "gazelle_opt.h"

/*
 * When doing reads from the NIC or the client queues,
 * use this batch size
 */
#define BACKUP_SIZE_FACTOR   (256)
#define RING_MAX_SIZE        (512) /* determined by g_mbuf_ring.rx_ring in func create_shared_ring in file dpdk.c */
#define PACKET_READ_SIZE     (32)
#define BACKUP_MBUF_SIZE     (BACKUP_SIZE_FACTOR * PACKET_READ_SIZE)


enum GAZELLE_CLIENT_STATE {
    GAZELLE_CLIENT_STATE_NORMAL = 0,
    GAZELLE_CLIENT_STATE_CONNECTING,
    GAZELLE_CLIENT_STATE_RECONNECTING,
    GAZELLE_CLIENT_STATE_MAX
};

enum GAZELLE_TCP_LIST_STATE {
    GAZELLE_ACTIVE_LIST,
    GAZELLE_LISTEN_LIST,
    GAZELLE_TIME_WAIT_LIST,
};

enum GAZELLE_TCP_STATE {
    GAZELLE_TCP_STATE_CLS,
    GAZELLE_TCP_STATE_LSN,
    GAZELLE_TCP_STATE_S_S,
    GAZELLE_TCP_STATE_S_R,
    GAZELLE_TCP_STATE_ESTB,
    GAZELLE_TCP_STATE_FW1,
    GAZELLE_TCP_STATE_FW2,
    GAZELLE_TCP_STATE_CW,
    GAZELLE_TCP_STATE_CLSING,
    GAZELLE_TCP_STATE_LA,
    GAZELLE_TCP_STATE_TW
};

/*
 * Shared statistics information for display by dfx tools.
 * All statistic values share cache lines, as this data is written only
 * by the server process. (rare reads by stats display)
 * and be read by dfx tools.
 */
struct gazelle_stat_ltran_port {
    uint64_t tx;
    uint64_t rx;
    uint64_t tx_drop;
    uint64_t rx_drop;

    uint64_t rx_iter_arr[GAZELLE_PACKET_READ_SIZE + 1];

    uint64_t tx_bytes;
    uint64_t rx_bytes;

    uint64_t arp_pkt;
    uint64_t kni_pkt;
    uint64_t icmp_pkt;
    uint64_t tcp_pkt;

    int32_t loglevel;
} __rte_cache_aligned;

struct gazelle_stat_lstack_total {
    uint32_t eof;
    uint32_t tid;
    uint32_t index;
    uint64_t rx;
    uint64_t tx;
    uint64_t rx_err;
    uint64_t tx_err;
    uint64_t rx_drop;
    uint64_t tx_drop;
    uint64_t tx_backup;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t latency_total;
    uint64_t latency_pkts;
    uint64_t latency_min;
    uint64_t latency_max;
    uint32_t backup_mbuf_cnt;
    uint32_t tx_ring_cnt;
    uint32_t rx_ring_cnt;
    uint32_t reg_ring_cnt;
} __rte_cache_aligned;

/* forward statistics structure */
struct statistics {
    struct gazelle_stat_ltran_port port_stats[GAZELLE_MAX_ETHPORTS];
};

/* ltran statistics structure */
struct gazelle_stat_ltran_total {
    uint32_t port_num;
    struct gazelle_stat_ltran_port port_list[GAZELLE_MAX_PORT_NUM];
};

struct gazelle_stat_ltran_ip {
    uint32_t ip_num;
    struct in_addr ip_list[GAZELLE_CLIENT_NUM_ALL];
};

struct gazelle_stat_client_info {
    uint32_t id;
    uint32_t bond_port;
    struct in_addr ip;
    enum GAZELLE_CLIENT_STATE state;
    uint32_t stack_cnt;
    int32_t sockfd;
    uint32_t pid;
};

struct gazelle_stat_ltran_client {
    uint32_t client_num;
    struct gazelle_stat_client_info client_info[GAZELLE_CLIENT_NUM_ALL];
};

int32_t get_start_latency_flag(void);
void stat_client_clear(int32_t num);
uint64_t get_start_time_stamp(void);
void set_start_latency_flag(int32_t flag);
void set_ltran_stop_flag(int32_t flag);
int32_t get_ltran_stop_flag(void);
struct statistics *get_statistics(void);

struct gazelle_stat_msg_request;
void handle_resp_ltran_latency(int32_t fd);
void handle_cmd_to_lstack(const struct gazelle_stat_msg_request *msg);
void handle_resp_ltran_sock(int32_t fd);
void handle_resp_ltran_total(int32_t fd);
void handle_resp_ltran_client(int32_t fd);
void handle_resp_ltran_conn(int32_t fd);
void handle_resp_lstack_latency(int32_t fd);
void set_ltran_log_level(struct gazelle_stat_msg_request *msg);
void handle_resp_lstack_transfer(const struct gazelle_stat_msg_request *msg, int32_t fd);
void handle_resp_lstack_total(const struct gazelle_stat_msg_request *msg, int32_t fd);

#endif /* ifndef __GAZELLE_STAT_H__ */
