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

#ifndef __GAZELLE_DFX_MSG_H__
#define __GAZELLE_DFX_MSG_H__

#include <sys/types.h>
#include <stdint.h>

#include <lwip/lwipgz_flow.h>

#ifdef GAZELLE_FAULT_INJECT_ENABLE
#include "gazelle_fault_inject_common.h"
#endif /* GAZELLE_FAULT_INJECT_ENABLE */

#define GAZELLE_CLIENT_NUM_MIN           1
#define GAZELLE_LOG_LEVEL_MAX            10
#define MAX_PROTOCOL_LENGTH              20
#define GAZELLECTL_TIMEOUT               5000 // millisecond
/* maybe it should be consistent with MEMP_NUM_TCP_PCB */
#define GAZELLE_LSTACK_MAX_CONN          (20000 + 2000) // same as MAX_CLIENTS + RESERVED_CLIENTS in lwipopts.h

#define GAZELLE_RESULT_LEN               4096
#define GAZELLE_MAX_LATENCY_TIME         1800 // max latency time 30mins
#define GAZELLE_RESULT_LINE_LEN          80   // for a single row, the max len of result is 80

enum GAZELLE_STAT_MODE {
    GAZELLE_STAT_LTRAN_SHOW = 0,
    GAZELLE_STAT_LTRAN_SHOW_RATE,
    GAZELLE_STAT_LTRAN_SHOW_LB_RATE,
    GAZELLE_STAT_LTRAN_SHOW_INSTANCE,
    GAZELLE_STAT_LTRAN_SHOW_BURST,
    GAZELLE_STAT_LTRAN_SHOW_LATENCY,
    GAZELLE_STAT_LTRAN_QUIT,
    GAZELLE_STAT_LTRAN_START_LATENCY,
    GAZELLE_STAT_LTRAN_STOP_LATENCY,
    GAZELLE_STAT_LTRAN_LOG_LEVEL_SET,
    GAZELLE_STAT_LTRAN_SHOW_SOCKTABLE,
    GAZELLE_STAT_LTRAN_SHOW_CONNTABLE,
    GAZELLE_STAT_LTRAN_SHOW_LSTACK,
    GAZELLE_STAT_LSTACK_SHOW_PROTOCOL,

    GAZELLE_STAT_LSTACK_SHOW,
    GAZELLE_STAT_LSTACK_LOG_LEVEL_SET,
    GAZELLE_STAT_LSTACK_SHOW_RATE,
    GAZELLE_STAT_LSTACK_SHOW_SNMP,
    GAZELLE_STAT_LSTACK_SHOW_VIRTIO,
    GAZELLE_STAT_LSTACK_SHOW_CONN,
    GAZELLE_STAT_LSTACK_SHOW_LATENCY,
    GAZELLE_STAT_LSTACK_LOW_POWER_MDF,
    GAZELLE_STAT_LSTACK_SHOW_XSTATS,
    GAZELLE_STAT_LSTACK_SHOW_AGGREGATE,
    GAZELLE_STAT_LSTACK_SHOW_NIC_FEATURES,
    GAZELLE_STAT_LSTACK_SHOW_INTR,

#ifdef GAZELLE_FAULT_INJECT_ENABLE
    GAZELLE_STAT_FAULT_INJECT_SET,
    GAZELLE_STAT_FAULT_INJECT_UNSET,
#endif /* GAZELLE_FAULT_INJECT_ENABLE */

    GAZELLE_STAT_MODE_MAX,
};

enum GAZELLE_LATENCY_TYPE {
    GAZELLE_LATENCY_INTO_MBOX,       // t0 -> t1
    GAZELLE_LATENCY_READ_LWIP,       // t1 -> t2
    GAZELLE_LATENCY_READ_APP_CALL,   // t2 -> t3
    GAZELLE_LATENCY_READ_LSTACK,     // t3 -> t4
    GAZELLE_LATENCY_READ_MAX,        // t0 -> t4

    GAZELLE_LATENCY_WRITE_INTO_RING, // t0 -> t1
    GAZELLE_LATENCY_WRITE_LWIP,      // t1 -> t2
    GAZELLE_LATENCY_WRITE_LSTACK,    // t2 -> t3
    GAZELLE_LATENCY_WRITE_MAX,       // t0 -> t3

    GAZELLE_LATENCY_WRITE_RPC_MSG,   // rpc_call_send
    GAZELLE_LATENCY_RECVMBOX_READY,  // ready to read from recvmbox

    GAZELLE_LATENCY_MAX,
};

enum GAZELLE_TCP_LIST_STATE {
    GAZELLE_ACTIVE_LIST,
    GAZELLE_LISTEN_LIST,
    GAZELLE_TIME_WAIT_LIST,
};

struct gazelle_stack_stat {
    uint64_t wakeup_events;
    uint64_t write_lwip_cnt;
    uint64_t send_pkts_fail;
    uint64_t read_lwip_drop;
    uint64_t read_lwip_cnt;
    uint64_t rx_allocmbuf_fail;
    uint64_t tx_allocmbuf_fail;
    uint64_t call_null;
    uint64_t rx_drop;
    uint64_t rx;
    uint64_t tx_drop;
    uint64_t tx;
    uint64_t tx_prepare_fail;
    uint64_t accept_fail;
    uint64_t sock_rx_drop;
    uint64_t sock_tx_merge;
};

struct gazelle_wakeup_stat {
    uint64_t app_events;
    uint64_t app_write_rpc;
    uint64_t app_write_cnt;
    uint64_t app_read_cnt;
    uint64_t read_null;
    uint64_t kernel_events;
};

struct gazelle_stack_aggregate_stats {
    /* 0: RX, 1: TX, 2: APP_TX */
    uint32_t size_1_64[3];
    uint32_t size_65_512[3];
    uint32_t size_513_1460[3];
    uint32_t size_1461_8192[3];
    uint32_t size_8193_max[3];

    uint64_t rx_bytes;
    uint64_t tx_bytes;
};

struct gazelle_stat_pkts {
    uint16_t conn_num;
    uint32_t mbufpool_avail_cnt;
    uint64_t call_msg_cnt;
    uint64_t recv_list_cnt;
    uint64_t call_alloc_fail;
    struct gazelle_stack_stat stack_stat;
    struct gazelle_wakeup_stat wakeup_stat;
    struct gazelle_stack_aggregate_stats aggregate_stats;
};

// same with lstack_virtio.h struct virtio_instance
struct gazelle_stat_lstack_virtio {
#define VIRTIO_MAX_QUEUE_NUM 8
    uint16_t lstack_port_id;
    uint16_t virtio_port_id;
    uint16_t rx_queue_num;
    uint16_t tx_queue_num;

    uint64_t rx_pkg[VIRTIO_MAX_QUEUE_NUM];
    uint64_t rx_drop[VIRTIO_MAX_QUEUE_NUM];
    uint64_t tx_pkg[VIRTIO_MAX_QUEUE_NUM];
    uint64_t tx_drop[VIRTIO_MAX_QUEUE_NUM];
};

/* same as define in lwip/stats.h - struct stats_mib2 */
struct gazelle_stat_lstack_snmp {
    /* IP */
    uint32_t ip_inhdr_err;
    uint32_t ip_inaddr_err;
    uint32_t ip_inunknownprot;
    uint32_t ip_in_discard;
    uint32_t ip_in_deliver;
    uint32_t ip_out_req;
    uint32_t ip_out_discard;
    uint32_t ip_outnort;
    uint32_t ip_reasm_ok;
    uint32_t ip_reasm_fail;
    uint32_t ip_frag_ok;
    uint32_t ip_frag_fail;
    uint32_t ip_frag_create;
    uint32_t ip_reasm_reqd;
    uint32_t ip_fw_dgm;
    uint32_t ip_in_recv;

    /* TCP */
    uint32_t tcp_act_open;
    uint32_t tcp_passive_open;
    uint32_t tcp_attempt_fail;
    uint32_t tcp_estab_rst;
    uint32_t tcp_out_seg;
    uint32_t tcp_retran_seg;
    uint32_t tcp_in_seg;
    uint32_t tcp_in_err;
    uint32_t tcp_out_rst;
    uint32_t tcp_fin_ack_cnt;
    uint32_t tcp_delay_ack_cnt;
    uint32_t tcp_refused_cnt;
    uint32_t tcp_out_of_seq;
    uint32_t tcp_acceptmbox_full;
    uint32_t tcp_listen_drops;
    uint32_t tcp_in_empty_acks;
    /* GAZELLE TCP */
    uint32_t tcp_rst_in_keepalive_timeout;
    uint32_t tcp_rst_wrong_syn_in_timewait;
    uint32_t tcp_rst_wrong_ack_in_syn_rcvd;
    uint32_t tcp_ooseq_data_drop;
    uint32_t tcp_free_pcb_in_syn_maxrtx;
    uint32_t tcp_free_pcb_in_maxrtx;
    uint32_t tcp_alloc_pcb_fails;

    /* UDP */
    uint32_t udp_in_datagrams;
    uint32_t udp_no_ports;
    uint32_t udp_in_errors;
    uint32_t udp_out_datagrams;

    /* ICMP */
    uint32_t icmp_in_msgs;
    uint32_t icmp_in_errors;
    uint32_t icmp_in_dest_unreachs;
    uint32_t icmp_in_time_excds;
    uint32_t icmp_in_parm_probs;
    uint32_t icmp_in_src_quenchs;
    uint32_t icmp_in_redirects;
    uint32_t icmp_in_echos;
    uint32_t icmp_in_echo_reps;
    uint32_t icmp_in_time_stamps;
    uint32_t icmp_in_time_stamp_reps;
    uint32_t icmp_in_addr_masks;
    uint32_t icmp_in_addr_mask_reps;
    uint32_t icmp_out_msgs;
    uint32_t icmp_out_errors;
    uint32_t icmp_out_dest_unreachs;
    uint32_t icmp_out_time_excds;
    uint32_t icmp_out_echos; /* can be incremented by user application ('ping') */
    uint32_t icmp_out_echo_reps;
};

/* same as define in lwip/stats.h - struct stats_proto */
struct gazelle_stat_lstack_proto {
    /* data */
    uint64_t xmit;             /* Transmitted packets. */
    uint64_t recv;             /* Received packets. */
    uint64_t tx_in;            /* Transmitted in packets. */
    uint64_t tx_out;           /* Transmitted out packets. */
    uint64_t rx_in;            /* Received in packets. */
    uint64_t rx_out;           /* Received out packets. */
    uint64_t fw;               /* Forwarded packets. */
    uint64_t drop;             /* Dropped packets. */
    uint64_t chkerr;           /* Checksum error. */
    uint64_t lenerr;           /* Invalid length error. */
    uint64_t memerr;           /* Out of memory error. */
    uint64_t rterr;            /* Routing error. */
    uint64_t proterr;          /* Protocol error. */
    uint64_t opterr;           /* Error in options. */
    uint64_t err;              /* Misc error. */
    uint64_t cachehit;
};


struct gazelle_stat_lstack_conn_info {
    uint32_t state;
    gz_addr_t rip;
    gz_addr_t lip;
    uint16_t r_port;
    uint16_t l_port;
    uint32_t in_send;
    uint32_t recv_cnt;
    uint32_t send_ring_cnt;
    uint32_t recv_ring_cnt;
    uint32_t tcp_sub_state;

    uint32_t cwn;
    uint32_t rcv_wnd;
    uint32_t snd_wnd;
    uint32_t snd_buf;
    uint32_t lastack;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;
    int32_t fd;
    uint32_t events;
    uint32_t epoll_events;
    uint32_t eventlist;
    uint32_t keepalive;
    uint32_t keep_idle;
    uint32_t keep_intvl;
    uint32_t keep_cnt;
};

struct gazelle_stat_lstack_conn {
    uint32_t total_conn_num; // conn_num real use maybe bigger then conn_num
    uint32_t conn_num; // conn_num in conn_list
    struct gazelle_stat_lstack_conn_info conn_list[GAZELLE_LSTACK_MAX_CONN];
};

struct stack_latency {
    uint64_t latency_max;
    uint64_t latency_min;
    uint64_t latency_pkts;
    uint64_t latency_total;
};

struct gazelle_latency_result {
    int latency_stat_index;
    struct stack_latency latency_stat_record;
    char latency_stat_result[GAZELLE_RESULT_LEN];
};

struct gazelle_stack_latency {
    struct stack_latency latency[GAZELLE_LATENCY_MAX];
    uint64_t start_time;
    uint64_t g_cycles_per_us;
};

struct gazelle_stat_low_power_info {
    uint16_t low_power_mod;
    uint16_t lpm_rx_pkts;
    uint32_t lpm_pkts_in_detect;
    uint32_t lpm_detect_ms;
};

#define RTE_ETH_XSTATS_NAME_SIZE 64
#define RTE_ETH_XSTATS_MAX_LEN 256
#define RTE_MAX_ETHPORTS 32
struct nic_eth_xstats_name {
    char name[RTE_ETH_XSTATS_NAME_SIZE];
};

struct bonding {
    int8_t mode;
    int32_t miimon;
    uint16_t primary_port_id;
    uint16_t slaves[RTE_MAX_ETHPORTS];
    uint16_t slave_count;
};

struct nic_eth_xstats {
    struct nic_eth_xstats_name xstats_name[RTE_ETH_XSTATS_MAX_LEN];
    uint64_t values[RTE_ETH_XSTATS_MAX_LEN];
    uint32_t len;
    uint16_t port_id;
    struct bonding bonding;
};

struct nic_eth_features {
    uint16_t port_id;
    uint64_t rx_offload;
    uint64_t tx_offload;
};

struct interrupt_stats {
    uint64_t virtio_user_event_cnt;
    uint64_t nic_event_cnt;
    uint64_t remote_event_cnt;
    uint64_t local_event_cnt;
    uint64_t timeout_event_cnt;
};

struct gazelle_stack_dfx_data {
    /* indicates whether the current message is the last */
    uint32_t eof;
    uint32_t tid;
    int32_t loglevel;
    uint32_t stack_id;
    struct gazelle_stat_low_power_info low_power_info;

    union lstack_msg {
        struct gazelle_stat_pkts pkts;
        struct gazelle_stack_latency latency;
        struct gazelle_stat_lstack_conn conn;
        struct gazelle_stat_lstack_snmp snmp;
        struct gazelle_stat_lstack_virtio virtio;
        struct nic_eth_xstats nic_xstats;
        struct nic_eth_features nic_features;
        struct gazelle_stat_lstack_proto  proto_data;
        struct interrupt_stats intr_stats;

#ifdef GAZELLE_FAULT_INJECT_ENABLE
        struct gazelle_fault_inject_data inject;
#endif /* GAZELLE_FAULT_INJECT_ENABLE */
    } data;
};

struct gazelle_stat_forward_table_info {
    uint32_t tid;
    uint32_t protocol;
    /* net byte order */
    uint16_t dst_port;
    uint16_t src_port;
    uint32_t dst_ip;
    uint32_t src_ip;
    uint32_t conn_num;
};

struct gazelle_stat_forward_table {
    uint32_t conn_num;
    struct gazelle_stat_forward_table_info conn_list[GAZELLE_LSTACK_MAX_CONN];
};

struct gazelle_in_addr {
    uint32_t s_addr;
};
struct gazelle_stat_msg_request {
    enum GAZELLE_STAT_MODE stat_mode;
    struct gazelle_in_addr ip;
    uint32_t pid;

    union stat_param {
        char log_level[GAZELLE_LOG_LEVEL_MAX];
        uint16_t low_power_mod;
        char protocol[MAX_PROTOCOL_LENGTH];
#ifdef GAZELLE_FAULT_INJECT_ENABLE
        struct gazelle_fault_inject_data inject;
#endif /* GAZELLE_FAULT_INJECT_ENABLE */
    } data;
};

int write_specied_len(int fd, const char *buf, size_t target_size);
int read_specied_len(int fd, char *buf, size_t target_size);

#endif
