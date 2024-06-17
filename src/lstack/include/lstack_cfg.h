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

#ifndef _GAZELLE_NET_CFG_H_
#define _GAZELLE_NET_CFG_H_
#include <stdbool.h>

#include <lwip/ip_addr.h>
#include <rte_ether.h>

#include "lstack_protocol_stack.h"
#include "gazelle_opt.h"

#define BASE_BIN_SCALE  2
#define BASE_OCT_SCALE  8
#define BASE_DEC_SCALE  10
#define BASE_HEX_SCALE  16

#define TX_RING_NAME    64
#define RX_RING_NAME    64
#define MBUF_POOL_NAME  64

#define CFG_MAX_CPUS    512
#define CFG_MAX_PORTS   UINT8_MAX
#define ARP_MAX_ENTRIES 1024
#define LOG_DIR_PATH    PATH_MAX
#define LOG_LEVEL_LEN   16
#define GAZELLE_MAX_NUMA_NODES 8
#define MAX_PROCESS_NUM 32

/* Default value of low power mode parameters */
#define LSTACK_LPM_DETECT_MS_MIN        (5 * 1000)
#define LSTACK_LPM_DETECT_MS_MAX        (60 * 10000)

#define LSTACK_LPM_RX_PKTS_MIN          5
#define LSTACK_LPM_RX_PKTS_MAX          100

#define LSTACK_LPM_DETECT_MS            1000
#define LSTACK_LPM_PKTS_IN_DETECT       1000
#define LSTACK_LPM_RX_PKTS              20


#define LSTACK_LPM_PKTS_IN_DETECT_MIN   5
#define LSTACK_LPM_PKTS_IN_DETECT_MAX   65535

struct secondary_attach_arg {
    uint8_t socket_num;
    uint64_t socket_size;
    uint32_t socket_per_size[GAZELLE_MAX_NUMA_NODES];
    uintptr_t base_virtaddr;
    char file_prefix[PATH_MAX];
};

struct cfg_nic_params {
    uint32_t rxqueue_size;
    uint32_t txqueue_size;
    int32_t vlan_mode;
};

struct cfg_params {
    ip4_addr_t host_addr;
    ip6_addr_t host_addr6;
    ip4_addr_t netmask;
    ip4_addr_t gateway_addr;
    uint8_t mac_addr[ETHER_ADDR_LEN];
    uint16_t num_cpu;
    uint32_t cpus[CFG_MAX_CPUS];
    uint32_t send_cpus[CFG_MAX_CPUS];
    uint32_t recv_cpus[CFG_MAX_CPUS];
    uint16_t app_exclude_num_cpu;
    uint32_t app_exclude_cpus[CFG_MAX_CPUS];
    uint8_t num_ports;
    uint16_t ports[CFG_MAX_PORTS];
    char log_file[PATH_MAX];
    uint16_t low_power_mod;
    uint16_t lpm_rx_pkts;
    uint32_t lpm_detect_ms;
    uint32_t lpm_pkts_in_detect;
    uint32_t tcp_conn_count;
    uint32_t mbuf_count_per_conn;
    uint32_t read_connect_number;
    uint32_t rpc_number;
    uint32_t nic_read_number;
    uint8_t use_ltran; // false:lstack read from nic. true:lstack read form ltran process.

    uint16_t num_process;
    uint16_t num_listen_port;
    uint16_t is_primary;
    uint16_t num_queue;
    uint16_t tot_queue_num;
    uint8_t process_idx;
    uint32_t process_numa[PROTOCOL_STACK_MAX];

    bool kni_switch;
    bool listen_shadow; // true:listen in all stack thread. false:listen in one stack thread.
    bool app_bind_numa;
    bool main_thread_affinity;
    bool seperate_send_recv;
    int dpdk_argc;
    char **dpdk_argv;
    struct secondary_attach_arg sec_attach_arg;
    char unix_socket_filename[NAME_MAX];
    uint16_t send_ring_size;
    uint16_t recv_ring_size;
    bool tuple_filter;
    int8_t bond_mode;
    int32_t bond_miimon;
    struct rte_ether_addr bond_slave_mac_addr[GAZELLE_MAX_BOND_NUM];
    bool use_sockmap;
    bool udp_enable;
    struct cfg_nic_params nic;
    bool stack_mode_rtc;
    bool nonblock_mode;
    uint32_t rpc_msg_max;
    bool send_cache_mode;
};

struct cfg_params *get_global_cfg_params(void);

static inline uint8_t use_ltran(void)
{
    return get_global_cfg_params()->use_ltran;
}

int cfg_init(void);
int gazelle_param_init(int *argc, char **argv);
int gazelle_copy_param(const char *param, bool is_double,
    int *argc, char argv[][PATH_MAX]);

int match_host_addr(ip_addr_t *addr);
int32_t init_stack_numa_cpuset(struct protocol_stack *stack);

#endif /* GAZELLE_NET_CFG_H */
