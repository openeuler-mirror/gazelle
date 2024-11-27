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

#ifndef IFNAMSIZ
#include <net/if.h>
#endif

#include <lwip/ip_addr.h>
#include <rte_ether.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>

#include "lstack_protocol_stack.h"
#include "common/gazelle_reg_msg.h"
#include "common/gazelle_opt.h"

#define BASE_BIN_SCALE  2
#define BASE_OCT_SCALE  8
#define BASE_DEC_SCALE  10
#define BASE_HEX_SCALE  16

#define TX_RING_NAME    64
#define RX_RING_NAME    64
#define MBUF_POOL_NAME  64

#define CFG_MAX_PORTS   UINT8_MAX
#define ARP_MAX_ENTRIES 1024
#define LOG_DIR_PATH    PATH_MAX
#define LOG_LEVEL_LEN   16
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

struct dev_addr {
#define DEV_ADDR_TYPE_EMPTY             0
#define DEV_ADDR_TYPE_MAC               1
#define DEV_ADDR_TYPE_PCI               2
    uint8_t addr_type;
    union addr_union {
        struct rte_ether_addr mac_addr;
        struct rte_pci_addr pci_addr;
    } addr;
};

struct cfg_params {
    char log_file[PATH_MAX];

    struct { // dpdk
        char **dpdk_argv;
        uint8_t dpdk_argc;
        struct secondary_attach_arg {
            uint8_t socket_num;
            uint64_t socket_size;
            uint32_t socket_per_size[GAZELLE_MAX_NUMA_NODES];
            uintptr_t base_virtaddr;
            char file_prefix[PATH_MAX];
        } sec_attach_arg;
        char socket_mem[SOCKET_MEM_STRLEN];
        char lcores[RTE_MAX_LCORE];
    };

    struct { // eth
        ip4_addr_t host_addr;
        ip6_addr_t host_addr6;
        ip4_addr_t netmask;
        ip4_addr_t gateway_addr;
        char xdp_eth_name[IFNAMSIZ];
        uint8_t mac_addr[ETHER_ADDR_LEN];
        int8_t bond_mode;
        int32_t bond_miimon;
        struct dev_addr bond_slave_addr[GAZELLE_MAX_BOND_NUM];
    };

    struct { // low_power
        uint16_t low_power_mod;
        uint16_t lpm_rx_pkts;
        uint32_t lpm_detect_ms;
        uint32_t lpm_pkts_in_detect;
    };

    struct { // eth_rxtx
        uint32_t rxqueue_size;
        uint32_t txqueue_size;
        uint16_t num_queue;
        uint16_t tot_queue_num;
        bool send_cache_mode;
        bool flow_bifurcation;
        int32_t vlan_mode;
    };

    struct { // stack
        uint16_t num_cpu;
        uint16_t numa_id;
        uint16_t stack_num;
        uint32_t cpus[CPUS_MAX_NUM];

        bool main_thread_affinity;
        bool app_bind_numa;
        uint16_t app_exclude_num_cpu;
        uint32_t app_exclude_cpus[CPUS_MAX_NUM];

        bool stack_mode_rtc;
        bool listen_shadow; // true:listen in all stack thread. false:listen in one stack thread.
        bool stack_interrupt;

        uint32_t read_connect_number;
        uint32_t nic_read_number;
        uint32_t rpc_number;
        uint32_t rpc_msg_max;
    };

    struct { // socket
        uint16_t send_ring_size;
        uint16_t recv_ring_size;
        uint32_t tcp_conn_count;
        uint32_t mbuf_count_per_conn;
    };

    struct { // deprecated
        char unix_socket_filename[NAME_MAX];
        bool use_ltran; // false:lstack read from nic. true:lstack read form ltran process.
        bool udp_enable;
        bool kni_switch;
    };

    struct { // experiment
        uint16_t num_process;
        uint16_t is_primary;
        uint8_t process_idx;
        uint32_t process_numa[PROTOCOL_STACK_MAX];
        bool tuple_filter;
        bool use_sockmap;
    };
};

struct cfg_params *get_global_cfg_params(void);

static inline uint8_t use_ltran(void)
{
    return get_global_cfg_params()->use_ltran;
}

int cfg_init(void);
int gazelle_param_init(int *argc, char **argv);
int gazelle_copy_param(const char *param, bool is_double, int *argc, char argv[][PATH_MAX]);
int match_host_addr(ip_addr_t *addr);
int numa_to_cpusnum(uint16_t numa_id, uint32_t *cpulist, int num);

#endif /* GAZELLE_NET_CFG_H */
