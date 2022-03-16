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

#ifndef LIBOS_NET_CFG_H
#define LIBOS_NET_CFG_H
#include <stdbool.h>

#include <rte_ether.h>

#include <lwip/ip_addr.h>

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
#define LWIP_EPOOL_MAX_EVENTS 512

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
    uint64_t socket_per_size[GAZELLE_MAX_NUMA_NODES];
    uintptr_t base_virtaddr;
    char file_prefix[PATH_MAX];
};

struct cfg_params {
    ip4_addr_t host_addr;
    ip4_addr_t netmask;
    ip4_addr_t gateway_addr;
    struct rte_ether_addr ethdev;
    uint16_t num_cpu;
    uint16_t cpus[CFG_MAX_CPUS];
    uint16_t num_wakeup;
    uint16_t weakup[CFG_MAX_CPUS];
    uint8_t num_ports;
    uint16_t ports[CFG_MAX_PORTS];
    char log_file[PATH_MAX];
    uint16_t low_power_mod;
    uint16_t lpm_rx_pkts;
    uint32_t lpm_detect_ms;
    uint32_t lpm_pkts_in_detect;
    bool use_ltran; // ture:lstack read from nic false:read form ltran
    bool kni_switch;
    int dpdk_argc;
    char **dpdk_argv;
#ifdef USE_LIBOS_MEM
    struct secondary_attach_arg sec_attach_arg;
#endif
};

struct cfg_params *get_global_cfg_params(void);

static inline bool use_ltran(void)
{
    return get_global_cfg_params()->use_ltran;
}

int cfg_init(void);
int gazelle_param_init(int *argc, char **argv);
int gazelle_copy_param(const char *param, bool is_double,
    int *argc, char argv[][PATH_MAX]);

int match_host_addr(uint32_t ipv4);
int32_t init_stack_numa_cpuset(void);

#endif /* LIBOS_NET_CFG_H */
