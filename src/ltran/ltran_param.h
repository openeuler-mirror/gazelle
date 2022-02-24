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

#ifndef __GAZELLE_PARAM_H__
#define __GAZELLE_PARAM_H__

#include <netinet/in.h>
#include <rte_ether.h>

#include "ltran_stat.h"
#include "ltran_instance.h"
#include "ltran_base.h"

struct ltran_config {
    struct {
        char **dpdk_argv;
        int32_t dpdk_argc;
        int32_t kni_switch;
    } dpdk;

    struct {
        uint8_t num_clients;
        /* host byte order */
        struct in_addr ipv4_subnet_addr;
        uint32_t ipv4_net_mask;
        int32_t ipv4_subnet_size;
        int32_t ipv4_subnet_length;
    } dispatcher;

    struct {
        int32_t miimon;
        int32_t mode;
        int32_t mtu;
        uint32_t portmask[GAZELLE_MAX_BOND_NUM];
        uint32_t port_num;
        uint32_t mac_num;
        uint32_t rx_queue_num;
        uint32_t tx_queue_num;
        struct rte_ether_addr mac[GAZELLE_MAX_BOND_NUM];
    } bond;

    struct {
        /* the unit is seconds */
        unsigned long tcp_conn_scan_interval;
    } tcp_conn;

    struct {
        int32_t log_switch;
    } log;
};

int32_t parse_config_file_args(const char *conf_file_path, struct ltran_config *ltran_config);
void param_resource_destroy(struct ltran_config *ltran_config);
bool is_same_mac_addr(const struct rte_ether_addr *smac, const struct rte_ether_addr *dmac);
struct ltran_config* get_ltran_config(void);

#endif /* ifndef __GAZELLE_PARAM_H__ */
