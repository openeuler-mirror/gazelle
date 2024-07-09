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

#ifndef __GAZELLE_ETHDEV_H__
#define __GAZELLE_ETHDEV_H__

#include <stdint.h>

#include "common/gazelle_opt.h"

struct port_info {
    uint16_t num_ports;
    uint16_t id[GAZELLE_MAX_ETHPORTS];
};

struct rte_kni;
uint32_t get_bond_num(void);
struct rte_kni* get_gazelle_kni(void);
void set_bond_num(const uint32_t bond_num);
struct port_info* get_port_info(void);
uint16_t* get_bond_port(void);

struct rte_mempool;
struct rte_mempool** get_pktmbuf_txpool(void);
struct rte_mempool** get_pktmbuf_rxpool(void);

int32_t ltran_ethdev_init(void);

#endif /* ifndef __GAZELLE_ETHDEV_H__ */
