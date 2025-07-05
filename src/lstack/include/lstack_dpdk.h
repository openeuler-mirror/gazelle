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

#ifndef _GAZELLE_DPDK_H_
#define _GAZELLE_DPDK_H_

#include <rte_version.h>
#include <rte_ring.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "common/gazelle_opt.h"
#include "common/gazelle_dfx_msg.h"

#define KNI_NB_MBUF          (DEFAULT_RING_SIZE << 4)

#define RING_SIZE(x)         ((x) - 1)

struct protocol_stack;

int32_t dpdk_eal_init(void);
void lstack_log_level_init(void);

int dpdk_ethdev_init(int port_id);
int dpdk_ethdev_start(void);
int init_dpdk_ethdev(void);

int thread_affinity_default(void);

int32_t create_shared_ring(struct protocol_stack *stack);
int32_t fill_mbuf_to_ring(int stack_id, struct rte_ring *ring, uint32_t mbuf_num);

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
void dpdk_skip_nic_init(void);
void dpdk_restore_pci(void);
#endif
int32_t dpdk_init_lstack_kni(void);

void dpdk_nic_xstats_get(struct gazelle_stack_dfx_data *dfx, uint16_t port_id);
void dpdk_nic_features_get(struct gazelle_stack_dfx_data *dfx, uint16_t port_id);

uint32_t dpdk_pktmbuf_mempool_num(void);
uint32_t dpdk_total_socket_memory(void);

#endif /* GAZELLE_DPDK_H */
