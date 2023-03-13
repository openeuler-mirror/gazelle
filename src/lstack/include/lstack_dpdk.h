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

#include "gazelle_opt.h"
#include "gazelle_dfx_msg.h"

#define RXTX_CACHE_SZ       (VDEV_RX_QUEUE_SZ)
#define KNI_NB_MBUF         (DEFAULT_RING_SIZE << 4)

#define RESERVE_NIC_RECV    (1024)

#define MBUF_HEADER_LEN     64

#define MAX_PACKET_SZ       2048

#define RING_SIZE(x)         ((x) - 1)

#define MBUF_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

#define MAX_CORE_NUM            256
#define CALL_MSG_RING_SIZE      (unsigned long long)32
#define CALL_CACHE_SZ           0

int thread_affinity_default(void);
int thread_affinity_init(int cpu_id);

struct protocol_stack;
struct rte_mempool;
struct rte_ring;
struct rte_mbuf;
int32_t fill_mbuf_to_ring(struct rte_mempool *mempool, struct rte_ring *ring, uint32_t mbuf_num);
int32_t dpdk_eal_init(void);
int32_t pktmbuf_pool_init(struct protocol_stack *stack, uint16_t stack_num);
struct rte_ring *create_ring(const char *name, uint32_t count, uint32_t flags, int32_t queue_id);
int32_t create_shared_ring(struct protocol_stack *stack);
void lstack_log_level_init(void);
int dpdk_ethdev_init(void);
int dpdk_ethdev_start(void);
void dpdk_skip_nic_init(void);
int32_t dpdk_init_lstack_kni(void);
void dpdk_restore_pci(void);
bool port_in_stack_queue(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
uint16_t get_port_id();
struct rte_mempool *create_pktmbuf_mempool(const char *name, uint32_t nb_mbuf,uint32_t mbuf_cache_size, uint16_t queue_id);

void dpdk_nic_xstats_get(struct gazelle_stack_dfx_data *dfx, uint16_t port_id);
#endif /* GAZELLE_DPDK_H */
