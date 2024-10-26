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

#include <lwip/lwipgz_flow.h>
#include "common/gazelle_opt.h"
#include "common/gazelle_dfx_msg.h"

#define RXTX_CACHE_SZ        (VDEV_RX_QUEUE_SZ)

#define KNI_NB_MBUF          (DEFAULT_RING_SIZE << 4)

#define MAX_PACKET_SZ        1538

#define RING_SIZE(x)         ((x) - 1)

#define MBUF_SZ              (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

#define BYTES2MB(bytes)      (((double)(bytes)) / (1024 * 1024))

/* DPDK limit ring head-tail distance in rte_ring_init.
 * Max value is RTE_RING_SZ_MASK / HTD_MAX_DEF, RTE_RING_SZ_MASK is 0x7fffffff, HTD_MAX_DEF is 8.
 */
#define MBUF_MAX_NUM         0xfffffff

int thread_affinity_default(void);
int thread_affinity_init(int cpu_id);

struct protocol_stack;
struct rte_mempool;
struct rte_ring;
struct rte_mbuf;
int32_t fill_mbuf_to_ring(struct rte_mempool *mempool, struct rte_ring *ring, uint32_t mbuf_num);
int32_t dpdk_eal_init(void);
int32_t pktmbuf_pool_init(struct protocol_stack *stack);
struct rte_mempool *create_mempool(const char *name, uint32_t count, uint32_t size,
                                   uint32_t flags, int32_t idx);
int32_t create_shared_ring(struct protocol_stack *stack);
void lstack_log_level_init(void);
int dpdk_ethdev_init(int port_id);
int dpdk_ethdev_start(void);
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
void dpdk_skip_nic_init(void);
void dpdk_restore_pci(void);
#endif
int32_t dpdk_init_lstack_kni(void);
bool port_in_stack_queue(gz_addr_t *src_ip, gz_addr_t *dst_ip, uint16_t src_port, uint16_t dst_port);
struct rte_mempool *create_pktmbuf_mempool(const char *name, uint32_t nb_mbuf,
                                           uint32_t mbuf_cache_size, uint16_t queue_id, unsigned numa_id);

void dpdk_nic_xstats_get(struct gazelle_stack_dfx_data *dfx, uint16_t port_id);
int32_t dpdk_alloc_pktmbuf(struct rte_mempool *pool, struct rte_mbuf **mbufs, uint32_t num, bool reserve);
void dpdk_nic_features_get(struct gazelle_stack_dfx_data *dfx, uint16_t port_id);
void dpdk_fixed_mem_usage(double *fixed_mem);
void dpdk_general_mem_usage(struct gazelle_general_lstack_memory *general_mem_info);
void dpdk_mempool_mem_get(struct rte_mempool *mp, struct gazelle_memory_info *mem_info);
#endif /* GAZELLE_DPDK_H */
