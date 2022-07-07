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

#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <lwip/pbuf.h>
#include "lstack_lockless_queue.h"
#include "lstack_vdev.h"
#include "gazelle_reg_msg.h"
#include "dpdk_common.h"
struct protocol_stack;

#define RX_NB_MBUF          ((5 * MAX_CLIENTS) + (VDEV_RX_QUEUE_SZ * DEFAULT_BACKUP_RING_SIZE_FACTOR))
#define RX_MBUF_CACHE_SZ    (VDEV_RX_QUEUE_SZ)
#define TX_NB_MBUF          (128 * DEFAULT_RING_SIZE)
#define TX_MBUF_CACHE_SZ    (DEFAULT_RING_SIZE)
#define KNI_NB_MBUF         (DEFAULT_RING_SIZE << 2)
#define KNI_MBUF_CACHE_SZ   (DEFAULT_RING_SIZE)

#define MBUF_HEADER_LEN 64

#define MAX_PACKET_SZ  2048

#define RING_SIZE(x)         ((x) - 1)

#define MBUF_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

#define MAX_CORE_NUM            256
#define CALL_MSG_RING_SIZE      (unsigned long long)32
#define CALL_CACHE_SZ           0

/* Layout:
 * | rte_mbuf | pbuf | custom_free_function | payload |
 **/
static inline struct rte_mbuf *pbuf_to_mbuf(const struct pbuf *p)
{
    return ((struct rte_mbuf *)((uint8_t *)(p) - sizeof(struct rte_mbuf) - GAZELLE_MBUFF_PRIV_SIZE));
}
static inline struct pbuf_custom *mbuf_to_pbuf(const struct rte_mbuf *m)
{
    return ((struct pbuf_custom *)((uint8_t *)(m) + sizeof(struct rte_mbuf) + GAZELLE_MBUFF_PRIV_SIZE));
}

int thread_affinity_default(void);
int thread_affinity_init(int cpu_id);

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

#endif /* GAZELLE_DPDK_H */
