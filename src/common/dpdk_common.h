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

#ifndef __LIBOS_DPDK_COMMON_H__
#define __LIBOS_DPDK_COMMON_H__

#include <rte_mbuf.h>

#define GAZELLE_KNI_NAME                     "kni"   // will be removed during dpdk update

/* time_stamp time_stamp_vaid_check . align 8 */
#define GAZELLE_MBUFF_PRIV_SIZE  (sizeof(uint64_t) * 2)
#define PTR_TO_PRIVATE(mbuf)    RTE_PTR_ADD(mbuf, sizeof(struct rte_mbuf))

static __rte_always_inline void copy_mbuf(struct rte_mbuf *dst, struct rte_mbuf *src)
{
    /* NOTE!!! magic code, even the order.
        I wrote it carefully, and check the assembly. for example, there is 24 ins in A72,
        and if there is no cache miss, it only take less than 20 cycle(store pipe is the bottleneck).
    */
    uint8_t *dst_data = NULL;
    uint8_t *src_data = NULL;
    uint32_t rx_desc_fields_len = 16;
    uint16_t data_len;

    /* In the direction of tx, data is copied from lstack to ltran. It is necessary to judge whether
       the length of data transmitted from lstack has been tampered with to prevent overflow
    */
    data_len = src->data_len;
    if (data_len > RTE_MBUF_DEFAULT_BUF_SIZE)
        return;

    dst->ol_flags = src->ol_flags;
    // there is buf_len in rx_descriptor_fields1, copy it is dangerous acturely.
    rte_memcpy((uint8_t *)dst->rx_descriptor_fields1, (const uint8_t *)src->rx_descriptor_fields1, rx_desc_fields_len);

    dst_data = rte_pktmbuf_mtod(dst, void*);
    src_data = rte_pktmbuf_mtod(src, void*);

    rte_memcpy(dst_data, src_data, data_len);

    // copy private date.
    dst_data = (uint8_t *)PTR_TO_PRIVATE(dst);
    src_data = (uint8_t *)PTR_TO_PRIVATE(src);
    rte_memcpy(dst_data, src_data, GAZELLE_MBUFF_PRIV_SIZE);

    return;
}

static __rte_always_inline void time_stamp_into_mbuf(uint32_t rx_count, struct rte_mbuf *buf[], uint64_t time_stamp)
{
    for (uint32_t i = 0; i < rx_count; i++) {
        uint64_t *priv = (uint64_t *)PTR_TO_PRIVATE(buf[i]);
        *priv = time_stamp; // time stamp
        *(priv + 1) = ~(*priv); // just for later vaid check
    }
}

pthread_mutex_t *get_kni_mutex(void);
struct rte_kni* get_gazelle_kni(void);
int32_t dpdk_kni_init(uint16_t port, struct rte_mempool *pool);
int32_t kni_process_tx(struct rte_mbuf **pkts_burst, uint32_t count);
void kni_process_rx(uint16_t port);

#endif
