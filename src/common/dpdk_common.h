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

#ifndef __GAZELLE_DPDK_COMMON_H__
#define __GAZELLE_DPDK_COMMON_H__

#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "gazelle_opt.h"

#define GAZELLE_KNI_NAME                     "kni"   // will be removed during dpdk update

/* time_stamp time_stamp_vaid_check . align 8 */
#define PTR_TO_PRIVATE(mbuf)    RTE_PTR_ADD(mbuf, sizeof(struct rte_mbuf))

/* Layout:
 * | rte_mbuf | pbuf | custom_free_function | tcp_seg | payload |
 **/
struct pbuf;
static inline struct rte_mbuf *pbuf_to_mbuf(struct pbuf *p)
{
    return ((struct rte_mbuf *)(void *)((uint8_t *)(p) - sizeof(struct rte_mbuf) - GAZELLE_MBUFF_PRIV_SIZE));
}
static inline struct pbuf_custom *mbuf_to_pbuf(struct rte_mbuf *m)
{
    return ((struct pbuf_custom *)((uint8_t *)(m) + sizeof(struct rte_mbuf) + GAZELLE_MBUFF_PRIV_SIZE));
}

/* NOTE!!! magic code, even the order.
*  I wrote it carefully, and check the assembly. for example, there is 24 ins in A72,
*  and if there is no cache miss, it only take less than 20 cycle(store pipe is the bottleneck).
*/
static __rte_always_inline void copy_mbuf(struct rte_mbuf *dst, struct rte_mbuf *src)
{
    /* In the direction of tx, data is copied from lstack to ltran. It is necessary to judge whether
       the length of data transmitted from lstack has been tampered with to prevent overflow
    */
    uint16_t data_len = src->data_len;
    if (data_len > RTE_MBUF_DEFAULT_BUF_SIZE)
        return;

    dst->ol_flags = src->ol_flags;
    dst->tx_offload = src->tx_offload;
    // there is buf_len in rx_descriptor_fields1, copy it is dangerous acturely. 16 : mbuf desc size
    rte_memcpy((uint8_t *)dst->rx_descriptor_fields1, (const uint8_t *)src->rx_descriptor_fields1, 16);

    uint8_t *dst_data = rte_pktmbuf_mtod(dst, void*);
    uint8_t *src_data = rte_pktmbuf_mtod(src, void*);
    rte_memcpy(dst_data, src_data, data_len);

    // copy private date.
    dst_data = (uint8_t *)PTR_TO_PRIVATE(dst);
    src_data = (uint8_t *)PTR_TO_PRIVATE(src);
    rte_memcpy(dst_data, src_data, GAZELLE_MBUFF_PRIV_SIZE);
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
void dpdk_kni_release(void);

struct rte_eth_conf;
struct rte_eth_dev_info;
void eth_params_checksum(struct rte_eth_conf *conf, struct rte_eth_dev_info *dev_info);

/*
    gazelle custom rte ring interface
    lightweight ring reduce atomic and smp_mb.
    only surpport single-consumers or the single-consumer.
 */
static __rte_always_inline uint32_t gazelle_light_ring_enqueue_busrt(struct rte_ring *r, void **obj_table, uint32_t n)
{
    uint32_t cons = __atomic_load_n(&r->cons.tail, __ATOMIC_ACQUIRE);
    uint32_t prod = r->prod.tail;
    uint32_t free_entries = r->capacity + cons - prod;

    if (n > free_entries) {
        return 0;
    }

    __rte_ring_enqueue_elems(r, prod, obj_table, sizeof(void *), n);

    __atomic_store_n(&r->prod.tail, prod + n, __ATOMIC_RELEASE);

    return n;
}

static __rte_always_inline uint32_t gazelle_light_ring_dequeue_burst(struct rte_ring *r, void **obj_table, uint32_t n)
{
    uint32_t prod = __atomic_load_n(&r->prod.tail, __ATOMIC_ACQUIRE);
    uint32_t cons = r->cons.tail;
    uint32_t entries = prod - cons;

    if (n > entries) {
        n = entries;
    }

    if (n == 0) {
        return 0;
    }

    __rte_ring_dequeue_elems(r, cons, obj_table, sizeof(void *), n);

    __atomic_store_n(&r->cons.tail, cons + n, __ATOMIC_RELEASE);

    return n;
}

/*
    gazelle custom rte ring interface
    one thread enqueue and dequeue, other thread read object use and object still in queue.
    so malloc and free in same thread. only surpport single-consumers or the single-consumer.

    cons.tail            prod.tail                prod.head                 cons.head
    gazelle_ring_sp_enqueue: cons.head-->> cons.tal,  enqueue object
    gazelle_ring_sc_dequeue: cons.tal -->> prod.tail, dequeue object
    gazelle_ring_read:       prod.head-->> cons.head, read object, prod.head = prod.tail + N
    gazelle_ring_read_over:  prod.tail  =  prod.head, update prod.tail
 */
static __rte_always_inline uint32_t gazelle_ring_sp_enqueue(struct rte_ring *r, void **obj_table, uint32_t n)
{
    uint32_t head = __atomic_load_n(&r->cons.head, __ATOMIC_ACQUIRE);
    uint32_t tail = r->cons.tail;

    uint32_t entries = r->capacity + tail - head;
    if (n > entries) {
        return 0;
    }

    __rte_ring_enqueue_elems(r, head, obj_table, sizeof(void *), n);

    __atomic_store_n(&r->cons.head, head + n, __ATOMIC_RELEASE);

    return n;
}

static __rte_always_inline uint32_t gazelle_ring_sc_dequeue(struct rte_ring *r, void **obj_table, uint32_t n)
{
    uint32_t prod = __atomic_load_n(&r->prod.tail, __ATOMIC_ACQUIRE);
    uint32_t cons = r->cons.tail;

    uint32_t entries = prod - cons;
    if (n > entries) {
        n = entries;
    }
    if (unlikely(n == 0)) {
        return 0;
    }

    __rte_ring_dequeue_elems(r, cons, obj_table, sizeof(void *), n);

    __atomic_store_n(&r->cons.tail, cons + n, __ATOMIC_RELEASE);

    return n;
}

static __rte_always_inline uint32_t gazelle_ring_read(struct rte_ring *r, void **obj_table, uint32_t n)
{
    uint32_t cons = __atomic_load_n(&r->cons.head, __ATOMIC_ACQUIRE);
    uint32_t prod = r->prod.head;

    const uint32_t entries = cons - prod;
    if (n > entries) {
        n = entries;
    }
    if (unlikely(n == 0)) {
        return 0;
    }

    __rte_ring_dequeue_elems(r, prod, obj_table, sizeof(void *), n);

    r->prod.head = prod + n;

    return n;
}

static __rte_always_inline void gazelle_ring_read_over(struct rte_ring *r)
{
    __atomic_store_n(&r->prod.tail, r->prod.head, __ATOMIC_RELEASE);
}

static __rte_always_inline uint32_t gazelle_ring_readover_count(struct rte_ring *r)
{
    rte_smp_rmb();
    return r->prod.tail - r->cons.tail;
}
static __rte_always_inline uint32_t gazelle_ring_readable_count(const struct rte_ring *r)
{
    rte_smp_rmb();
    return r->cons.head - r->prod.head;
}

static __rte_always_inline uint32_t gazelle_ring_count(const struct rte_ring *r)
{
    rte_smp_rmb();
    return r->cons.head - r->cons.tail;
}
static __rte_always_inline uint32_t gazelle_ring_free_count(const struct rte_ring *r)
{
    return r->capacity - gazelle_ring_count(r);
}
#endif
