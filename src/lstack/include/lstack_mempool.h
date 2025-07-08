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

#ifndef __GAZELLE_MEMPOOL_H__
#define __GAZELLE_MEMPOOL_H__

#include <stdlib.h>

#include <rte_common.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include <lwip/lwipopts.h>
#include <lwip/pbuf.h>

#include "common/dpdk_common.h"

/* fix virtio PMD error: Rx scatter is disabled and RxQ mbuf pool object is too small. */
#define DEV_VIRTIO_RX_MBUF_SIZE 1530
/* see hinic_convert_rx_buf_size() */
#define DEV_HINIC_RX_MBUF_SIZE  0x600

/* IP6_HLEN - IP_HLEN: reserve 20 byte to overflow, 
 * if distinguish between IP4_MSS and IP6_MSS. */
#define MBUF_PAYLOAD_SIZE       LWIP_MAX(PBUF_POOL_BUFSIZE, DEV_HINIC_RX_MBUF_SIZE)
#define MBUF_DATA_SIZE          (MBUF_PAYLOAD_SIZE + RTE_PKTMBUF_HEADROOM)
/* DPDK limit ring head-tail distance in rte_ring_init.
 * Max value is RTE_RING_SZ_MASK / HTD_MAX_DEF, RTE_RING_SZ_MASK is 0x7fffffff, HTD_MAX_DEF is 8.
 */
#define MEMPOOL_MAX_NUM         0xfffffff

#define MBUFPOOL_CACHE_NUM      LWIP_MIN(NIC_QUEUE_SIZE_MAX >> 1, RTE_MEMPOOL_CACHE_MAX_SIZE)
#define MBUFPOOL_RESERVE_NUM    (NIC_QUEUE_SIZE_MAX + MBUFPOOL_CACHE_NUM)
#define RPCPOOL_RESERVE_NUM     512

#define MEMPOOL_OPS_NAME            "ring_mt_rts"
#define MEMPOOL_CACHE_NUM           32

#define BUF_CACHE_MIN_NUM           16
#define BUF_CACHE_MAX_NUM           1024
#define BUF_CACHE_WATERSTEP_SHIFT   4   /* 1/16 */
#define BUF_CACHE_WATERSTEP_MIN     4

#define BUF_BULK_MAX_NUM            32

#define MIGRATE_RING_MIN_NUM        (BUF_CACHE_MIN_NUM << 1)

struct buf_cache {
    unsigned size;           /* Size of cache. */
    unsigned mask;           /* Mask (size-1) of cache. */
    unsigned capacity;       /* Usable size of cache */

    unsigned watermark;
    unsigned waterstep;
    unsigned flushthresh;

    unsigned head;
    unsigned tail;

    /* new cache line */
    char pad0 __rte_cache_aligned;
    void *objs[0];
};

static __rte_always_inline
struct buf_cache *buf_cache_create(unsigned count)
{
    struct buf_cache *cache;
    unsigned size;

    size = rte_align32pow2(count);
    if (size < BUF_CACHE_MIN_NUM)
        return NULL;

    cache = (struct buf_cache *)calloc(1, sizeof(struct buf_cache) + sizeof(void *) * size);
    if (cache == NULL)
        return NULL;

    cache->size = size;
    cache->mask = size - 1;
    cache->capacity = size - 1;
    if (cache->capacity > count)
        cache->capacity = count;

    cache->head = 0;
    cache->tail = 0;

    cache->waterstep = cache->size >> BUF_CACHE_WATERSTEP_SHIFT;
    if (cache->waterstep < BUF_CACHE_WATERSTEP_MIN)
        cache->waterstep = BUF_CACHE_WATERSTEP_MIN;
    cache->watermark = cache->waterstep;
    cache->flushthresh = cache->size - cache->waterstep;

    return cache;
}

static __rte_always_inline
void buf_cache_free(struct buf_cache *cache)
{
    if (cache != NULL) {
        free(cache);
    }
}

static __rte_always_inline
unsigned buf_cache_count(const struct buf_cache *cache)
{
    unsigned count = (cache->head - cache->tail) & cache->mask;
    return (count > cache->capacity) ? cache->capacity : count;
}

static __rte_always_inline
unsigned buf_cache_free_count(const struct buf_cache *cache)
{
    return cache->capacity - buf_cache_count(cache);
}

static __rte_always_inline
unsigned buf_cache_get_capacity(const struct buf_cache *cache)
{
    return cache->capacity;
}

static __rte_always_inline
void buf_cache_add_watermark(struct buf_cache *cache)
{
    if (cache->watermark < cache->flushthresh) {
        cache->watermark += cache->waterstep;
    }
}

static __rte_always_inline
void buf_cache_sub_watermark(struct buf_cache *cache)
{
    if (cache->watermark > cache->waterstep) {
        cache->watermark -= cache->waterstep;
    }
}

static __rte_always_inline
void buf_cache_reset_watermark(struct buf_cache *cache)
{
    cache->watermark = cache->waterstep;
}

static __rte_always_inline
void __buf_cache_copy_objs(void ** dst_table, void *const *src_table, unsigned n)
{
    unsigned i;

    for (i = 0; i < (n & ~0x3); i += 4) {
        dst_table[i] = src_table[i];
        dst_table[i + 1] = src_table[i + 1];
        dst_table[i + 2] = src_table[i + 2];
        dst_table[i + 3] = src_table[i + 3];
    }
    switch (n & 0x3) {
    case 3:
        dst_table[i] = src_table[i]; /* fallthrough */
        ++i;
    case 2:
        dst_table[i] = src_table[i]; /* fallthrough */
        ++i;
    case 1:
        dst_table[i] = src_table[i]; /* fallthrough */
    }
}

static __rte_always_inline
unsigned buf_cache_enqueue_bulk(struct buf_cache *cache, void *const *obj_table, unsigned n, unsigned *free_space)
{
    unsigned free_count = buf_cache_free_count(cache);
    unsigned i, idx;

    if (unlikely(n > free_count)) {
        if (free_space != NULL) {
            *free_space = free_count;
        }
        return 0;
    }

    /* refence to __rte_ring_enqueue_elems_64() */
    idx = cache->head & cache->mask;
    if (likely(idx + n < cache->size)) {
        __buf_cache_copy_objs(&cache->objs[idx], obj_table, n);
    } else {
        for (i = 0; idx < cache->size; i++, idx++)
            cache->objs[idx] = obj_table[i];
        /* Start at the beginning */
        for (idx = 0; i < n; i++, idx++)
            cache->objs[idx] = obj_table[i];
    }

    cache->head += n;
    return n;
}

static __rte_always_inline
unsigned buf_cache_dequeue_bulk(struct buf_cache *cache, void **obj_table, unsigned n, unsigned *available)
{
    unsigned count = buf_cache_count(cache);
    unsigned i, idx;

    if (unlikely(n > count)) {
        if (available != NULL) {
            *available = count;
        }
        return 0;
    }

    /* refence to __rte_ring_dequeue_elems_64() */
    idx = cache->tail & cache->mask;
    if (likely(idx + n < cache->size)) {
        __buf_cache_copy_objs(obj_table, &cache->objs[idx], n);
    } else {
        for (i = 0; idx < cache->size; i++, idx++)
            obj_table[i] = cache->objs[idx];
        /* Start at the beginning */
        for (idx = 0; i < n; i++, idx++)
            obj_table[i] = cache->objs[idx];
    }

    cache->tail += n;
    return n;
}

static __rte_always_inline
unsigned buf_cache_push_bulk(struct buf_cache *cache, void *const *obj_table, unsigned n, unsigned *free_space)
{
    unsigned free_count = buf_cache_free_count(cache);
    unsigned top;

    if (unlikely(n > free_count)) {
        if (free_space != NULL) {
            *free_space = free_count;
        }
        return 0;
    }

    top = cache->head;
    __buf_cache_copy_objs(&cache->objs[top], obj_table, n);

    cache->head += n;
    return n;
}

static __rte_always_inline
unsigned buf_cache_pop_bulk(struct buf_cache *cache, void **obj_table, unsigned n, unsigned *available)
{
    unsigned count = buf_cache_count(cache);
    unsigned top;

    if (unlikely(n > count)) {
        if (available != NULL) {
            *available = count;
        }
        return 0;
    }

    top = cache->head;
    __buf_cache_copy_objs(obj_table, &cache->objs[top - n], n);

    cache->head -= n;
    return n;
}


struct mem_stack {
    struct rte_mempool *rpc_pool;

    struct rte_mempool *mbuf_pool;
    struct rte_mempool_cache *mbuf_mpcache;
    unsigned migrate_watermark;
};

struct mem_thread {
    int stack_id;

    struct buf_cache *rpc_cache;

    struct buf_cache *mbuf_cache;
    struct rte_ring *mbuf_migrate_ring;

    char pad0 __rte_cache_aligned;  /* new cache line */

    unsigned stk_migrate_count;
} __rte_cache_aligned;

void mem_stack_pool_free(int stack_id);
int mem_stack_pool_init(int stack_id, unsigned numa_id);
int mem_stack_mpcache_init(int stack_id, unsigned cpu_id);

int mem_thread_manager_init(void);
bool mem_thread_ignore_flush_intr(void);
void mem_thread_cache_free(struct mem_thread *mt);
int mem_thread_cache_init(struct mem_thread *mt, int stack_id);

struct rte_mempool *mem_get_mbuf_pool(int stack_id);
struct rte_mempool *mem_get_rpc_pool(int stack_id);
unsigned mem_stack_mbuf_pool_count(int stack_id);
unsigned mem_stack_rpc_pool_count(int stack_id);

void *mem_get_rpc(int stack_id, bool reserve);
void mem_put_rpc(void *obj);

struct mem_thread *mem_thread_migrate_get(int stack_id);
void mem_mbuf_migrate_enqueue(struct mem_thread *mt, unsigned n);
void mem_mbuf_migrate_dequeue(struct mem_thread *mt);

unsigned mem_get_mbuf_bulk(int stack_id, struct rte_mbuf **mbuf_table, unsigned n, bool reserve);
void mem_put_mbuf_bulk(struct rte_mbuf *const *mbuf_table, unsigned n);

unsigned mem_get_pbuf_bulk(int stack_id, struct pbuf **pbuf_table, unsigned n, bool reserve);
void mem_preput_pbuf(struct pbuf *p);
void mem_put_pbuf_bulk(struct pbuf *const *pbuf_table, unsigned n);
void mem_put_pbuf_list_bulk(struct pbuf *const *pbuf_table, unsigned n);

struct pbuf *mem_get_pbuf(int stack_id, bool reserve);
void mem_put_pbuf(struct pbuf *p);

unsigned mem_extcache_get_pbuf_bulk(int stack_id, struct pbuf **pbuf_table, unsigned n, bool reserve, 
    struct pbuf **extcache_list);
struct pbuf *mem_extcache_get_pbuf(int stack_id, bool reserve, struct pbuf **extcache_list);
void mem_extcache_put_pbuf(struct pbuf *h, struct pbuf *t, struct pbuf **extcache_list);
void mem_extcache_flush_pbuf(struct pbuf **extcache_list);

void mem_init_pbuf(struct pbuf *p, pbuf_layer layer, uint16_t tot_len, uint16_t len, pbuf_type type);


#endif /* __GAZELLE_MEMPOOL_H__ */