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

#ifndef __MBOX_RING_H__
#define __MBOX_RING_H__

#include <rte_malloc.h>
#include <rte_ring.h>

#include <lwip/dpdk_version.h>
#include <lwip/arch/sys_arch.h>

#include "common/dpdk_common.h"
#include "lstack_dpdk.h"
#include "lstack_mempool.h"
#include "lstack_cfg.h"

/* Optimize performance of creating ring. */
static inline
struct rte_ring *rte_ring_create_fast(const char *name, unsigned size, unsigned flags)
{
    ssize_t ring_size;
    char ring_name[RTE_MEMZONE_NAMESIZE] = {0};
    struct rte_ring *ring;

    ring_size = rte_ring_get_memsize(size);
    if (ring_size < 0) {
        RTE_LOG(ERR, EAL, "rte_ring_get_memszie failed\n");
        return NULL;
    }

    /*
     * rte_ring_create is not used because it calls memzone_lookup_thread_unsafe function
     * time consuming when there are many rings
     */
    ring = rte_malloc_socket(NULL, ring_size, RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (ring == NULL) {
        RTE_LOG(ERR, EAL, "cannot create rte_ring for mbox\n");
        return NULL;
    }

    if (snprintf(ring_name, sizeof(ring_name), "%s""%"PRIXPTR, name, (uintptr_t)ring) < 0) {
        rte_free(ring);
        RTE_LOG(ERR, EAL, "snprintf failed\n");
        return NULL;
    }

    if (rte_ring_init(ring, ring_name, size, flags) != 0) {
        rte_free(ring);
        RTE_LOG(ERR, EAL, "cannot init rte_ring for mbox\n");
        return NULL;
    }

    return ring;
}

static inline
void rte_ring_free_fast(struct rte_ring *ring)
{
    rte_free(ring);
}


static inline
void mbox_ring_common_free(struct mbox_ring *mr)
{
    void *obj;

    if (mr->private_data_free_fn != NULL && mr->private_data != NULL) {
        mr->private_data_free_fn(mr);
        mr->private_data_free_fn = NULL;
        mr->private_data = NULL;
    }

    obj = mr->ops->pop_tail(mr, NULL);
    if (obj != NULL)
        mr->obj_free_fn(mr, obj, true);

    if (mr->ring != NULL) {
        if (mr->flags & MBOX_FLAG_RECV)
            mr->ops->recv_finish_burst(mr);
        while (true) {
            if (mr->ops->dequeue_burst(mr, &obj, 1) == 0)
                break;
            mr->obj_free_fn(mr, obj, false);
        }
    }
}

extern void sockio_mbox_set_func(struct mbox_ring *mr);
static inline
void mbox_ring_common_init(struct mbox_ring *mr)
{
    mr->stk_queued_num = 0;

    mr->app_free_count = 0;
    mr->app_queued_num = 0;
    mr->app_tail_left  = 0;
    mr->app_recvd_len  = 0;

    sockio_mbox_set_func(mr);
}

/* single thread */
static inline
int st_ring_create(struct mbox_ring *mr, const char *name, unsigned count)
{
    mbox_ring_common_init(mr);

    mr->ops = &g_mbox_rtc_default_ops;
    mr->st_obj = NULL;

    mr->ring = rte_ring_create_fast(name, count, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (mr->ring == NULL) {
        return -ENOMEM;
    }
    return 0;
}

static inline
void st_ring_destroy(struct mbox_ring *mr)
{
    mbox_ring_common_free(mr);

    mr->ops = NULL;
    mr->st_obj = NULL;
    if (mr->ring != NULL) {
        rte_ring_free_fast(mr->ring);
        mr->ring = NULL;
    }
}

static inline
unsigned st_ring_get_capacity(const struct mbox_ring *mr)
{
    return mr->ring->capacity;
}

static inline
unsigned st_ring_count(const struct mbox_ring *mr)
{
    // return rte_ring_count(mr->ring);
    struct rte_ring *r = mr->ring;
    uint32_t prod_tail = r->prod.tail;
    uint32_t cons_head = r->cons.head;
    uint32_t count = (prod_tail - cons_head) & r->mask;
    return (count > r->capacity) ? r->capacity : count;
}

static inline
unsigned st_ring_free_count(const struct mbox_ring *mr)
{
    return st_ring_get_capacity(mr) - st_ring_count(mr);
}

static inline
unsigned st_ring_enqueue_burst_start(struct mbox_ring *mr, void *const *obj_table, unsigned n)
{
    struct rte_ring *r = mr->ring;
    uint32_t prod_head, cons_tail;
    uint32_t free_entries;

    prod_head = r->prod.head;
    cons_tail = r->cons.tail;

    free_entries = r->capacity + cons_tail - prod_head;
    if (unlikely(free_entries == 0))
        return 0;
    if (n > free_entries)
        n = free_entries;

    r->prod.head = prod_head + n;

    __rte_ring_enqueue_elems(r, prod_head, obj_table, sizeof(void *), n);
    return n;
}

static inline
void st_ring_enqueue_burst_finish(struct mbox_ring *mr)
{
    mr->ring->prod.tail = mr->ring->prod.head;
}

static inline
unsigned st_ring_dequeue_burst_start(struct mbox_ring *mr, void **obj_table, unsigned n)
{
    struct rte_ring *r = mr->ring;
    uint32_t cons_head, prod_tail;
    uint32_t entries;

    cons_head = r->cons.head;
    prod_tail = r->prod.tail;

    entries = prod_tail - cons_head;
    if (unlikely(entries == 0))
        return 0;
    if (n > entries)
        n = entries;

    r->cons.head = cons_head + n;

    __rte_ring_dequeue_elems(r, cons_head, obj_table, sizeof(void *), n);
    return n;
}

static inline
void st_ring_dequeue_burst_finish(struct mbox_ring *mr)
{
    mr->ring->cons.tail = mr->ring->cons.head;
}

static inline
unsigned st_ring_enqueue_burst(struct mbox_ring *mr, void *const *obj_table, unsigned n)
{
    n = st_ring_enqueue_burst_start(mr, obj_table, n);
    st_ring_enqueue_burst_finish(mr);
    return n;
}

static inline
unsigned st_ring_dequeue_burst(struct mbox_ring *mr, void **obj_table, unsigned n)
{
    n = st_ring_dequeue_burst_start(mr, obj_table, n);
    st_ring_dequeue_burst_finish(mr);
    return n;
}

static inline
void *st_ring_read_tail(const struct mbox_ring *mr)
{
    return mr->st_obj;
}

static inline
void st_ring_push_tail(struct mbox_ring *mr, void *obj)
{
    mr->st_obj = obj;
}

static inline
void *st_ring_pop_tail(struct mbox_ring *mr, void *expect)
{
    expect = mr->st_obj;
    mr->st_obj = NULL;
    return expect;
}

static inline
void st_ring_ops_init(struct mbox_ring_ops *ops)
{
    ops->create         = st_ring_create;
    ops->destroy        = st_ring_destroy;

    ops->get_capacity   = st_ring_get_capacity;
    ops->count          = st_ring_count;
    ops->free_count     = st_ring_free_count;

    ops->enqueue_burst  = st_ring_enqueue_burst;
    ops->dequeue_burst  = st_ring_dequeue_burst;

    ops->recv_count     = st_ring_count;
    ops->recv_start_burst  = st_ring_dequeue_burst_start;
    ops->recv_finish_burst = st_ring_dequeue_burst_finish;

    ops->read_tail      = st_ring_read_tail;
    ops->push_tail      = st_ring_push_tail;
    ops->pop_tail       = st_ring_pop_tail;
}


/* multi thread */
static inline
int mt_ring_create(struct mbox_ring *mr, const char *name, unsigned count)
{
    mbox_ring_common_init(mr);

    if ((mr->flags & MBOX_FLAG_TCP) && (mr->flags & MBOX_FLAG_SEND)) {
        mr->ops = &g_mbox_rtw_append_ops;
        rte_atomic64_init(&mr->mt_obj);
    } else {
        mr->ops = &g_mbox_rtw_default_ops;
        mr->st_obj = NULL;
    }
    if (mr->flags & MBOX_FLAG_RECV) {
        if (get_global_cfg_params()->mem_async_mode) {
            mr->flags |= MBOX_FLAG_PEEK;
            mr->ops = &g_mbox_rtw_peek_ops;
            mr->ops->create(mr, name, count);
        }
    }

    mr->ring = rte_ring_create_fast(name, count, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (mr->ring == NULL) {
        return -ENOMEM;
    }
    return 0;
}

static inline
void mt_ring_destroy(struct mbox_ring *mr)
{
    if (mr->flags & MBOX_FLAG_PEEK) {
        mr->ops->destroy(mr);
    }
    mbox_ring_common_free(mr);

    mr->ops = NULL;
    if ((mr->flags & MBOX_FLAG_TCP) && (mr->flags & MBOX_FLAG_SEND)) {
        rte_atomic64_clear(&mr->mt_obj);
    } else {
        mr->st_obj = NULL;
    }

    if (mr->ring != NULL) {
        rte_ring_free_fast(mr->ring);
        mr->ring = NULL;
    }
}

static inline
unsigned mt_ring_get_capacity(const struct mbox_ring *mr)
{
    return mr->ring->capacity;
}

static inline
unsigned mt_ring_count(const struct mbox_ring *mr)
{
    // return rte_ring_count(mr->ring);
    struct rte_ring *r = mr->ring;
    uint32_t prod_tail = r->prod.tail;
    uint32_t cons_head = r->cons.head;
    uint32_t count = (prod_tail - cons_head) & r->mask;
    return (count > r->capacity) ? r->capacity : count;
}

static inline
unsigned mt_ring_free_count(const struct mbox_ring *mr)
{
    return mt_ring_get_capacity(mr) - mt_ring_count(mr);
}

static inline
unsigned mt_ring_enqueue_burst_start(struct mbox_ring *mr, void *const *obj_table, unsigned n)
{
    struct rte_ring *r = mr->ring;
    uint32_t prod_head, cons_tail;
    uint32_t free_entries;

    prod_head = r->prod.head;
    cons_tail = __atomic_load_n(&r->cons.tail, __ATOMIC_ACQUIRE);

    free_entries = r->capacity + cons_tail - prod_head;
    if (unlikely(free_entries == 0))
        return 0;
    if (n > free_entries)
        n = free_entries;

    r->prod.head = prod_head + n;

    __rte_ring_enqueue_elems(r, prod_head, obj_table, sizeof(void *), n);
    return n;
}

static inline
void mt_ring_enqueue_burst_finish(struct mbox_ring *mr)
{
    __atomic_store_n(&mr->ring->prod.tail, mr->ring->prod.head, __ATOMIC_RELEASE);
}

static inline
unsigned mt_ring_dequeue_burst_start(struct mbox_ring *mr, void ** obj_table, unsigned n)
{
    struct rte_ring *r = mr->ring;
    uint32_t cons_head, prod_tail;
    uint32_t entries;

    cons_head = r->cons.head;
    prod_tail = __atomic_load_n(&r->prod.tail, __ATOMIC_ACQUIRE);

    entries = prod_tail - cons_head;
    if (unlikely(entries == 0))
        return 0;
    if (n > entries)
        n = entries;

    r->cons.head = cons_head + n;

    __rte_ring_dequeue_elems(r, cons_head, obj_table, sizeof(void *), n);
    return n;
}

static inline
void mt_ring_dequeue_burst_finish(struct mbox_ring *mr)
{
    __atomic_store_n(&mr->ring->cons.tail, mr->ring->cons.head, __ATOMIC_RELEASE);
}

static inline
unsigned mt_ring_enqueue_burst(struct mbox_ring *mr, void *const *obj_table, unsigned n)
{
    // return rte_ring_sp_enqueue_burst(mr->ring, obj_table, n, NULL);
    n = mt_ring_enqueue_burst_start(mr, obj_table, n);
    mt_ring_enqueue_burst_finish(mr);
    return n;
}

static inline
unsigned mt_ring_dequeue_burst(struct mbox_ring *mr, void **obj_table, unsigned n)
{
    // return rte_ring_sc_dequeue_burst(mr->ring, obj_table, n, NULL);
    n = mt_ring_dequeue_burst_start(mr, obj_table, n);
    mt_ring_dequeue_burst_finish(mr);
    return n;
}

static inline
void *mt_ring_read_tail(const struct mbox_ring *mr)
{
    return (void *)rte_atomic64_read((rte_atomic64_t *)&mr->mt_obj);
}

static inline
void mt_ring_push_tail(struct mbox_ring *mr, void *obj)
{
    rte_atomic64_set(&mr->mt_obj, (uint64_t )obj);
}

static inline
void *mt_ring_pop_tail(struct mbox_ring *mr, void *expect)
{
    if (expect == NULL) {
        expect = (void *)rte_atomic64_exchange((volatile uint64_t *)&mr->mt_obj.cnt, 
                                               (uint64_t)NULL);
        return expect;
    }

    int ret = rte_atomic64_cmpset((volatile uint64_t *)&mr->mt_obj.cnt, 
                                  (uint64_t)expect, (uint64_t)NULL);
    if (ret == 0)   /* mt_obj != expect, cmpset failed */
        return NULL;
    return expect;
}

static inline
void mt_ring_ops_init(struct mbox_ring_ops *ops)
{
    ops->create         = mt_ring_create;
    ops->destroy        = mt_ring_destroy;

    ops->get_capacity   = mt_ring_get_capacity;
    ops->count          = mt_ring_count;
    ops->free_count     = mt_ring_free_count;

    ops->enqueue_burst  = mt_ring_enqueue_burst;
    ops->dequeue_burst  = mt_ring_dequeue_burst;

    ops->recv_count     = mt_ring_count;
    ops->recv_start_burst  = mt_ring_dequeue_burst_start;
    ops->recv_finish_burst = mt_ring_dequeue_burst_finish;

    ops->read_tail      = mt_ring_read_tail;
    ops->push_tail      = mt_ring_push_tail;
    ops->pop_tail       = mt_ring_pop_tail;
}

/* multi thread & peek */
static inline
int pk_ring_create(struct mbox_ring *mr, const char *name, unsigned count)
{
    return 0;
}

static inline
void pk_ring_destroy(struct mbox_ring *mr)
{
    void *obj;
    if (mr->ring != NULL) {
        while (mr->ops->recv_start_burst(mr, &obj, 1) > 0) { }
        mr->ops->recv_finish_burst(mr);
    }
    return;
}

extern void sockio_peek_recv_free(struct mbox_ring *mr, unsigned n);
static inline
unsigned pk_ring_enqueue_burst(struct mbox_ring *mr, void *const *obj_table, unsigned n)
{
    n = gazelle_ring_sp_enqueue(mr->ring, obj_table, n);
    if (mr->flags & MBOX_FLAG_RECV)
        sockio_peek_recv_free(mr, n);
    return n;
}

static inline
unsigned pk_ring_dequeue_burst(struct mbox_ring *mr, void **obj_table, unsigned n)
{
    return gazelle_ring_sc_dequeue(mr->ring, obj_table, n);
}

static inline
unsigned pk_ring_peek_start_burst(struct mbox_ring *mr, void **obj_table, unsigned n)
{
    return gazelle_ring_read(mr->ring, obj_table, n);
}
static inline
void pk_ring_peek_finish_burst(struct mbox_ring *mr)
{
    gazelle_ring_read_over(mr->ring);
}

static inline
unsigned pk_ring_get_capacity(const struct mbox_ring *mr)
{
    return mr->ring->capacity;
}
static inline
unsigned pk_ring_count(const struct mbox_ring *mr)
{
    return gazelle_ring_count(mr->ring);
}
static inline
unsigned pk_ring_free_count(const struct mbox_ring *mr)
{
    return gazelle_ring_free_count(mr->ring);
}

static inline
unsigned pk_ring_peek_start_count(const struct mbox_ring *mr)
{
    return gazelle_ring_readable_count(mr->ring);
}
static inline
unsigned pk_ring_peek_finish_count(const struct mbox_ring *mr)
{
    return gazelle_ring_readover_count(mr->ring);
}

static inline
void pk_ring_ops_init(struct mbox_ring_ops *ops)
{
    ops->create         = pk_ring_create;
    ops->destroy        = pk_ring_destroy;

    ops->get_capacity   = pk_ring_get_capacity;
    ops->count          = pk_ring_count;
    ops->free_count     = pk_ring_free_count;

    ops->enqueue_burst  = pk_ring_enqueue_burst;
    ops->dequeue_burst  = pk_ring_dequeue_burst;

    ops->recv_count     = pk_ring_peek_start_count;
    ops->recv_start_burst  = pk_ring_peek_start_burst;
    ops->recv_finish_burst = pk_ring_peek_finish_burst;

    ops->read_tail      = st_ring_read_tail;
    ops->push_tail      = st_ring_push_tail;
    ops->pop_tail       = st_ring_pop_tail;
}

static inline
void mbox_ring_ops_init(void)
{
    st_ring_ops_init(&g_mbox_rtc_default_ops);

    mt_ring_ops_init(&g_mbox_rtw_append_ops);
    mt_ring_ops_init(&g_mbox_rtw_default_ops);
    /* rtw udp don't need to append data.*/
    g_mbox_rtw_default_ops.read_tail = st_ring_read_tail;
    g_mbox_rtw_default_ops.pop_tail  = st_ring_pop_tail;
    g_mbox_rtw_default_ops.push_tail = st_ring_push_tail;

    pk_ring_ops_init(&g_mbox_rtw_peek_ops);

    if (get_global_cfg_params()->stack_mode_rtc) {
        g_mbox_default_ops = &g_mbox_rtc_default_ops;
    } else {
        g_mbox_default_ops = &g_mbox_rtw_default_ops;
    }
}

#endif /* __MBOX_RING_H__ */
