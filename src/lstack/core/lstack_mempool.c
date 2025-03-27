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

#include <securec.h>

#include <rte_errno.h>
#include <lwip/arch/sys_arch.h>

#include "lstack_mempool.h"
#include "lstack_log.h"
#include "lstack_cfg.h"
#include "common/dpdk_common.h"
#include "lstack_dpdk.h"
#include "lstack_protocol_stack.h"
#include "lstack_unistd.h"

#define MEM_THREAD_FLUSH_SIG            (SIGRTMIN + 11)
#define MEM_THREAD_MANAGER_FLUSH_MS     100
#define MEM_THREAD_MANAGER_FREE_S       2
#define MEM_THREAD_MANAGER_FREE_MAX     64

struct mem_thread_manager {
    struct list_node mt_work_list;
    struct list_node mt_free_list;
    rte_spinlock_t list_lock;
    uint32_t flush_time;
};

struct mem_thread_group {
    int tid;
    pthread_t thread;
    struct list_node mt_node;
    struct mem_thread mt_array[PROTOCOL_STACK_MAX];

    bool used_flag;
    uint32_t used_time;
};

static struct mem_stack g_mem_stack_group[PROTOCOL_STACK_MAX] = {0};
static PER_THREAD struct mem_thread_group *g_mem_thread_group = NULL;
static struct mem_thread_manager g_mem_thread_manager = {0};

static __rte_always_inline
struct mem_stack *mem_stack_get(int stack_id)
{
    return &g_mem_stack_group[stack_id];
}

struct rte_mempool *mem_get_mbuf_pool(int stack_id)
{
    return g_mem_stack_group[stack_id].mbuf_pool;
}

struct rte_mempool *mem_get_rpc_pool(int stack_id)
{
    return g_mem_stack_group[stack_id].rpc_pool;
}

static inline bool mem_thread_group_in_used(const struct mem_thread_group *mt_grooup, uint32_t timeout)
{
    return mt_grooup->used_flag || 
           (sys_now() - mt_grooup->used_time < timeout);
}

static inline void mem_thread_group_used(void)
{
    g_mem_thread_group->used_flag = true;
    g_mem_thread_group->used_time = sys_now();
}

static inline void mem_thread_group_done(void)
{
    g_mem_thread_group->used_flag = false;
}

static void mem_thread_cache_flush(struct mem_thread *mt);
static unsigned mem_thread_cache_count(const struct mem_thread *mt);
static void mem_thread_group_action_flush(int signum)
{
    struct mem_thread *mt;
    int stack_id;

    if (g_mem_thread_group == NULL)
        return;
    if (mem_thread_group_in_used(g_mem_thread_group, MEM_THREAD_MANAGER_FLUSH_MS))
        return;

    for (stack_id = 0; stack_id < PROTOCOL_STACK_MAX; stack_id++) {
        mt = &g_mem_thread_group->mt_array[stack_id];
        mem_thread_cache_flush(mt);
    }
}

static int mem_thread_group_register_flush(void)
{
    sighandler_t handler;
    handler = signal(MEM_THREAD_FLUSH_SIG, mem_thread_group_action_flush);
    if (handler == SIG_ERR) {
        LSTACK_LOG(ERR, LSTACK, "signal failed\n");
        return -1;
    }
    pthread_unblock_sig(MEM_THREAD_FLUSH_SIG);
    return 0;
}

static inline void mem_thread_group_notify_flush(const struct mem_thread_group *mt_group, uint32_t timeout)
{
    const struct mem_thread *mt;
    int stack_id;
    unsigned count = 0;

    if (mem_thread_group_in_used(mt_group, timeout))
        return;

    for (stack_id = 0; stack_id < PROTOCOL_STACK_MAX; stack_id++) {
        mt = &mt_group->mt_array[stack_id];
        count += mem_thread_cache_count(mt);
    }
    if (count == 0) {
        return;
    }

    if (pthread_kill(mt_group->thread, MEM_THREAD_FLUSH_SIG) != 0) {
        LSTACK_LOG(ERR, LSTACK, "pthread_kill tid %d failed\n", mt_group->tid);
    }
}

static inline bool mem_thread_group_exist(const struct mem_thread_group *mt_group)
{
    if (pthread_tryjoin_np(mt_group->thread, NULL) == 0)
        return false;
    return true;
}

static void mem_thread_manager_add_work(struct mem_thread_group *mt_group)
{
    rte_spinlock_lock(&g_mem_thread_manager.list_lock);
    list_add_node(&mt_group->mt_node, &g_mem_thread_manager.mt_work_list);
    rte_spinlock_unlock(&g_mem_thread_manager.list_lock);
}

static void mem_thread_group_free(struct mem_thread_group *mt_group)
{
    struct mem_thread *mt;
    int stack_id;

    for (stack_id = 0; stack_id < PROTOCOL_STACK_MAX; stack_id++) {
        mt = &mt_group->mt_array[stack_id];
        mem_thread_cache_free(mt);
    }
    free(mt_group);
    return;
}

static int mem_thread_group_init(int stack_id)
{
    struct mem_thread *mt;

    if (rte_lcore_id() < RTE_MAX_LCORE) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, lcore_id %u is invalid\n", rte_gettid(), rte_lcore_id());
        return -1;
    }

    if (g_mem_thread_group == NULL) {
        g_mem_thread_group = (struct mem_thread_group *)calloc(1, sizeof(struct mem_thread_group));
        if (g_mem_thread_group == NULL) {
            LSTACK_LOG(ERR, LSTACK, "alloc mem_thread_group failed, stack_id %d\n", stack_id);
            return -1;
        }
        mem_thread_group_register_flush();

        g_mem_thread_group->tid = rte_gettid();
        g_mem_thread_group->thread = pthread_self();
        list_init_node(&g_mem_thread_group->mt_node);
        mem_thread_manager_add_work(g_mem_thread_group);
    }

    mt = &g_mem_thread_group->mt_array[stack_id];
    if (mem_thread_cache_init(mt, stack_id) != 0) {
        LSTACK_LOG(ERR, LSTACK, "mem_thread_cache_init failed, stack_id %d\n", stack_id);
        return -1;
    }

    return 0;
}

static inline struct mem_thread *mem_thread_group_get(int stack_id)
{
    struct mem_thread *mt;

    if (likely(g_mem_thread_group != NULL)) {
        mt = &g_mem_thread_group->mt_array[stack_id];
        if (likely(mt->mbuf_cache != NULL))
            return mt;
    }

    if (mem_thread_group_init(stack_id) != 0) {
        LSTACK_LOG(ERR, LSTACK, "mem_thread_group_init failed, stack_id %d\n", stack_id);
        return NULL;
    }
    mt = &g_mem_thread_group->mt_array[stack_id];
    return mt;
}

static void mem_thread_manager_flush_all(void)
{
    struct list_node *node, *next;
    struct mem_thread_group *mt_group;
    uint32_t now = sys_now();

    rte_spinlock_lock(&g_mem_thread_manager.list_lock);

    if (now - g_mem_thread_manager.flush_time < MEM_THREAD_MANAGER_FLUSH_MS) {
        rte_spinlock_unlock(&g_mem_thread_manager.list_lock);
        return;
    }
    g_mem_thread_manager.flush_time = now;

    list_for_each_node(node, next, &g_mem_thread_manager.mt_work_list) {
        mt_group = container_of(node, struct mem_thread_group, mt_node);
        /* skip myself */
        if (mt_group == g_mem_thread_group)
            continue;
        mem_thread_group_notify_flush(mt_group, MEM_THREAD_MANAGER_FLUSH_MS);
    }

    rte_spinlock_unlock(&g_mem_thread_manager.list_lock);
}

static void *mem_thread_manager_thread(void *arg)
{
    struct list_node *node, *next;
    struct mem_thread_group *mt_group;
    unsigned count = 0;

    rte_spinlock_init(&g_mem_thread_manager.list_lock);
    list_init_head(&g_mem_thread_manager.mt_work_list);
    list_init_head(&g_mem_thread_manager.mt_free_list);
    g_mem_thread_manager.flush_time = sys_now();

    while(true) {
        sleep(MEM_THREAD_MANAGER_FREE_S);

        rte_spinlock_lock(&g_mem_thread_manager.list_lock);

        list_for_each_node(node, next, &g_mem_thread_manager.mt_free_list) {
            mt_group = container_of(node, struct mem_thread_group, mt_node);
            list_del_node(node);
            mem_thread_group_free(mt_group);
        }

        list_for_each_node(node, next, &g_mem_thread_manager.mt_work_list) {
            count++;
            if (count > MEM_THREAD_MANAGER_FREE_MAX) {
                /* move list head after the current node, 
                 * and start traversing from this node next time */
                list_del_node(&g_mem_thread_manager.mt_work_list);
                list_add_node(&g_mem_thread_manager.mt_work_list, node);
                break;
            }

            mt_group = container_of(node, struct mem_thread_group, mt_node);
            if (mem_thread_group_exist(mt_group)) {
                mem_thread_group_notify_flush(mt_group, MEM_THREAD_MANAGER_FREE_S * MS_PER_S);
                continue;
            }
            list_del_node(node);
            list_add_node(node, &g_mem_thread_manager.mt_free_list);
        }

        rte_spinlock_unlock(&g_mem_thread_manager.list_lock);
    }

    return NULL;
}

int mem_thread_manager_init(void)
{
    return thread_create("gzmempool", 0, mem_thread_manager_thread, NULL);
}

static inline struct mem_thread *mem_thread_get(int stack_id)
{
    /* stack thread uses mbufpool_cache instead of buf_cache */
    if (get_protocol_stack() != NULL)
        return NULL;

#if MEMP_DEBUG
    if (RTE_PER_LCORE(_lcore_id) < RTE_MAX_LCORE) {
        LWIP_DEBUGF(MEMP_DEBUG | LWIPGZ_LOG_FATAL, ("tid %d has invalid rte_lcore_id %u !\n", 
            rte_gettid(), RTE_PER_LCORE(_lcore_id)));
        return NULL;
    }
#endif /* MEMP_DEBUG */

    return mem_thread_group_get(stack_id);
}

struct mem_obj_ops {
    void (*init)(struct rte_mempool *mp, void *arg, void *obj, unsigned obj_idx);
    unsigned (*get_stack_id)(const void *obj);
    struct rte_mempool * (*get_pool)(const void *obj);
};

static __rte_always_inline
void rpc_obj_init(struct rte_mempool *mp, void *arg, void *obj, unsigned obj_idx)
{
    int stack_id = *(int *)arg;
    struct rpc_msg *msg = obj;
    msg->stack_id = stack_id;
}

static __rte_always_inline
unsigned rpc_obj_get_stack_id(const void *obj)
{
    return ((const struct rpc_msg *)obj)->stack_id;
}

static __rte_always_inline
struct rte_mempool *rpc_obj_get_pool(const void *obj)
{
    int stack_id = rpc_obj_get_stack_id(obj);
    return mem_get_rpc_pool(stack_id);
}

static __rte_always_inline
void mbuf_obj_init(struct rte_mempool *mp, void *arg, void *obj, unsigned obj_idx)
{
    int stack_id = *(int *)arg;
    struct rte_mbuf *mbuf = obj;
    struct mbuf_private *priv = mbuf_to_private(mbuf);
    priv->stack_id = stack_id;
}

static __rte_always_inline
unsigned mbuf_obj_get_stack_id(const void *obj)
{
    return mbuf_to_private((const struct rte_mbuf *)obj)->stack_id;
}

static __rte_always_inline
struct rte_mempool *mbuf_obj_get_pool(const void *obj)
{
    int stack_id = mbuf_obj_get_stack_id(obj);
    return mem_get_mbuf_pool(stack_id);
}

static const struct mem_obj_ops rpc_obj_ops = {
    .init           = rpc_obj_init,
    .get_stack_id   = rpc_obj_get_stack_id,
    .get_pool       = rpc_obj_get_pool,
};

static const struct mem_obj_ops mbuf_obj_ops = {
    .init           = mbuf_obj_init,
    .get_stack_id   = mbuf_obj_get_stack_id,
    .get_pool       = mbuf_obj_get_pool,
};

struct mempool_ops {
    struct rte_mempool *(*create)(const char *name, unsigned n, 
        unsigned cache_size, unsigned priv_size, unsigned data_room_size, int socket_id);
    void (*put_bulk)(struct rte_mempool *pool, void *const *obj_table, unsigned n);
    unsigned (*get_bulk)(struct rte_mempool *pool, void **obj_table, unsigned n);
};

static __rte_always_inline
struct rte_mempool *mempool_create(const char *name, unsigned n, 
    unsigned cache_size, unsigned priv_size, unsigned data_room_size, int socket_id)
{
    struct rte_mempool *pool;

    LSTACK_LOG(INFO, LSTACK, "name %s, n %u, cache_size %u, priv_size %u, data_room_size %u, socket_id %d, ops_name %s\n", 
        name, n, cache_size, priv_size, data_room_size, socket_id, MEMPOOL_OPS_NAME);

    pool = rte_mempool_create(name, n, data_room_size, cache_size, priv_size, NULL, NULL, NULL, NULL, socket_id, 0);
    if (pool != NULL)
        rte_mempool_set_ops_byname(pool, MEMPOOL_OPS_NAME, NULL);
    return pool;
}

static __rte_always_inline
void mempool_put_bulk(struct rte_mempool *pool, void *const *obj_table, unsigned n)
{
    rte_mempool_put_bulk(pool, obj_table, n);
}

static __rte_always_inline
unsigned mempool_get_bulk(struct rte_mempool *pool, void **obj_table, unsigned n)
{
    return rte_mempool_get_bulk(pool, obj_table, n) != 0 ? 0 : n;
}

static __rte_always_inline
struct rte_mempool *pkgmbuf_create(const char *name, unsigned n, 
    unsigned cache_size, unsigned priv_size, unsigned data_room_size, int socket_id)
{
    LSTACK_LOG(INFO, LSTACK, "name %s, n %u, cache_size %u, priv_size %u, data_room_size %u, socket_id %d, ops_name %s\n", 
        name, n, cache_size, priv_size, data_room_size, socket_id, MEMPOOL_OPS_NAME);

    return rte_pktmbuf_pool_create_by_ops(name, n, cache_size, priv_size, data_room_size, socket_id, MEMPOOL_OPS_NAME);
}

static __rte_always_inline
void pkgmbuf_put_bulk(struct rte_mempool *pool, void *const *obj_table, unsigned n)
{
    // rte_pktmbuf_free_bulk((struct rte_mbuf **)obj_table, n);
    rte_mempool_put_bulk(pool, obj_table, n);
}

static __rte_always_inline
unsigned pkgmbuf_get_bulk(struct rte_mempool *pool, void **obj_table, unsigned n)
{
    return rte_pktmbuf_alloc_bulk(pool, (struct rte_mbuf **)obj_table, n) != 0 ? 0 : n;
}

static const struct mempool_ops mem_mp_ops = {
    .create   = mempool_create,
    .put_bulk = mempool_put_bulk,
    .get_bulk = mempool_get_bulk,
};

static const struct mempool_ops mbuf_mp_ops = {
    .create   = pkgmbuf_create,
    .put_bulk = pkgmbuf_put_bulk,
    .get_bulk = pkgmbuf_get_bulk,
};


static struct rte_mempool *mbuf_pool_create(int stack_id, unsigned numa_id)
{
    struct cfg_params *cfg_params = get_global_cfg_params();
    char name[RTE_MEMPOOL_NAMESIZE];
    struct rte_mempool *pool;
    uint32_t total_conn_mbufs, total_nic_mbufs, total_mbufs;
    uint16_t private_size;
    uint16_t xdp_metadata = 0;

    total_conn_mbufs = cfg_params->mbuf_count_per_conn * cfg_params->tcp_conn_count;
    total_nic_mbufs = cfg_params->rxqueue_size + cfg_params->txqueue_size;

    total_mbufs = (total_conn_mbufs / cfg_params->num_queue) + total_nic_mbufs + MBUFPOOL_RESERVE_NUM;
    /* limit mbuf max num based on the dpdk capability */
    if (total_mbufs > MBUFPOOL_MAX_NUM) {
        LSTACK_LOG(ERR, LSTACK, "total_mbufs %u out of the dpdk mbuf_pool range\n", total_mbufs);
        return NULL;
    }

    SYS_FORMAT_NAME(name, RTE_MEMPOOL_NAMESIZE, "%s_%hu", "mbuf_pool", stack_id);
    /* reserved for xdp metadata, see struct xsk_tx_metadata in /usr/include/linux/if_xdp.h */
    if (xdp_eth_enabled()) {
        xdp_metadata = 24;
    }
    private_size = RTE_ALIGN(sizeof(struct mbuf_private) + xdp_metadata, RTE_CACHE_LINE_SIZE);

    pool = mbuf_mp_ops.create(name, total_mbufs, MBUFPOOL_CACHE_NUM, private_size, MBUF_DATA_SIZE, numa_id);
    if (pool == NULL) {
        LSTACK_LOG(ERR, LSTACK, "rte_pktmbuf_pool_create %s failed, rte_errno %d\n", name, rte_errno);
        return NULL;
    }

    return pool;
}

static struct rte_mempool *rpc_pool_create(int stack_id, unsigned numa_id)
{
    char name [RTE_MEMPOOL_NAMESIZE];
    struct rte_mempool *pool;
    uint32_t total_bufs = get_global_cfg_params()->rpc_msg_max;

    SYS_FORMAT_NAME(name, RTE_MEMPOOL_NAMESIZE, "%s_%hu", "rpc_pool", stack_id);

    pool = mem_mp_ops.create(name, total_bufs, MEMPOOL_CACHE_NUM, 0, sizeof(struct rpc_msg), numa_id);
    if (pool == NULL) {
        LSTACK_LOG(ERR, LSTACK, "rte_mempool_create %s failed, rte_errno %d\n", name, rte_errno);
    }

    return pool;
}

void mem_stack_pool_free(int stack_id)
{
    struct mem_stack *ms = mem_stack_get(stack_id);

    if (ms->mbuf_pool != NULL) {
        rte_mempool_free(ms->mbuf_pool);
        ms->mbuf_pool = NULL;
    }
    if (ms->rpc_pool != NULL) {
        rte_mempool_free(ms->rpc_pool);
        ms->rpc_pool = NULL;
    }
}

int mem_stack_pool_init(int stack_id, unsigned numa_id)
{
    struct mem_stack *ms = mem_stack_get(stack_id);

    ms->mbuf_pool = mbuf_pool_create(stack_id, numa_id);
    if (ms->mbuf_pool == NULL) {
        return -1;
    }

    ms->rpc_pool = rpc_pool_create(stack_id, numa_id);
    if (ms->rpc_pool == NULL) {
        mem_stack_pool_free(stack_id);
        return -1;
    }

    rte_mempool_obj_iter(ms->mbuf_pool, mbuf_obj_ops.init, &stack_id);
    rte_mempool_obj_iter(ms->rpc_pool, rpc_obj_ops.init, &stack_id);

    return 0;
}

int mem_stack_mpcache_init(int stack_id, unsigned cpu_id)
{
    struct mem_stack *ms = mem_stack_get(stack_id);

    if (ms->mbuf_pool == NULL) {
        LSTACK_LOG(ERR, LSTACK, "mem_stack_get stack_id %d failed\n", stack_id);
        return -1;
    }

    RTE_PER_LCORE(_lcore_id) = cpu_id;
    ms->mbuf_mpcache = rte_mempool_default_cache(ms->mbuf_pool, rte_lcore_id());
    ms->migrate_watermark = ms->mbuf_mpcache->size / 8;

    LSTACK_LOG(INFO, LSTACK, "tid %d, stack_id %d, lcore_id %u, migrate_watermark %u\n", 
        rte_gettid(), stack_id, rte_lcore_id(), ms->migrate_watermark);

    return 0;
}

unsigned mem_stack_mbuf_pool_count(int stack_id)
{
    struct mem_stack *ms = mem_stack_get(stack_id);
    return rte_mempool_avail_count(ms->mbuf_pool);
}

static void mem_thread_cache_flush(struct mem_thread *mt)
{
    struct mem_stack *ms = mem_stack_get(mt->stack_id);
    void *obj_table[BUF_BULK_MAX_NUM];
    unsigned num;

    if (mt->mbuf_migrate_ring != NULL) {
        LWIP_DEBUGF(MEMP_DEBUG, ("%s(mem_thread=%p, stack_id=%d, mbuf_migrate_ring count=%u)\n", 
                    __FUNCTION__, mt, mt->stack_id, rte_ring_count(mt->mbuf_migrate_ring)));

        while (true) {
            num = rte_ring_sc_dequeue_burst(mt->mbuf_migrate_ring, obj_table, BUF_BULK_MAX_NUM, NULL);
            if (num == 0)
                break;
            mbuf_mp_ops.put_bulk(ms->mbuf_pool, obj_table, num);
        }
    }

    if (mt->mbuf_cache != NULL) {
        LWIP_DEBUGF(MEMP_DEBUG, ("%s(mem_thread=%p, stack_id=%d, mbuf_cache count=%u)\n", 
                    __FUNCTION__, mt, mt->stack_id, buf_cache_count(mt->mbuf_cache)));

        while (true) {
            num = LWIP_MIN(buf_cache_count(mt->mbuf_cache), BUF_BULK_MAX_NUM);
            num = buf_cache_pop_bulk(mt->mbuf_cache, obj_table, num, NULL);
            if (num == 0)
                break;
            mbuf_mp_ops.put_bulk(ms->mbuf_pool, obj_table, num);
        }
        buf_cache_reset_watermark(mt->mbuf_cache);
    }

    if (mt->rpc_cache != NULL) {
        LWIP_DEBUGF(MEMP_DEBUG, ("%s(mem_thread=%p, stack_id=%d, rpc_cache count=%u)\n", 
                    __FUNCTION__, mt, mt->stack_id, buf_cache_count(mt->rpc_cache)));

        while (true) {
            num = LWIP_MIN(buf_cache_count(mt->rpc_cache), BUF_BULK_MAX_NUM);
            num = buf_cache_pop_bulk(mt->rpc_cache, obj_table, num, NULL);
            if (num == 0)
                break;
            mem_mp_ops.put_bulk(ms->rpc_pool, obj_table, num);
        }
        buf_cache_reset_watermark(mt->rpc_cache);
    }
}

static unsigned mem_thread_cache_count(const struct mem_thread *mt)
{
    unsigned count = 0;

    if (mt->mbuf_migrate_ring != NULL) {
        count += rte_ring_count(mt->mbuf_migrate_ring);
    }
    if (mt->mbuf_cache != NULL) {
        count += buf_cache_count(mt->mbuf_cache);
    }
    if (mt->rpc_cache != NULL) {
        count += buf_cache_count(mt->rpc_cache);
    }
    return count;
}

void mem_thread_cache_free(struct mem_thread *mt)
{
    mem_thread_cache_flush(mt);

    if (mt->mbuf_migrate_ring != NULL) {
        rte_ring_free(mt->mbuf_migrate_ring);
        mt->mbuf_migrate_ring = NULL;
    }
    if (mt->mbuf_cache != NULL) {
        buf_cache_free(mt->mbuf_cache);
        mt->mbuf_cache = NULL;
    }
    if (mt->rpc_cache != NULL) {
        buf_cache_free(mt->rpc_cache);
        mt->rpc_cache = NULL;
    }
}

int mem_thread_cache_init(struct mem_thread *mt, int stack_id)
{
    mt->stack_id = stack_id;

    if (get_global_cfg_params()->mem_async_mode) {
        char name [RTE_MEMPOOL_NAMESIZE];
        SYS_FORMAT_NAME(name, RTE_MEMPOOL_NAMESIZE, "%s_%p", "migrate_ring", mt);

        mt->mbuf_migrate_ring = rte_ring_create(name, 
            LWIP_MAX(get_global_cfg_params()->mem_cache_num, MIGRATE_RING_MIN_NUM), 
            rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (mt->mbuf_migrate_ring == NULL) {
            return -1;
        }
    }

    mt->mbuf_cache = buf_cache_create(get_global_cfg_params()->mem_cache_num);
    if (mt->mbuf_cache == NULL) {
        mem_thread_cache_free(mt);
        return -1;
    }

    mt->rpc_cache = buf_cache_create(BUF_CACHE_MIN_NUM);
    if (mt->rpc_cache == NULL) {
        mem_thread_cache_free(mt);
        return -1;
    }

    return 0;
}

struct mem_thread *mem_thread_migrate_get(int stack_id)
{
    struct mem_thread *mt = mem_thread_get(stack_id);
    if (mt == NULL || mt->mbuf_migrate_ring == NULL)
        return NULL;
    return mt;
}

static inline void mem_preinit_pbuf(struct pbuf *p);
void mem_mbuf_migrate_enqueue(struct mem_thread *mt, unsigned n)
{
    struct mem_stack *ms;
    struct rte_mempool_cache *mpcache;
    int stack_id;
    unsigned num, i;
    void **obj_table;

    stack_id = get_protocol_stack()->stack_idx;
    ms = mem_stack_get(stack_id);
    mpcache = ms->mbuf_mpcache;

    mt->stk_migrate_count += n;
    if (mt->stk_migrate_count < BUF_CACHE_WATERSTEP_MIN)
        return;
    if (mpcache->len < ms->migrate_watermark)
        return;

    /* no sufficient mbuf */
    if (rte_ring_count(ms->mbuf_pool->pool_data) < MBUFPOOL_RESERVE_NUM) {
        mem_thread_manager_flush_all();
        mt->stk_migrate_count = 0;
        return;
    }

    num = LWIP_MIN(mpcache->len - ms->migrate_watermark, 
                   mt->stk_migrate_count);
    obj_table = &mpcache->objs[mpcache->len - num];

    for (i = 0; i < num; i++) {
        rte_pktmbuf_reset(obj_table[i]);
        mem_preinit_pbuf(mbuf_to_pbuf(obj_table[i]));
    }
    num = rte_ring_sp_enqueue_bulk(mt->mbuf_migrate_ring, obj_table, num, NULL);
    if (num > 0) {
        mpcache->len -= num;
        mt->stk_migrate_count -= num;
    } else {
        mt->stk_migrate_count = 0;
    }
}

void mem_mbuf_migrate_dequeue(struct mem_thread *mt)
{
    struct buf_cache *cache;
    unsigned num;
    void **obj_table;

    if (mt->mbuf_migrate_ring == NULL)
        return;

    cache = mt->mbuf_cache;
    if (cache->head > (cache->watermark >> 1))
        return;

    num = cache->capacity - cache->head;
    obj_table = &cache->objs[cache->head];

    num = rte_ring_sc_dequeue_burst(mt->mbuf_migrate_ring, obj_table, num, NULL);
    cache->head += num;
}

/* see rte_mempool_cache_flush() */
static inline
void pool_put_with_mpcache(struct rte_mempool *pool, struct rte_mempool_cache* mpcache, void *obj)
{
    if (mpcache->len >= mpcache->flushthresh) {
        rte_mempool_ops_enqueue_bulk(pool, &mpcache->objs[mpcache->size], 
            mpcache->len - mpcache->size);
        mpcache->len = mpcache->size;
    }
    mpcache->objs[mpcache->len] = obj;
    mpcache->len++;
}

static inline
void pool_put_with_bufcache(struct rte_mempool *pool, struct buf_cache* cache, void *obj)
{
    if (cache->head >= cache->flushthresh) {
        buf_cache_sub_watermark(cache);
        rte_mempool_ops_enqueue_bulk(pool, &cache->objs[cache->watermark], 
            cache->head - cache->watermark);
        cache->head = cache->watermark;
    }
    cache->objs[cache->head] = obj;
    cache->head++;
}

static unsigned pool_get_bulk_with_cache(const struct mempool_ops *pool_ops, 
    struct rte_mempool *pool, struct buf_cache *cache, 
    void **obj_table, unsigned n)
{
    unsigned ret;
    unsigned count = 0;
    unsigned get_count;

    ret = buf_cache_pop_bulk(cache, obj_table, n, &count);
    if (ret > 0) {
        return n;
    }

    /* get from the pool */
    ret = pool_ops->get_bulk(pool, obj_table, n);
    if (unlikely(ret == 0)) {
        LSTACK_LOG(ERR, LSTACK, "pool %s get_bulk failed, n %u\n", pool->name, n);
        return 0;
    }

    buf_cache_add_watermark(cache);
    if (count >= cache->watermark) {
        return n;
    }

    /* get from the pool, then enqueue to cache */
    get_count = cache->watermark - count;
    LWIP_DEBUGF(MEMP_DEBUG, ("%s(cache=%p, watermark=%u, get_count=%u)\n", 
                __FUNCTION__, cache, cache->watermark, get_count));

    ret = pool_ops->get_bulk(pool, &cache->objs[cache->head], get_count);
    if (unlikely(ret == 0)) {
        LSTACK_LOG(ERR, LSTACK, "pool %s get_bulk failed, n %u\n", pool->name, get_count);
    } else {
        cache->head += get_count;
    }

    return n;
}

static void pool_put_bulk_with_cache(const struct mempool_ops *pool_ops, 
    struct rte_mempool *pool, struct buf_cache *cache, 
    void *const *obj_table, unsigned n)
{
    unsigned ret;
    unsigned count;
    unsigned free_count = 0;
    unsigned put_count;

    ret = buf_cache_push_bulk(cache, obj_table, n, &free_count);
    if (ret > 0) {
        return;
    }

    /* put to the pool */
    pool_ops->put_bulk(pool, obj_table, n);

    buf_cache_sub_watermark(cache);
    count = buf_cache_get_capacity(cache) - free_count;
    if (count <= cache->watermark) {
        return;
    }

    /* dequeue from cache, then put to the pool */
    put_count = count - cache->watermark;
    LWIP_DEBUGF(MEMP_DEBUG, ("%s(cache=%p, watermark=%u, put_count=%u)\n", 
                __FUNCTION__, cache, cache->watermark, put_count));

    pool_ops->put_bulk(pool, &cache->objs[cache->head - put_count], put_count);
    cache->head -= put_count;

    return;
}


void *mem_get_rpc(int stack_id)
{
    struct mem_stack *ms = mem_stack_get(stack_id);
    struct mem_thread *mt = mem_thread_get(stack_id);
    unsigned ret;
    void *obj;

    if (mt == NULL) {
        ret = mem_mp_ops.get_bulk(ms->rpc_pool, &obj, 1);
    } else {
        mem_thread_group_used();
        ret = pool_get_bulk_with_cache(&mem_mp_ops, ms->rpc_pool, mt->rpc_cache, &obj, 1);
        mem_thread_group_done();
    }

    LWIP_DEBUGF(MEMP_DEBUG, ("%s(stack_id=%d, obj=%p)\n", __FUNCTION__, stack_id, obj));

    return ret == 0 ? NULL : obj;
}

void mem_put_rpc(void *obj)
{
    unsigned stack_id = rpc_obj_ops.get_stack_id(obj);
    struct mem_stack *ms = mem_stack_get(stack_id);
    struct mem_thread *mt = mem_thread_get(stack_id);

    LWIP_DEBUGF(MEMP_DEBUG, ("%s(stack_id=%d, obj=%p)\n", __FUNCTION__, stack_id, obj));

    if (mt == NULL) {
        mem_mp_ops.put_bulk(ms->rpc_pool, &obj, 1);
    } else {
        mem_thread_group_used();
        pool_put_bulk_with_cache(&mem_mp_ops, ms->rpc_pool, mt->rpc_cache, &obj, 1);
        mem_thread_group_done();
    }
}

unsigned mem_get_mbuf_bulk(int stack_id, struct rte_mbuf **mbuf_table, unsigned n, bool reserve)
{
    struct mem_stack *ms = mem_stack_get(stack_id);
    struct mem_thread *mt = mem_thread_get(stack_id);
    unsigned ret;

    if (unlikely(n == 0)) {
        return 0;
    }

    if (reserve) {
        /* don't use rte_mempool_avail_count, it traverse cpu local cache,
         * when RTE_MAX_LCORE is too large, it's time-consuming
         */
        if (rte_ring_count(ms->mbuf_pool->pool_data) < MBUFPOOL_RESERVE_NUM + n) {
            mem_thread_manager_flush_all();
            return 0;
        }
    }

    if (mt == NULL) {
        ret = mbuf_mp_ops.get_bulk(ms->mbuf_pool, (void **)mbuf_table, n);
    } else {
        mem_thread_group_used();
        mem_mbuf_migrate_dequeue(mt);
        ret = pool_get_bulk_with_cache(&mbuf_mp_ops, ms->mbuf_pool, mt->mbuf_cache, (void **)mbuf_table, n);
        mem_thread_group_done();
    }

#if MEMP_DEBUG
    for (unsigned i = 0; i < ret; ++i) {
        LWIP_DEBUGF(MEMP_DEBUG, ("%s(stack_id=%d, n=%u, mbuf_table[%u]=%p, pbuf=%p)\n", 
                    __FUNCTION__, stack_id, n, i, mbuf_table[i], mbuf_to_pbuf(mbuf_table[i])));
    }
#endif /* MEMP_DEBUG */

    return ret;
}

static void mem_put_mbuf_bulk_by_pbuf(struct rte_mbuf *const *mbuf_table, unsigned n)
{
    unsigned stack_id = mbuf_obj_ops.get_stack_id(mbuf_table[0]);
    struct mem_stack *ms = mem_stack_get(stack_id);
    struct mem_thread *mt = mem_thread_get(stack_id);

    if (unlikely(n == 0)) {
        return;
    }

#if MEMP_DEBUG
    for (unsigned i = 0; i < n; ++i) {
        LWIP_DEBUGF(MEMP_DEBUG, ("%s(stack_id=%d, n=%u, mbuf_table[%u]=%p, pbuf=%p)\n", 
                    __FUNCTION__, stack_id, n, i, mbuf_table[i], mbuf_to_pbuf(mbuf_table[i])));
    }
#endif /* MEMP_DEBUG */

    if (mt == NULL) {
        mbuf_mp_ops.put_bulk(ms->mbuf_pool, (void *const *)mbuf_table, n);
    } else {
        mem_thread_group_used();
        pool_put_bulk_with_cache(&mbuf_mp_ops, ms->mbuf_pool, mt->mbuf_cache, (void *const *)mbuf_table, n);
        mem_thread_group_done();
    }

}

void mem_put_mbuf_bulk(struct rte_mbuf *const *mbuf_table, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; ++i) {
        LWIP_DEBUGF(MEMP_DEBUG, ("%s(stack_id=%d, n=%u, mbuf_table[%u]=%p, pbuf=%p)\n", 
            __FUNCTION__, mbuf_obj_ops.get_stack_id(mbuf_table[i]), 
            n, i, mbuf_table[i], mbuf_to_pbuf(mbuf_table[i])));

        rte_pktmbuf_free(mbuf_table[i]);
    }
}


unsigned mem_get_pbuf_bulk(int stack_id, struct pbuf **pbuf_table, unsigned n, bool reserve)
{
    struct rte_mbuf **mbuf_table = (struct rte_mbuf **)pbuf_table;
    unsigned ret, i;

    ret = mem_get_mbuf_bulk(stack_id, mbuf_table, n, reserve);
    if (unlikely(ret == 0)) {
        struct protocol_stack *stack = get_protocol_stack_by_id(stack_id);
        stack->stats.tx_allocmbuf_fail++;
        return 0;
    }

    for (i = 0; i < (n & ~0x3); i += 4) {
        pbuf_table[i]     = mbuf_to_pbuf(mbuf_table[i]);
        pbuf_table[i + 1] = mbuf_to_pbuf(mbuf_table[i + 1]);
        pbuf_table[i + 2] = mbuf_to_pbuf(mbuf_table[i + 2]);
        pbuf_table[i + 3] = mbuf_to_pbuf(mbuf_table[i + 3]);
    }
    switch (n & 0x3) {
    case 3:
        pbuf_table[i] = mbuf_to_pbuf(mbuf_table[i]); /* fallthrough */
        ++i;
    case 2:
        pbuf_table[i] = mbuf_to_pbuf(mbuf_table[i]); /* fallthrough */
        ++i;
    case 1:
        pbuf_table[i] = mbuf_to_pbuf(mbuf_table[i]); /* fallthrough */
        ++i;
    }

    return n;
}

void mem_preput_pbuf(struct pbuf *p)
{
    struct rte_mbuf *m = pbuf_to_mbuf(p);
    p->mbuf_refcnt = rte_mbuf_refcnt_read(m);
    if (p->mbuf_refcnt == 1) {
        rte_pktmbuf_reset(m);
    }
}

/* ignore buf->ref, and reset to 1 */
static __rte_always_inline
struct rte_mbuf *pbuf_to_mbuf_prefree(struct pbuf *p)
{
    if (unlikely(p == NULL))
        return NULL;

    if (p->next != NULL)
        p->next = NULL;

    struct rte_mbuf *m = pbuf_to_mbuf(p);
#if MEMP_DEBUG
    if (rte_mbuf_refcnt_read(m) > 1) {
        LWIP_DEBUGF(MEMP_DEBUG, ("%s(mbuf=%p, pbuf=%p, refcnt=%u)\n", 
                    __FUNCTION__, m, p, rte_mbuf_refcnt_read(m)));
    }
#endif /* MEMP_DEBUG */
    if (p->mbuf_refcnt != 1) {
        m = rte_pktmbuf_prefree_seg(m);
        if (m != NULL) {
            rte_pktmbuf_reset(m);
        }
    }

    return m;
}

void mem_put_pbuf_bulk(struct pbuf *const *pbuf_table, unsigned n)
{
    struct rte_mbuf *mbuf_table[BUF_BULK_MAX_NUM];
    unsigned i, copied, batch, bulk_num;

    copied = 0;
    while (copied < n) {
        batch = LWIP_MIN(n - copied, BUF_BULK_MAX_NUM);
        bulk_num = 0;
        for (i = 0; i < batch; ++i, ++copied) {
            mbuf_table[bulk_num] = pbuf_to_mbuf_prefree(pbuf_table[copied]);
            if (mbuf_table[bulk_num] != NULL) {
                ++bulk_num;
            }
        }
        mem_put_mbuf_bulk_by_pbuf(mbuf_table, bulk_num);
    }
}

void mem_put_pbuf_list_bulk(struct pbuf *const *pbuf_table, unsigned n)
{
    unsigned stack_id = mbuf_obj_ops.get_stack_id(pbuf_to_mbuf(pbuf_table[0]));
    struct mem_stack *ms = mem_stack_get(stack_id);
    struct mem_thread *mt = mem_thread_get(stack_id);

    struct pbuf *q, *next;
    struct rte_mbuf *mbuf;

    if (mt != NULL)
        mem_thread_group_used();

    for (unsigned i = 0; i < n; ++i) {
        q = pbuf_table[i];
        while (q != NULL) {
            next = q->next;
            q->next = NULL;

            q->ref--;
            if (q->ref > 0)
                break;
            mbuf = pbuf_to_mbuf_prefree(q);
            if (mbuf == NULL)
                break;

            q = next;

            if (mt == NULL) {
                pool_put_with_mpcache(ms->mbuf_pool, ms->mbuf_mpcache, mbuf);
            } else {
                pool_put_with_bufcache(ms->mbuf_pool, mt->mbuf_cache, mbuf);
            }

            LWIP_DEBUGF(MEMP_DEBUG, ("%s(stack_id=%d, n=%u, mbuf_table[%u]=%p, pbuf=%p)\n", 
                __FUNCTION__, stack_id, n, i, mbuf, q));
        }
    }

    if (mt != NULL)
        mem_thread_group_done();
    return;
}

struct pbuf *mem_get_pbuf(int stack_id, bool reserve)
{
    int ret;
    struct rte_mbuf *mbuf;

    if (stack_id < 0 || stack_id >= PROTOCOL_STACK_MAX)
        stack_id = get_protocol_stack()->stack_idx;

    ret = mem_get_mbuf_bulk(stack_id, &mbuf, 1, reserve);
    if (unlikely(ret == 0)) {
        struct protocol_stack *stack = get_protocol_stack_by_id(stack_id);
        stack->stats.tx_allocmbuf_fail++;
        return NULL;
    }

    return mbuf_to_pbuf(mbuf);
}

void mem_put_pbuf(struct pbuf *p)
{
    struct rte_mbuf *mbuf = pbuf_to_mbuf_prefree(p);
    if (mbuf != NULL) {
        mem_put_mbuf_bulk_by_pbuf(&mbuf, 1);
    }
}

unsigned mem_extcache_get_pbuf_bulk(int stack_id, struct pbuf **pbuf_table, unsigned n, bool reserve, struct pbuf **extcache_list)
{
    unsigned ret;
    struct pbuf *p;

    for (int i = 0; i < n; ++i) {
        p = *extcache_list;
        if (p != NULL) {
            *extcache_list = p->next;
            p->next = NULL;
            pbuf_table[i] = p;
        } else {
            ret = mem_get_pbuf_bulk(stack_id, &pbuf_table[i], n - i, reserve);
            if (unlikely(ret == 0)) {
                mem_put_pbuf_bulk(pbuf_table, i);
                return 0;
            }
            break;
        }
    }

    return n;
}

struct pbuf *mem_extcache_get_pbuf(int stack_id, bool reserve, struct pbuf **extcache_list)
{
    struct pbuf *p;

    p = *extcache_list;
    if (p != NULL) {
        *extcache_list = p->next;
        p->next = NULL;
    } else {
        p = mem_get_pbuf(stack_id, reserve);
    }

    return p;
}

void mem_extcache_put_pbuf(struct pbuf *h, struct pbuf *t, struct pbuf **extcache_list)
{
    if (get_global_cfg_params()->stack_mode_rtc) {
        pbuf_free(h);
        return;
    }

    if (*extcache_list == NULL) {
        *extcache_list = h;
    } else {
        if (t == NULL)
            t = pbuf_list_tail(h);
        t->next = *extcache_list;
        *extcache_list = h;
    }
}

void mem_extcache_flush_pbuf(struct pbuf **extcache_list)
{
    if (get_global_cfg_params()->stack_mode_rtc) {
        return;
    }

    struct pbuf *p = *extcache_list;
    if (p != NULL) {
        mem_put_pbuf_list_bulk(&p, 1);
        *extcache_list = NULL;
    }
}

static inline void mem_preinit_pbuf(struct pbuf *p)
{
    mem_init_pbuf(p, 0, 0, 0, PBUF_POOL_PREINIT);
}

void mem_init_pbuf(struct pbuf *p, pbuf_layer layer, uint16_t tot_len, uint16_t len, pbuf_type type)
{
    struct pbuf_custom *pc;
    struct rte_mbuf *mbuf;
    void *data;

    /* PBUF_POOL_PREINIT maybe give back to mbuf_pool, and alloc to NIC rx.
     * so ignore PBUF_POOL_PREINIT at this time. */
    if (layer == PBUF_TRANSPORT && p->type_internal == PBUF_POOL_PREINIT) {
        p->payload = (uint8_t *)p->payload + LWIP_MEM_ALIGN_SIZE((uint16_t)layer);
        p->type_internal = type;
        p->len = len;
        p->tot_len = tot_len;
        return;
    }

    pc = (struct pbuf_custom *)p;
    mbuf = pbuf_to_mbuf(p);
    data = rte_pktmbuf_mtod(mbuf, void *);

    pbuf_alloced_custom(layer, len, type, pc, data, MBUF_PAYLOAD_SIZE);
    p->tot_len = tot_len;
    pc->custom_free_function = mem_put_pbuf;
}
