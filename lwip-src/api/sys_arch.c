/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Huawei Technologies
 *
 */

#include <pthread.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_cycles.h>

#include "lwip/err.h"
#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "arch/sys_arch.h"
#include "lwipgz_sock.h"

#define MBOX_NAME_PREFIX  "_mbox_0x"
#define MAX_MBOX_NAME_LEN (sizeof(MBOX_NAME_PREFIX) + 32) // log(UINT64_MAX) < 32

static u64_t g_sys_cycles_per_ms = 0;
static u64_t g_sys_cycles_per_us = 0;

/*
 * Timer
 * */
static void sys_timer_init(void)
{
    u64_t freq = rte_get_tsc_hz();
    if (g_sys_cycles_per_ms == 0) {
        g_sys_cycles_per_ms = (freq + MS_PER_S - 1) / MS_PER_S;
    }
    if (g_sys_cycles_per_us == 0) {
        g_sys_cycles_per_us = (freq + US_PER_S - 1) / US_PER_S;;
    }
}

u32_t sys_now(void)
{
    return (u32_t)(rte_rdtsc() / g_sys_cycles_per_ms);
}

u64_t sys_now_us(void)
{
    return (rte_rdtsc() / g_sys_cycles_per_us);
}

void sys_timer_run(void)
{
    u32_t sleeptime;

    sleeptime = sys_timeouts_sleeptime();
    if (sleeptime == 0) {
        sys_check_timeouts();
    }
}

/*
 * Threads
 * */
int thread_create(const char *name, unsigned id, thread_fn func, void *arg)
{
    int ret;
    pthread_t tid;
    char thread_name[SYS_NAME_LEN];

    ret = pthread_create(&tid, NULL, func, arg);
    if (ret != 0) {
        LWIP_DEBUGF(SYS_DEBUG | GAZELLE_DEBUG_SERIOUS, ("thread_create: pthread_create failed\n"));
        return ret;
    }

    SYS_FORMAT_NAME(thread_name, sizeof(thread_name), "%s_%02u", name, id);
    ret = pthread_setname_np(tid, thread_name);
    if (ret != 0) {
        LWIP_DEBUGF(SYS_DEBUG | GAZELLE_DEBUG_WARNING, ("thread_create: pthread_setname_np %s failed\n", thread_name));
    }
    return 0;
}

sys_thread_t sys_thread_new(const char *name, lwip_thread_fn function, void *arg, int stacksize, int prio)
{
    int ret;
    sys_thread_t thread;

    thread = (sys_thread_t)malloc(sizeof(*thread));
    if (thread == NULL) {
        LWIP_DEBUGF(SYS_DEBUG | GAZELLE_DEBUG_SERIOUS, ("sys_thread_new: malloc sys_thread failed\n"));
        return NULL;
    }

    ret = thread_create(name, 0, (thread_fn)function, arg);
    if (ret != 0) {
        free(thread);
        return NULL;
    }

    SYS_FORMAT_NAME(thread->name, sizeof(thread->name), "%s", name);
    thread->stacksize = stacksize;
    thread->prio = prio;

    return thread;
}


extern int eth_dev_poll(void);
/*
 * Mailbox
 * */
static int mbox_wait_func(void)
{
#if LWIP_TIMERS
    sys_timer_run();
#endif /* LWIP_TIMER */
    return eth_dev_poll();
}

struct rte_ring *gazelle_ring_create_fast(const char *name, uint32_t size, uint32_t flags)
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

void gazelle_ring_free_fast(struct rte_ring *ring)
{
    rte_free(ring);
}

err_t sys_mbox_new(struct sys_mbox **mb, int size)
{
    struct sys_mbox *mbox;

    mbox = (struct sys_mbox *)memp_malloc(MEMP_SYS_MBOX);
    if (mbox == NULL) {
        return ERR_MEM;
    }

    mbox->flags = RING_F_SP_ENQ | RING_F_SC_DEQ;
    mbox->size = size;
    mbox->socket_id = rte_socket_id();

    mbox->ring = gazelle_ring_create_fast(MBOX_NAME_PREFIX, mbox->size, mbox->flags);
    if (mbox->ring == NULL) {
        sys_mbox_free(&mbox);
        return ERR_MEM;
    }

    mbox->wait_fn = mbox_wait_func;
    *mb = mbox;

    return ERR_OK;
}

void sys_mbox_free(struct sys_mbox **mb)
{
    struct sys_mbox *mbox = *mb;
    if (mbox->ring != NULL) {
        gazelle_ring_free_fast(mbox->ring);
        mbox->ring = NULL;
    }
    memp_free(MEMP_SYS_MBOX, mbox);
    sys_mbox_set_invalid(mb);
}

err_t sys_mbox_trypost(struct sys_mbox **mb, void *msg)
{
    unsigned int n;
    struct sys_mbox *mbox = *mb;

    n = gazelle_st_ring_enqueue_busrt(mbox->ring, &msg, 1);
    if (!n)
        return ERR_BUF;
    return ERR_OK;
}

void sys_mbox_post(struct sys_mbox **mb, void *msg)
{
    struct sys_mbox *mbox = *mb;

    /* NOTE:  sys_mbox_post is used on mbox defined in src/api/tcpip.c.
    * If the ring size of mbox is greater than MEMP_NUM_TCPIP_MSG_API,
    * enqueue failure will never happen.
    * */
    if (!gazelle_st_ring_enqueue_busrt(mbox->ring, &msg, 1)) {
        LWIP_ASSERT("It is failed to post msg into mbox", 0);
    }
}

err_t sys_mbox_trypost_fromisr(sys_mbox_t *q, void *msg)
{
    return sys_mbox_trypost(q, msg);
}

uint32_t sys_arch_mbox_tryfetch(struct sys_mbox **mb, void **msg)
{
    unsigned int n;
    struct sys_mbox *mbox = *mb;

    n = gazelle_st_ring_dequeue_burst(mbox->ring, msg, 1);
    if (!n) {
        *msg = NULL;
        return SYS_MBOX_EMPTY;
    }

    return 0;
}

uint32_t sys_arch_mbox_fetch(struct sys_mbox **mb, void **msg, uint32_t timeout)
{
    unsigned int n;
    uint32_t poll_ts = 0;
    uint32_t time_needed = 0;
    struct sys_mbox *mbox = *mb;

    n = gazelle_st_ring_dequeue_burst(mbox->ring, msg, 1);

    if (timeout > 0)
        poll_ts = sys_now();

    while (!n) {
        if (timeout > 0) {
            time_needed = sys_now() - poll_ts;
            if (time_needed >= timeout) {
                return SYS_ARCH_TIMEOUT;
            }
        }

        (void)mbox->wait_fn();

        n = gazelle_st_ring_dequeue_burst(mbox->ring, msg, 1);
    }

    return time_needed;
}

int sys_mbox_empty(struct sys_mbox *mb)
{
    return rte_ring_count(mb->ring) == 0;
}

/*
 * Semaphore
 * */
err_t sys_sem_new(struct sys_sem **sem, uint8_t count)
{
    *sem = (struct sys_sem *)memp_malloc(MEMP_SYS_SEM);
    if ((*sem) == NULL) {
        return ERR_MEM;
    }
    (*sem)->c = 0;
    (*sem)->wait_fn = mbox_wait_func;
    return ERR_OK;
}

void sys_sem_signal(struct sys_sem **s)
{
    struct sys_sem *sem = NULL;
    LWIP_ASSERT("invalid sem", (s != NULL) && (*s != NULL));
    sem = *s;
    ++(sem->c);
}

static uint32_t cond_wait(struct sys_sem *sem, uint32_t timeout)
{
    uint32_t used_ms = 0;
    uint32_t poll_ts;

    if (timeout == 0) {
        (void)sem->wait_fn();
        return 0;
    }

    poll_ts = sys_now();

    while (used_ms < timeout) {
        if (sem->c > 0)
            return timeout - used_ms;

        (void)sem->wait_fn();
        used_ms = sys_now() - poll_ts;
    }

    return SYS_ARCH_TIMEOUT;
}

uint32_t sys_arch_sem_wait(struct sys_sem **s, uint32_t timeout)
{
    uint32_t time_needed = 0;
    struct sys_sem *sem = NULL;
    LWIP_ASSERT("invalid sem", (s != NULL) && (*s != NULL));
    sem = *s;

    while (sem->c <= 0) {
        if (timeout > 0) {
            time_needed = cond_wait(sem, timeout);

            if (time_needed == SYS_ARCH_TIMEOUT) {
                return SYS_ARCH_TIMEOUT;
            }
        } else {
            cond_wait(sem, 0);
        }
    }

    sem->c--;
    return time_needed;
}

void sys_sem_free(struct sys_sem **s)
{
    if ((s != NULL) && (*s != NULL))
        memp_free(MEMP_SYS_SEM, *s);
}

/*
 * Mutex
 * */
err_t sys_mutex_new(struct sys_mutex **mutex)
{
    return ERR_OK;
}

void sys_mutex_lock(struct sys_mutex **mutex)
{
}

void sys_mutex_unlock(struct sys_mutex **mutex)
{
}

void sys_mutex_free(struct sys_mutex **mutex)
{
}

/*
 * Critical section
 * */
sys_prot_t sys_arch_protect(void)
{
    return 0;
}

void sys_arch_unprotect(sys_prot_t pval)
{
}

/*
 * Memory
 * */
u8_t *sys_hugepage_malloc(const char *name, unsigned size)
{
    const struct rte_memzone *mz;
    char memname[PATH_MAX];

    SYS_FORMAT_NAME(memname, sizeof(memname), "%s_%d", name, rte_gettid());
    mz = rte_memzone_reserve(memname, size, rte_socket_id(), 0);
    if (mz == NULL) {
        LWIP_DEBUGF(SYS_DEBUG | GAZELLE_DEBUG_SERIOUS, ("sys_hugepage_malloc: failed to reserver memory for mempool[%s], errno %d\n", memname, errno));
        set_errno(ENOMEM);
        return NULL;
    } else {
        /* Ignore dpdk errno when mem allocation is successful */
        errno = 0;
    }

    memset(mz->addr, 0, mz->len);

    return (uint8_t*)mz->addr;
}

void sys_mempool_var_init(struct memp_desc *memp, char *desc, u16_t size, u16_t num,
    u8_t *base, struct memp **tab, struct stats_mem *stats)
{
    LWIP_DEBUGF(SYS_DEBUG, ("[tid %u] %s: memp %p desc %s size %u num %u base %p\n",
        rte_gettid(), __FUNCTION__, memp, desc, size, num, base));

#if defined(LWIP_DEBUG) || MEMP_OVERFLOW_CHECK || LWIP_STATS_DISPLAY
    memp->desc = desc;
#endif /* LWIP_DEBUG || MEMP_OVERFLOW_CHECK || LWIP_STATS_DISPLAY */
#if MEMP_STATS
    LWIP_ASSERT("stats != NULL", stats != NULL);
    memp->stats = stats;
#endif

    memp->size = size;

#if !MEMP_MEM_MALLOC
    LWIP_ASSERT("base != NULL", base != NULL);
    memp->num = num;
    memp->base = base;
    memp->tab = tab;
#endif /* MEMP_MEM_MALLOC */
}

/* Using errno to return lwip_init() result,
 * mem_init() and memp_init() will set failed errno.
 */
void sys_init(void)
{
    set_errno(0);
    sys_timer_init();
}
