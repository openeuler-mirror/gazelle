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

#ifndef _LWIP_ARCH_SYS_ARCH_H_
#define _LWIP_ARCH_SYS_ARCH_H_

#include <stdio.h>
#include <string.h>

#include "lwip/debug.h"
#include "lwip/memp.h"

#define SYS_NAME_LEN 64

struct sys_thread {
    struct sys_thread *next;
    char name[SYS_NAME_LEN];
    void *arg;
    int stacksize;
    int prio;
};
typedef struct sys_thread *sys_thread_t;
typedef void *(*thread_fn)(void *arg);
int thread_create(const char *name, unsigned id, thread_fn func, void *arg);


struct sys_sem {
    volatile unsigned int c;
    int (*wait_fn)(void);
};
typedef struct sys_sem *sys_sem_t;
#define sys_sem_valid(sem)             (((sem) != NULL) && (*(sem) != NULL))
#define sys_sem_set_invalid(sem)       do { if ((sem) != NULL) { *(sem) = NULL; }} while(0)


struct sys_mutex {
    volatile unsigned int m;
};
typedef struct sys_mutex *sys_mutex_t;
#define sys_mutex_valid(mutex)         sys_sem_valid(mutex)
#define sys_mutex_set_invalid(mutex)   sys_sem_set_invalid(mutex)


struct sys_mbox {
    char name[SYS_NAME_LEN];
    int size;
    int socket_id;
    unsigned flags;
    struct rte_ring *ring;
    int (*wait_fn)(void);
};
typedef struct sys_mbox *sys_mbox_t;
#define sys_mbox_valid(mbox)           sys_sem_valid(mbox)
#define sys_mbox_set_invalid(mbox)     sys_sem_set_invalid(mbox)
int sys_mbox_empty(struct sys_mbox *);

typedef uint32_t sys_prot_t;

u8_t *sys_hugepage_malloc(const char *name, unsigned size);
void sys_mempool_var_init(struct memp_desc *memp, char *desc, u16_t size, u16_t num,
    u8_t *base, struct memp **tab, struct stats_mem *stats);

u32_t sys_timer_run(void);
u32_t sys_now(void);
u64_t sys_now_us(void);

#define SYS_FORMAT_NAME(buf, size, fmt, ...) \
    do { \
        int ret = snprintf(buf, size, ""fmt"", ##__VA_ARGS__); \
        if (ret < 0) { \
            LWIP_DEBUGF(SYS_DEBUG, ("%s:%d: sprintf failed\n", __FUNCTION__, __LINE__)); \
            (void)memset((void *)buf, 0, size); \
        } \
    } while(0)

#if GAZELLE_ENABLE
#include <rte_ring.h>
#include "dpdk_version.h"

/* 
    gazelle custom rte ring interface
    lightweight ring no atomic.
    only surpport in single thread.
 */
static __rte_always_inline uint32_t gazelle_st_ring_enqueue_busrt(struct rte_ring *r, void **obj_table, uint32_t n)
{
    uint32_t prod = r->prod.tail;
    uint32_t cons = r->cons.tail;
    uint32_t free_entries = r->capacity + cons - prod;

    if (n > free_entries) {
        return 0;
    }

    __rte_ring_enqueue_elems(r, prod, obj_table, sizeof(void *), n);

    r->prod.tail = prod + n;

    return n;
}

static __rte_always_inline uint32_t gazelle_st_ring_dequeue_burst(struct rte_ring *r, void **obj_table, uint32_t n)
{
    uint32_t cons = r->cons.tail;
    uint32_t prod = r->prod.tail;
    uint32_t entries = prod - cons;

    if (n > entries) {
        n = entries;
    }

    if (n == 0) {
        return 0;
    }

    __rte_ring_dequeue_elems(r, cons, obj_table, sizeof(void *), n);

    r->cons.tail = cons + n;

    return n;
}

void gazelle_ring_free_fast(struct rte_ring *ring);
struct rte_ring *gazelle_ring_create_fast(const char *name, uint32_t size, uint32_t flags);

#endif /* GAZELLE_ENABLE */

#endif /* _LWIP_ARCH_SYS_ARCH_H_ */
