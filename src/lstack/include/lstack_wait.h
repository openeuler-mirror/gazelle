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

#ifndef _LSTACK_WAIT_H_
#define _LSTACK_WAIT_H_

#include <stdbool.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/select.h>

#include <rte_atomic.h>
#include <rte_spinlock.h>

#include <lwip/lwipgz_sock.h>
#include <lwip/lwipgz_list.h>
#include <lwip/arch/sys_arch.h>
#include <lwip/priv/tcp_priv.h>

#include "common/gazelle_dfx_msg.h"
#include "lstack_protocol_stack.h"
#include "lstack_cfg.h"


#define NETCONN_TYPE(conn)  NETCONNTYPE_GROUP(netconn_type((conn)))

enum sock_wait_type {
    WAIT_CLOSE  = 0x00,
    WAIT_POLL   = 0x01,
    WAIT_EPOLL  = 0x02,
    WAIT_BLOCK  = 0x04,
    WAIT_MAX    = 0x08,
};

struct wait_affinity {
    int bind_stack_id;
    int max_stack_id;
    unsigned stack_nfds[PROTOCOL_STACK_MAX];
};

/* epoll control block */
struct epoll_cb {
    struct list_node event_list;
    rte_spinlock_t lock;
};

/* poll control block */
struct poll_cb {
    int max_nfds;
    struct pollfd **lwip_p_fds;
    struct pollfd *kernel_fds;
};

struct sock_wait {
    enum sock_wait_type type;

    /* blocking and return 0 on timeout */
    int (*timedwait_fn)(struct sock_wait *sk_wait, int timeout, uint32_t start);
    /* trigger event */
    void (*notify_fn)(struct sock_wait *sk_wait, struct sock_event *sk_event, 
        unsigned pending, int stack_id);
    /* remove event */
    void (*remove_fn)(struct sock_wait *sk_wait, struct sock_event *sk_event, unsigned pending);

    /* dfx stat */
    struct list_node group_node;

    /* epoll kernel fd */
    int epfd;

    /* socket count */
    unsigned lwip_nfds;
    unsigned kernel_nfds;
    struct wait_affinity affinity;

#define SOCK_WAIT_STAT(sk_wait, name, count)  if ((sk_wait) != NULL && (sk_wait)->type != WAIT_CLOSE) { (sk_wait)->stat.name += count; }
    struct gazelle_wakeup_stat stat;

    char pad0 __rte_cache_aligned;  /* new cache line */

#if SOCK_WAIT_BATCH_NOTIFY
    /* lwip event foreach notify list */
    struct list_node __rte_cache_aligned stk_notify_node[PROTOCOL_STACK_MAX];
    struct list_node __rte_cache_aligned stk_event_list[PROTOCOL_STACK_MAX];
#endif /* SOCK_WAIT_BATCH_NOTIFY */

    char pad1 __rte_cache_aligned;  /* new cache line */

    /* kernel event flag */
    rte_atomic16_t kernel_pending;
    /* run-to-wakeup blocking lock */
    struct sys_sem sem; /* Do not use mutex, as it cannot be interrupted by signals */

    union {
        struct epoll_cb epcb;
        struct poll_cb pcb;
    };
};


int sock_wait_group_init(void);
void sock_wait_group_stat(int stack_id, struct gazelle_wakeup_stat *stat);

int lwip_wait_init(int stack_id);

void* kernel_wait_thread(void *arg);
int kernel_wait_ctl(struct sock_wait *sk_wait, int new_stack_id, int old_stack_id);

#if SOCK_WAIT_BATCH_NOTIFY
void lwip_wait_add_notify(struct sock_wait *sk_wait, struct sock_event *sk_event, 
    unsigned pending, int stack_id);
unsigned lwip_wait_foreach_notify(int stack_id);
bool lwip_wait_notify_empty(int stack_id);
#endif /* SOCK_WAIT_BATCH_NOTIFY */

unsigned sock_event_hold_pending(const struct lwip_sock *sock, 
    enum sock_wait_type type, enum netconn_evt evt, unsigned len);
void sock_event_notify_pending(struct lwip_sock *sock, enum netconn_evt evt, unsigned len);
void sock_event_remove_pending(struct lwip_sock *sock, enum netconn_evt evt, unsigned len);

int sock_event_init(struct sock_event *sk_event);
void sock_event_free(struct sock_event *sk_event, struct sock_wait *sk_wait);

int sock_wait_common_init(struct sock_wait *sk_wait);
void sock_wait_common_free(struct sock_wait *sk_wait);

int sock_wait_kernel_init(struct sock_wait *sk_wait, int epfd, int stack_num);
void sock_wait_kernel_free(struct sock_wait *sk_wait);

void affinity_update_max_stack(struct wait_affinity *affinity);
void affinity_bind_stack(struct sock_wait *sk_wait, struct wait_affinity *affinity);

#endif /* _LSTACK_WAIT_H_ */
