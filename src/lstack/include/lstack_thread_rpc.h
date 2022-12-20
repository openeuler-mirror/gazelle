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

#ifndef __GAZELLE_THREAD_RPC_H__
#define __GAZELLE_THREAD_RPC_H__

#include <pthread.h>
#include <arch/sys_arch.h>

#include "lstack_lockless_queue.h"

#define MSG_ARG_0                      (0)
#define MSG_ARG_1                      (1)
#define MSG_ARG_2                      (2)
#define MSG_ARG_3                      (3)
#define MSG_ARG_4                      (4)
#define RPM_MSG_ARG_SIZE               (5)
struct rpc_msg;
typedef void (*rpc_msg_func)(struct rpc_msg *msg);
union rpc_msg_arg {
    int32_t i;
    uint32_t u;
    long l;
    unsigned long ul;
    void *p;
    const void *cp;
    socklen_t socklen;
    size_t size;
};
struct rpc_msg_pool;
struct rpc_msg {
    pthread_spinlock_t lock; /* msg handler unlock notice sender msg process done */
    int32_t self_release; /* 0:msg handler release msg  1:msg sender release msg */
    int64_t result; /* func return val */
    lockless_queue_node queue_node;
    struct rpc_msg_pool *pool;

    rpc_msg_func func; /* msg handle func hook */
    union rpc_msg_arg args[RPM_MSG_ARG_SIZE]; /* resolve by type */
};

struct protocol_stack;
struct rte_mbuf;
struct wakeup_poll;
struct lwip_sock;
void poll_rpc_msg(struct protocol_stack *stack, uint32_t max_num);
void rpc_call_clean_epoll(struct protocol_stack *stack, struct wakeup_poll *wakeup);
int32_t rpc_call_msgcnt(struct protocol_stack *stack);
int32_t rpc_call_shadow_fd(struct protocol_stack *stack, int32_t fd, const struct sockaddr *addr, socklen_t addrlen);
int32_t rpc_call_recvlistcnt(struct protocol_stack *stack);
int32_t rpc_call_sendlistcnt(struct protocol_stack *stack);
int32_t rpc_call_thread_regphase1(struct protocol_stack *stack, void *conn);
int32_t rpc_call_thread_regphase2(struct protocol_stack *stack, void *conn);
int32_t rpc_call_conntable(struct protocol_stack *stack, void *conn_table, uint32_t max_conn);
int32_t rpc_call_connnum(struct protocol_stack *stack);
int32_t rpc_call_arp(struct protocol_stack *stack, struct rte_mbuf *mbuf);
int32_t rpc_call_socket(int32_t domain, int32_t type, int32_t protocol);
int32_t rpc_call_close(int32_t fd);
int32_t rpc_call_bind(int32_t fd, const struct sockaddr *addr, socklen_t addrlen);
int32_t rpc_call_listen(int s, int backlog);
int32_t rpc_call_accept(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags);
int32_t rpc_call_connect(int fd, const struct sockaddr *addr, socklen_t addrlen);
int32_t rpc_call_send(int fd, const void *buf, size_t len, int flags);
int32_t rpc_call_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen);
int32_t rpc_call_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen);
int32_t rpc_call_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);
int32_t rpc_call_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
int32_t rpc_call_fcntl(int fd, int cmd, long val);
int32_t rpc_call_ioctl(int fd, long cmd, void *argp);
int32_t rpc_call_replenish(struct protocol_stack *stack, struct lwip_sock *sock);
int32_t rpc_call_mempoolsize(struct protocol_stack *stack);

#endif
