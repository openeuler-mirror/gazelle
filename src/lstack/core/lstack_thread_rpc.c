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
#include <lwip/sockets.h>
#include <lwip/lwipgz_sock.h>
#include <rte_mempool.h>

#include "lwip/lwipgz_posix_api.h"

#include "lstack_log.h"
#include "lstack_cfg.h"
#include "lstack_dpdk.h"
#include "lstack_stack_stat.h"
#include "lstack_protocol_stack.h"
#include "lstack_thread_rpc.h"
#include "lstack_epoll.h"
#include "lstack_lwip.h"

struct rpc_pool_array {
#define RPC_POOL_MAX_COUNT     1024
    struct rpc_msg_pool *array[RPC_POOL_MAX_COUNT];
    pthread_mutex_t lock;
    int cur_count;
};

static struct rpc_pool_array g_rpc_pool_array = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

static PER_THREAD struct rpc_msg_pool *g_rpc_pool = NULL;
static struct rpc_stats g_rpc_stats;

struct rpc_stats *rpc_stats_get(void)
{
    return &g_rpc_stats;
}

__rte_always_inline
static struct rpc_msg *get_rpc_msg(struct rpc_msg_pool *rpc_pool)
{
    int ret;
    struct rpc_msg *msg = NULL;
    ret = rte_mempool_get(rpc_pool->mempool, (void **)&msg);
    if (ret < 0) {
        errno = ENOMEM;
        return NULL;
    }
    return msg;
}

__rte_always_inline
static void rpc_msg_init(struct rpc_msg *msg, rpc_func_t func, struct rpc_msg_pool *pool)
{
    msg->func       = func;
    msg->rpcpool    = pool;
    msg->recall_flag = 0;
    pthread_spin_init(&msg->lock, PTHREAD_PROCESS_PRIVATE);
}

static struct rpc_msg_pool *rpc_msg_pool_init(void)
{
    struct rpc_msg_pool *rpc_pool;
    pthread_mutex_lock(&g_rpc_pool_array.lock);
    if (g_rpc_pool_array.cur_count >= RPC_POOL_MAX_COUNT) {
        pthread_mutex_unlock(&g_rpc_pool_array.lock);
        return g_rpc_pool_array.array[rte_gettid() % RPC_POOL_MAX_COUNT];
    }

    rpc_pool = calloc(1, sizeof(struct rpc_msg_pool));
    if (rpc_pool == NULL) {
        LSTACK_LOG(INFO, LSTACK, "g_rpc_pool calloc failed\n");
        goto END;
    }
    rpc_pool->mempool =
        create_mempool("rpc_pool", get_global_cfg_params()->rpc_msg_max, sizeof(struct rpc_msg), 0, rte_gettid());
    if (rpc_pool->mempool == NULL) {
        LSTACK_LOG(INFO, LSTACK, "rpc_pool create failed, errno is %d\n", errno);
        free(rpc_pool);
        goto END;
    }

    g_rpc_pool_array.array[g_rpc_pool_array.cur_count++] = rpc_pool;
    pthread_mutex_unlock(&g_rpc_pool_array.lock);
    return rpc_pool;
END:
    pthread_mutex_unlock(&g_rpc_pool_array.lock);
    g_rpc_stats.call_alloc_fail++;
    return NULL;
}


static struct rpc_msg *rpc_msg_alloc(rpc_func_t func)
{
    struct rpc_msg *msg;

    if (unlikely(g_rpc_pool == NULL)) {
        g_rpc_pool = rpc_msg_pool_init();
        if (g_rpc_pool == NULL) {
            exit(-1);
        }
    }

    msg = get_rpc_msg(g_rpc_pool);
    if (unlikely(msg == NULL)) {
        g_rpc_stats.call_alloc_fail++;
        return NULL;
    }

    rpc_msg_init(msg, func, g_rpc_pool);
    return msg;
}

__rte_always_inline
static void rpc_msg_free(struct rpc_msg *msg)
{
    pthread_spin_destroy(&msg->lock);
    if (msg->rpcpool != NULL && msg->rpcpool->mempool != NULL) {
        rte_mempool_put(msg->rpcpool->mempool, (void *)msg);
    } else {
        free(msg);
    }
}

__rte_always_inline
static void rpc_call(rpc_queue *queue, struct rpc_msg *msg)
{
    lockless_queue_mpsc_push(&queue->queue, &msg->queue_node);
    intr_wakeup(queue->queue_id, INTR_REMOTE_EVENT);
}

__rte_always_inline
static void rpc_async_call(rpc_queue *queue, struct rpc_msg *msg)
{
    msg->sync_flag = 0;
    rpc_call(queue, msg);
}

__rte_always_inline
static int rpc_sync_call(rpc_queue *queue, struct rpc_msg *msg)
{
    int ret;

    pthread_spin_trylock(&msg->lock);

    msg->sync_flag = 1;
    rpc_call(queue, msg);

    // waiting stack unlock
    pthread_spin_lock(&msg->lock);

    ret = msg->result;
    rpc_msg_free(msg);
    return ret;
}

int rpc_msgcnt(rpc_queue *queue)
{
    return lockless_queue_count(&queue->queue);
}

static struct rpc_msg *rpc_msg_alloc_except(rpc_func_t func)
{
    struct rpc_msg *msg = calloc(1, sizeof(struct rpc_msg));
    if (msg == NULL) {
        return NULL;
    }

    rpc_msg_init(msg, func, NULL);
    return msg;
}

static void stack_exit_by_rpc(struct rpc_msg *msg)
{
    stack_exit();
}

int rpc_call_stack_exit(rpc_queue *queue)
{
    struct rpc_msg *msg = rpc_msg_alloc_except(stack_exit_by_rpc);
    if (msg == NULL) {
        return -1;
    }

    rpc_async_call(queue, msg);
    return 0;
}

int rpc_poll_msg(rpc_queue *queue, int max_num)
{
    int force_quit = 0;
    struct rpc_msg *msg;

    while (max_num--) {
        lockless_queue_node *node = lockless_queue_mpsc_pop(&queue->queue);
        if (node == NULL) {
            break;
        }

        msg = container_of(node, struct rpc_msg, queue_node);

        if (likely(msg->func)) {
            msg->func(msg);
        } else {
            g_rpc_stats.call_null++;
        }

        if (unlikely(msg->func == stack_exit_by_rpc)) {
            force_quit = 1;
        }
        if (msg->recall_flag) {
            msg->recall_flag = 0;
            continue;
        }

        if (msg->sync_flag) {
            pthread_spin_unlock(&msg->lock);
        } else {
            rpc_msg_free(msg);
        }
    }

    return force_quit;
}


static void callback_socket(struct rpc_msg *msg)
{
    msg->result = lwip_socket(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i);
    if (msg->result < 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, %ld socket failed\n", rte_gettid(), msg->result);
    }
}

static void callback_close(struct rpc_msg *msg)
{
    int fd = msg->args[MSG_ARG_0].i;
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct lwip_sock *sock = lwip_get_socket(fd);

    if (sock && __atomic_load_n(&sock->call_num, __ATOMIC_ACQUIRE) > 0) {
        msg->recall_flag = 1;
        rpc_call(&stack->rpc_queue, msg); /* until stack_send recall finish */
        return;
    }

    msg->result = lwip_close(fd);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d failed %ld\n", rte_gettid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

static void callback_shutdown(struct rpc_msg *msg)
{
    int fd = msg->args[MSG_ARG_0].i;
    int how = msg->args[MSG_ARG_1].i;
    struct protocol_stack *stack = get_protocol_stack_by_fd(fd);
    struct lwip_sock *sock = lwip_get_socket(fd);

    if (sock && __atomic_load_n(&sock->call_num, __ATOMIC_ACQUIRE) > 0) {
        msg->recall_flag = 1;
        rpc_call(&stack->rpc_queue, msg);
        return;
    }

    msg->result = lwip_shutdown(fd, how);
    if (msg->result != 0 && errno != ENOTCONN) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d fail %ld\n", rte_gettid(), fd, msg->result);
    }

    posix_api->shutdown_fn(fd, how);
}

static void callback_bind(struct rpc_msg *msg)
{
    msg->result = lwip_bind(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].cp, msg->args[MSG_ARG_2].u);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d failed %ld\n", rte_gettid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

static void callback_listen(struct rpc_msg *msg)
{
    int fd = msg->args[MSG_ARG_0].i;
    int backlog = msg->args[MSG_ARG_1].i;

    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock == NULL) {
        msg->result = -1;
        return;
    }

    /* new listen add to stack listen list */
    msg->result = lwip_listen(fd, backlog);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d failed %ld\n", rte_gettid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

static void callback_create_shadow_fd(struct rpc_msg *msg)
{
    int fd = msg->args[MSG_ARG_0].i;
    struct sockaddr *addr = msg->args[MSG_ARG_1].p;
    socklen_t addr_len = msg->args[MSG_ARG_2].u;

    int clone_fd = 0;
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "get sock null fd=%d\n", fd);
        msg->result = -1;
        return;
    }

    int domain = addr->sa_family;
    int type = NETCONN_IS_UDP(sock) ? SOCK_DGRAM : SOCK_STREAM;
    clone_fd = lwip_socket(domain, type, 0);
    if (clone_fd < 0) {
        LSTACK_LOG(ERR, LSTACK, "clone socket failed clone_fd=%d errno=%d\n", clone_fd, errno);
        msg->result = clone_fd;
        return;
    }

    struct lwip_sock *clone_sock = lwip_get_socket(clone_fd);
    if (clone_sock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "get sock null fd=%d clone_fd=%d\n", fd, clone_fd);
        msg->result = -1;
        return;
    }

    do_lwip_clone_sockopt(clone_sock, sock);

    while (sock->listen_next) {
        sock = sock->listen_next;
    }
    sock->listen_next = clone_sock;

    int ret = lwip_bind(clone_fd, addr, addr_len);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "clone bind failed clone_fd=%d errno=%d\n", clone_fd, errno);
        msg->result = ret;
        return;
    }

    msg->result = clone_fd;
}

static void callback_accept(struct rpc_msg *msg)
{
    int fd = msg->args[MSG_ARG_0].i;
    msg->result = -1;
    struct protocol_stack *stack = get_protocol_stack();

    int accept_fd = lwip_accept4(fd, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].p, msg->args[MSG_ARG_3].i);
    if (accept_fd < 0) {
        stack->stats.accept_fail++;
        LSTACK_LOG(ERR, LSTACK, "fd %d ret %d\n", fd, accept_fd);
        return;
    }

    struct lwip_sock *sock = lwip_get_socket(accept_fd);
    if (sock == NULL || sock->stack == NULL) {
        lwip_close(accept_fd);
        LSTACK_LOG(ERR, LSTACK, "fd %d ret %d\n", fd, accept_fd);
        return;
    }

    msg->result = accept_fd;
    sock->stack->conn_num++;
    if (rte_ring_count(sock->conn->recvmbox->ring)) {
        do_lwip_add_recvlist(accept_fd);
    }
}

static void callback_connect(struct rpc_msg *msg)
{
    msg->result = lwip_connect(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].u);
    if (msg->result < 0) {
        msg->result = -errno;
    }
}

int rpc_call_socket(rpc_queue *queue, int domain, int type, int protocol)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_socket);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = domain;
    msg->args[MSG_ARG_1].i = type;
    msg->args[MSG_ARG_2].i = protocol;

    return rpc_sync_call(queue, msg);
}

int rpc_call_close(rpc_queue *queue, int fd)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_close);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;

    return rpc_sync_call(queue, msg);
}

int rpc_call_shutdown(rpc_queue *queue, int fd, int how)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_shutdown);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].i = how;

    return rpc_sync_call(queue, msg);
}

int rpc_call_bind(rpc_queue *queue, int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_bind);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].cp = addr;
    msg->args[MSG_ARG_2].u = addrlen;

    return rpc_sync_call(queue, msg);
}

int rpc_call_listen(rpc_queue *queue, int s, int backlog)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_listen);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = s;
    msg->args[MSG_ARG_1].i = backlog;

    return rpc_sync_call(queue, msg);
}

int rpc_call_shadow_fd(rpc_queue *queue, int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_create_shadow_fd);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].cp = addr;
    msg->args[MSG_ARG_2].u = addrlen;

    return rpc_sync_call(queue, msg);
}

int rpc_call_accept(rpc_queue *queue, int fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_accept);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].p = addr;
    msg->args[MSG_ARG_2].p = addrlen;
    msg->args[MSG_ARG_3].i = flags;

    return rpc_sync_call(queue, msg);
}

int rpc_call_connect(rpc_queue *queue, int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_connect);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].cp = addr;
    msg->args[MSG_ARG_2].u = addrlen;

    int ret = rpc_sync_call(queue, msg);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static void callback_getpeername(struct rpc_msg *msg)
{
    msg->result = lwip_getpeername(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].p);
}

static void callback_getsockname(struct rpc_msg *msg)
{
    msg->result = lwip_getsockname(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].p);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d fail %ld\n", rte_gettid(), msg->args[MSG_ARG_0].i, msg->result);
    }
}

static void callback_getsockopt(struct rpc_msg *msg)
{
    msg->result = lwip_getsockopt(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i,
        msg->args[MSG_ARG_3].p, msg->args[MSG_ARG_4].p);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d, level %d, optname %d, fail %ld\n", rte_gettid(),
                   msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i, msg->result);
    }
}

static void callback_setsockopt(struct rpc_msg *msg)
{
    msg->result = lwip_setsockopt(msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i,
        msg->args[MSG_ARG_3].cp, msg->args[MSG_ARG_4].u);
    if (msg->result != 0) {
        LSTACK_LOG(ERR, LSTACK, "tid %d, fd %d, level %d, optname %d, fail %ld\n", rte_gettid(),
                   msg->args[MSG_ARG_0].i, msg->args[MSG_ARG_1].i, msg->args[MSG_ARG_2].i, msg->result);
    }
}

int rpc_call_getpeername(rpc_queue *queue, int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_getpeername);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].p = addr;
    msg->args[MSG_ARG_2].p = addrlen;

    return rpc_sync_call(queue, msg);
}

int rpc_call_getsockname(rpc_queue *queue, int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_getsockname);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].p = addr;
    msg->args[MSG_ARG_2].p = addrlen;

    return rpc_sync_call(queue, msg);
}

int rpc_call_getsockopt(rpc_queue *queue, int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_getsockopt);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].i = level;
    msg->args[MSG_ARG_2].i = optname;
    msg->args[MSG_ARG_3].p = optval;
    msg->args[MSG_ARG_4].p = optlen;

    return rpc_sync_call(queue, msg);
}

int rpc_call_setsockopt(rpc_queue *queue, int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_setsockopt);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].i = level;
    msg->args[MSG_ARG_2].i = optname;
    msg->args[MSG_ARG_3].cp = optval;
    msg->args[MSG_ARG_4].u = optlen;

    return rpc_sync_call(queue, msg);
}

static void callback_tcp_send(struct rpc_msg *msg)
{
    int fd = msg->args[MSG_ARG_0].i;
    size_t len = UINT16_MAX; /* ignore msg->args[MSG_ARG_1].size; */
    struct protocol_stack *stack = get_protocol_stack();
    int ret;
    msg->result = -1;

    struct lwip_sock *sock = lwip_get_socket(fd);
    if (unlikely(POSIX_IS_CLOSED(sock))) {
        return;
    }

    if (get_protocol_stack_group()->latency_start) {
        calculate_sock_latency(&stack->latency, sock, GAZELLE_LATENCY_WRITE_RPC_MSG);
    }

    ret = lwip_send(fd, sock, len, 0);
    if (unlikely(ret < 0) && (errno == ENOTCONN || errno == ECONNRESET || errno == ECONNABORTED)) {
        __sync_fetch_and_sub(&sock->call_num, 1);
        return;
    }
    msg->result = 0;

    ret = do_lwip_replenish_sendring(stack, sock);
    if (ret > 0 || NETCONN_IS_DATAOUT(sock)) {
        if (__atomic_load_n(&sock->call_num, __ATOMIC_ACQUIRE) == 1) {
            msg->recall_flag = 1;
            rpc_call(&stack->rpc_queue, msg);
            return;
        }
    }

    __sync_fetch_and_sub(&sock->call_num, 1);
    return;
}

static void callback_udp_send(struct rpc_msg *msg)
{
    int fd = msg->args[MSG_ARG_0].i;
    size_t len = msg->args[MSG_ARG_1].size;
    struct protocol_stack *stack = get_protocol_stack();
    int ret;
    msg->result = -1;

    struct lwip_sock *sock = lwip_get_socket(fd);
    if (unlikely(POSIX_IS_CLOSED(sock))) {
        return;
    }

    if (get_protocol_stack_group()->latency_start) {
        calculate_sock_latency(&stack->latency, sock, GAZELLE_LATENCY_WRITE_RPC_MSG);
    }

    ret = lwip_send(fd, sock, len, 0);
    if (unlikely(ret < 0) && (errno == ENOTCONN || errno == ECONNRESET || errno == ECONNABORTED)) {
        __sync_fetch_and_sub(&sock->call_num, 1);
        return;
    }
    msg->result = 0;

    ret = do_lwip_replenish_sendring(stack, sock);
    if (ret > 0 && (__atomic_load_n(&sock->call_num, __ATOMIC_ACQUIRE) == 1)) {
        rpc_call_replenish(&stack->rpc_queue, sock);
        return;
    }

    __sync_fetch_and_sub(&sock->call_num, 1);
    return;
}

int rpc_call_udp_send(rpc_queue *queue, int fd, size_t len, int flags)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_udp_send);
    if (msg == NULL) {
        return -1;
    }

    if (get_protocol_stack_group()->latency_start) {
        time_stamp_into_rpcmsg(lwip_get_socket(fd));
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].size = len;
    msg->args[MSG_ARG_2].i = flags;

    rpc_async_call(queue, msg);
    return 0;
}

int rpc_call_tcp_send(rpc_queue *queue, int fd, size_t len, int flags)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_tcp_send);
    if (msg == NULL) {
        return -1;
    }

    if (get_protocol_stack_group()->latency_start) {
        time_stamp_into_rpcmsg(lwip_get_socket(fd));
    }

    msg->args[MSG_ARG_0].i = fd;
    msg->args[MSG_ARG_1].size = len;
    msg->args[MSG_ARG_2].i = flags;

    rpc_async_call(queue, msg);
    return 0;
}

static void callback_replenish_sendring(struct rpc_msg *msg)
{
    struct protocol_stack *stack = get_protocol_stack();
    struct lwip_sock *sock = (struct lwip_sock *)msg->args[MSG_ARG_0].p;

    msg->result = do_lwip_replenish_sendring(stack, sock);
    if (msg->result == true) {
        msg->recall_flag = 1;
        rpc_call(&stack->rpc_queue, msg);
    }
}

int rpc_call_replenish(rpc_queue *queue, void *sock)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_replenish_sendring);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].p = sock;

    rpc_async_call(queue, msg);
    return 0;
}

static void callback_recvlist_count(struct rpc_msg *msg)
{
    struct protocol_stack *stack = get_protocol_stack();
    struct list_node *list = &stack->recv_list;
    int count = 0;
    struct list_node *node;
    struct list_node *temp;

    list_for_each_node(node, temp, list) {
        count++;
    }
    msg->result = count;
}

int rpc_call_recvlistcnt(rpc_queue *queue)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_recvlist_count);
    if (msg == NULL) {
        return -1;
    }

    return rpc_sync_call(queue, msg);
}

static void callback_clean_epoll(struct rpc_msg *msg)
{
    struct protocol_stack *stack = get_protocol_stack();
    struct wakeup_poll *wakeup = (struct wakeup_poll *)msg->args[MSG_ARG_0].p;

    list_del_node(&wakeup->wakeup_list[stack->stack_idx]);
}

int rpc_call_clean_epoll(rpc_queue *queue, void *wakeup)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_clean_epoll);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].p = wakeup;

    rpc_sync_call(queue, msg);
    return 0;
}

static void callback_arp(struct rpc_msg *msg)
{
    struct rte_mbuf *mbuf = (struct rte_mbuf *)msg->args[MSG_ARG_0].p;
    struct protocol_stack *stack = get_protocol_stack();

    eth_dev_recv(mbuf, stack);
}

int rpc_call_arp(rpc_queue *queue, void *mbuf)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_arp);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].p = mbuf;

    rpc_async_call(queue, msg);
    return 0;
}

static void callback_mempool_size(struct rpc_msg *msg)
{
    struct protocol_stack *stack = get_protocol_stack();

    msg->result = rte_mempool_avail_count(stack->rxtx_mbuf_pool);
}

static void callback_get_conntable(struct rpc_msg *msg)
{
    struct gazelle_stat_lstack_conn_info *conn = (struct gazelle_stat_lstack_conn_info *)msg->args[MSG_ARG_0].p;
    unsigned max_num = msg->args[MSG_ARG_1].u;

    msg->result = do_lwip_get_conntable(conn, max_num);
}

static void callback_get_connnum(struct rpc_msg *msg)
{
    msg->result = do_lwip_get_connnum();
}

int rpc_call_conntable(rpc_queue *queue, void *conn_table, unsigned max_conn)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_get_conntable);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].p = conn_table;
    msg->args[MSG_ARG_1].u = max_conn;

    return rpc_sync_call(queue, msg);
}

int rpc_call_connnum(rpc_queue *queue)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_get_connnum);
    if (msg == NULL) {
        return -1;
    }

    return rpc_sync_call(queue, msg);
}

int rpc_call_mbufpoolsize(rpc_queue *queue)
{
    struct rpc_msg *msg = rpc_msg_alloc(callback_mempool_size);
    if (msg == NULL) {
        return -1;
    }

    return rpc_sync_call(queue, msg);
}

extern void thread_register_phase1(struct rpc_msg *msg);
int rpc_call_thread_regphase1(rpc_queue *queue, void *conn)
{
    struct rpc_msg *msg = rpc_msg_alloc(thread_register_phase1);
    if (msg == NULL) {
        return -1;
    }
    msg->args[MSG_ARG_0].p = conn;
    return rpc_sync_call(queue, msg);
}

extern void thread_register_phase2(struct rpc_msg *msg);
int rpc_call_thread_regphase2(rpc_queue *queue, void *conn)
{
    struct rpc_msg *msg = rpc_msg_alloc(thread_register_phase2);
    if (msg == NULL) {
        return -1;
    }
    msg->args[MSG_ARG_0].p = conn;
    return rpc_sync_call(queue, msg);
}
