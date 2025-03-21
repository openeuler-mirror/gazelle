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

#include <lwip/lwipgz_sock.h>
#include <lwip/priv/tcp_priv.h>

#include "lstack_log.h"
#include "lstack_cfg.h"
#include "lstack_stack_stat.h"
#include "lstack_protocol_stack.h"
#include "lstack_thread_rpc.h"
#include "lstack_mempool.h"

static struct rpc_stats g_rpc_stats;

struct rpc_stats *rpc_stats_get(void)
{
    return &g_rpc_stats;
}

__rte_always_inline
static void rpc_msg_init(struct rpc_msg *msg, rpc_func_t func)
{
    msg->func       = func;
    msg->flags      = 0;
    pthread_spin_init(&msg->lock, PTHREAD_PROCESS_PRIVATE);

    lockless_queue_node_set_poped(&msg->queue_node);
}

struct rpc_msg *rpc_msg_alloc(int stack_id, rpc_func_t func)
{
    struct rpc_msg *msg;

    msg = mem_get_rpc(stack_id);
    if (unlikely(msg == NULL)) {
        g_rpc_stats.call_alloc_fail++;
        return NULL;
    }

    rpc_msg_init(msg, func);
    return msg;
}

void rpc_msg_free(struct rpc_msg *msg)
{
    pthread_spin_destroy(&msg->lock);
    mem_put_rpc(msg);
}

void rpc_async_call(rpc_queue *queue, struct rpc_msg *msg, int flags)
{
    if (flags & RPC_MSG_RECALL)
        msg->flags |= flags;  /* if RECALL, keep the previous flags. */
    else
        msg->flags = flags & (~RPC_MSG_SYNC);

    if (msg->flags & RPC_MSG_REUSE)
        lockless_queue_mpsc_test_push(&queue->queue, &msg->queue_node);
    else
        lockless_queue_mpsc_push(&queue->queue, &msg->queue_node);

    intr_wakeup(queue->queue_id, INTR_REMOTE_EVENT);
}

int rpc_sync_call(rpc_queue *queue, struct rpc_msg *msg)
{
    int ret;

    pthread_spin_trylock(&msg->lock);

    msg->flags = RPC_MSG_SYNC;
    lockless_queue_mpsc_push(&queue->queue, &msg->queue_node);

    intr_wakeup(queue->queue_id, INTR_REMOTE_EVENT);

    // waiting stack unlock
    pthread_spin_lock(&msg->lock);

    ret = msg->result;
    rpc_msg_free(msg);
    return ret;
}

void rpc_queue_init(rpc_queue *queue, uint16_t queue_id)
{
    lockless_queue_init(&queue->queue);
    queue->queue_id = queue_id;
}

int rpc_msgcnt(rpc_queue *queue)
{
    return lockless_queue_count(&queue->queue);
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

        if (msg->flags & RPC_MSG_RECALL) {
            msg->flags &= ~RPC_MSG_RECALL;
            continue;
        }

        if (unlikely(msg->flags & RPC_MSG_EXIT)) {
            force_quit = 1;
        }

        if (msg->flags & RPC_MSG_SYNC) {
            pthread_spin_unlock(&msg->lock);
        }
        if (msg->flags & RPC_MSG_FREE) {
            rpc_msg_free(msg);
        }
    }

    return force_quit;
}


static void callback_arp(struct rpc_msg *msg)
{
    struct rte_mbuf *mbuf = (struct rte_mbuf *)msg->args[MSG_ARG_0].p;
    struct protocol_stack *stack = get_protocol_stack();

    eth_dev_recv(mbuf, stack);
}

int rpc_call_arp(int stack_id, void *mbuf)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_arp);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].p = mbuf;

    rpc_async_call(queue, msg, RPC_MSG_FREE);
    return 0;
}

static void copy_pcb_to_conn(struct gazelle_stat_lstack_conn_info *conn, const struct tcp_pcb *pcb)
{
    struct netconn *netconn = (struct netconn *)pcb->callback_arg;
    const struct mbox_ring *mr;

    conn->lip = *((gz_addr_t *)&pcb->local_ip);
    conn->rip = *((gz_addr_t *)&pcb->remote_ip);
    conn->l_port = pcb->local_port;
    conn->r_port = pcb->remote_port;
    conn->in_send = pcb->snd_queuelen;
    conn->tcp_sub_state = pcb->state;
    conn->cwn = pcb->cwnd;
    conn->rcv_wnd = pcb->rcv_wnd;
    conn->snd_wnd = pcb->snd_wnd;
    conn->snd_buf = pcb->snd_buf;
    conn->lastack = pcb->lastack;
    conn->snd_nxt = pcb->snd_nxt;
    conn->rcv_nxt = pcb->rcv_nxt;
    conn->keepalive = (ip_get_option(pcb, SOF_KEEPALIVE) != 0);
    conn->keep_idle = pcb->keep_idle;
    conn->keep_intvl = pcb->keep_intvl;
    conn->keep_cnt = pcb->keep_cnt;
    conn->pingpong = tcp_in_pingpong(pcb);

    if (netconn != NULL) {
        if (sys_mbox_valid(&netconn->recvmbox)) {
            mr = &netconn->recvmbox->mring;
            conn->recvmbox_cnt = mr->ops->recv_count(mr);
            conn->recvmbox_tail = mr->tail_count(mr);
        }
        if (sys_mbox_valid(&netconn->sendmbox)) {
            mr = &netconn->sendmbox->mring;
            conn->sendmbox_cnt = mr->ops->count(mr);
            conn->sendmbox_tail = mr->tail_count(mr);
        }

        conn->fd = netconn->callback_arg.socket;
        struct lwip_sock *sock = lwip_get_socket(netconn->callback_arg.socket);
        if (!POSIX_IS_CLOSED(sock)) {
            struct sock_event *sk_event = &sock->sk_event;
            conn->events = sk_event->pending;
            conn->epoll_events = sk_event->events;
            conn->eventlist = !list_node_null(&sk_event->event_node);
        }
    }
}

static uint32_t do_lwip_get_conntable(struct gazelle_stat_lstack_conn_info *conn,
                               uint32_t max_num)
{
    struct tcp_pcb *pcb = NULL;
    uint32_t conn_num = 0;
    const struct mbox_ring *mr;

    if (conn == NULL) {
        return -1;
    }

    for (pcb = tcp_active_pcbs; pcb != NULL && conn_num < max_num; pcb = pcb->next) {
        conn[conn_num].state = GAZELLE_ACTIVE_LIST;
        copy_pcb_to_conn(conn + conn_num, pcb);
        conn_num++;
    }

    for (pcb = tcp_tw_pcbs; pcb != NULL && conn_num < max_num; pcb = pcb->next) {
        conn[conn_num].state = GAZELLE_TIME_WAIT_LIST;
        copy_pcb_to_conn(conn + conn_num, pcb);
        conn_num++;
    }

    for (struct tcp_pcb_listen *pcbl = tcp_listen_pcbs.listen_pcbs; pcbl != NULL && conn_num < max_num;
        pcbl = pcbl->next) {
        conn[conn_num].state = GAZELLE_LISTEN_LIST;
        conn[conn_num].lip = *((gz_addr_t *)&pcbl->local_ip);
        conn[conn_num].l_port = pcbl->local_port;
        conn[conn_num].tcp_sub_state = pcbl->state;
        struct netconn *netconn = (struct netconn *)pcbl->callback_arg;
        conn[conn_num].fd = netconn != NULL ? netconn->callback_arg.socket : -1;
        if (netconn != NULL) {
            if (sys_mbox_valid(&netconn->acceptmbox)) {
                mr = &netconn->acceptmbox->mring;
                conn[conn_num].recvmbox_cnt = mr->ops->count(mr);
            }
        }
        conn_num++;
    }

    return conn_num;
}

static void callback_get_conntable(struct rpc_msg *msg)
{
    struct gazelle_stat_lstack_conn_info *conn = (struct gazelle_stat_lstack_conn_info *)msg->args[MSG_ARG_0].p;
    unsigned max_num = msg->args[MSG_ARG_1].u;

    msg->result = do_lwip_get_conntable(conn, max_num);
}

static uint32_t do_lwip_get_connnum(void)
{
    struct tcp_pcb *pcb = NULL;
    struct tcp_pcb_listen *pcbl = NULL;
    uint32_t conn_num = 0;

    for (pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
        conn_num++;
    }

    for (pcbl = tcp_listen_pcbs.listen_pcbs; pcbl != NULL; pcbl = pcbl->next) {
        conn_num++;
    }

    for (pcb = tcp_tw_pcbs; pcb != NULL; pcb = pcb->next) {
        conn_num++;
    }

    return conn_num;
}

static void callback_get_connnum(struct rpc_msg *msg)
{
    msg->result = do_lwip_get_connnum();
}

int rpc_call_conntable(int stack_id, void *conn_table, unsigned max_conn)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->dfx_rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_get_conntable);
    if (msg == NULL) {
        return -1;
    }

    msg->args[MSG_ARG_0].p = conn_table;
    msg->args[MSG_ARG_1].u = max_conn;

    return rpc_sync_call(queue, msg);
}

int rpc_call_connnum(int stack_id)
{
    rpc_queue *queue = &get_protocol_stack_by_id(stack_id)->dfx_rpc_queue;
    struct rpc_msg *msg = rpc_msg_alloc(stack_id, callback_get_connnum);
    if (msg == NULL) {
        return -1;
    }

    return rpc_sync_call(queue, msg);
}
