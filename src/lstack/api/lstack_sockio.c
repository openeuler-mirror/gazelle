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

#include <lwip/sockets.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/priv/api_msg.h>

#include "lstack_thread_rpc.h"
#include "lstack_log.h"
#include "lstack_sockio.h"
#include "lstack_wait.h"
#include "mbox_ring.h"
#include "lstack_epoll.h"
#include "lstack_stack_stat.h"


/* see lwip ip4_frag() and ip6_frag(), nfb must be a multiple of 8 */
#define IP_FRAG_NFB             ((GAZELLE_ETH_MTU - PBUF_IP) / 8)
#define UDP_MSS                 (IP_FRAG_NFB * 8 - UDP_HLEN)

#define IP4_UDP_SND_SIZE_MAX    (0xFFFF - IP_HLEN - UDP_HLEN)
#define IP6_UDP_SND_SIZE_MAX    (0xFFFF - IP6_HLEN - UDP_HLEN)
#define UDP_SND_SIZE_MAX(conn)  (NETCONNTYPE_ISIPV6(netconn_type(conn)) ? IP6_UDP_SND_SIZE_MAX : IP4_UDP_SND_SIZE_MAX)
#define UDP_SND_QUEUELEN_MAX    ((IP6_UDP_SND_SIZE_MAX + UDP_MSS - 1) / UDP_MSS)
#define UDP_SND_OUTPUT_NUM      (16)

#define TCP_SND_OUTPUT_NUM      OFFLOAD_TX_TSO_MTU_FRAGS
#define TCP_SND_QUEUELEN_MAX    OFFLOAD_TX_TSO_MTU_FRAGS
#define TCP_SND_SIZE_MAX        (TCP_SND_QUEUELEN_MAX * TCP_MSS)

#define TCP_SND_APPEND_LEN      (TCP_MSS >> 1)

#define RECV_EXTEND_CACHE_MAX   8
#define RECV_EXTEND_CACHE_LEN   (4 * TCP_MSS)

struct sockio_ops {
    ssize_t (*stack_udp_write)(struct lwip_sock *sock, const void *data, size_t len, int flags, 
                               const struct sockaddr *to, socklen_t tolen);
    void    (*stack_udp_send)(struct lwip_sock *sock);

    ssize_t (*stack_udp_readmsg)(struct lwip_sock *sock, struct msghdr *msg, size_t len, int flags);

    ssize_t (*stack_tcp_write)(struct lwip_sock *sock, const char *data, size_t len, int flags);
    void    (*stack_tcp_send)(struct lwip_sock *sock);

    ssize_t (*stack_tcp_read)(struct lwip_sock *sock, char *data, size_t len, int flags,
                              struct sockaddr *from, socklen_t *fromlen);
    void    (*stack_tcp_recvd)(struct lwip_sock *sock, ssize_t recvd, int flags);
};
static struct sockio_ops ioops = {0};


static unsigned pbuf_list_count(const struct mbox_ring *mr)
{
    struct pbuf *p = mr->ops->read_tail(mr);
    return pbuf_clen(p);
}

static unsigned netbuf_list_count(const struct mbox_ring *mr)
{
    struct netbuf *nbuf = mr->ops->read_tail(mr);
    return pbuf_clen(nbuf->p);
}

static void netbuf_obj_free(struct mbox_ring *mr, void *obj, bool is_tail)
{
    err_t err;
    if (unlikely(lwip_netconn_is_err_msg(obj, &err)))
        return;

    if (is_tail && (mr->flags & MBOX_FLAG_RECV)) {
        pbuf_free((struct pbuf *)obj);
    } else {
        netbuf_free((struct netbuf *)obj);
    }
}

static void pbuf_obj_free(struct mbox_ring *mr, void *obj, bool is_tail)
{
    err_t err;
    if (unlikely(lwip_netconn_is_err_msg(obj, &err)))
        return;
    pbuf_free((struct pbuf *)obj);
}

void sockio_mbox_set_func(struct mbox_ring *mr)
{
    mr->tail_count = pbuf_list_count;
    if (mr->flags & MBOX_FLAG_TCP) {
        /* only tcp sendmbox & recvmbox, lwip would free all acceptmbox newconn objs. */
        mr->obj_free_fn = pbuf_obj_free;
    } else if (mr->flags & MBOX_FLAG_UDP) {
        /* udp sendmbox & recvmbox */
        mr->obj_free_fn = netbuf_obj_free;
        if (mr->flags & MBOX_FLAG_SEND)
            mr->tail_count = netbuf_list_count;
    }
}

void sockio_peek_recv_free(struct mbox_ring *mr, unsigned n)
{
    void *buf_pkts[RECV_EXTEND_CACHE_MAX];
    unsigned num, i;

    mr->stk_queued_num += n;
    if (mr->stk_queued_num < (RECV_EXTEND_CACHE_MAX >> 1)) {
        return;
    }

    while (true) {
        num = mr->ops->dequeue_burst(mr, buf_pkts, RECV_EXTEND_CACHE_MAX);
        if (num == 0)
            break;
        if (mr->flags & MBOX_FLAG_UDP) {
            for (i = 0; i < num; ++i) {
                buf_pkts[i] = ((struct netbuf *)buf_pkts[i])->p;
            }
        }
        mem_put_pbuf_list_bulk((struct pbuf **)buf_pkts, num);
        mr->stk_queued_num -= num;
    }
}

static void sock_mbox_private_free(struct mbox_ring *mr)
{
    struct rpc_msg *msg = (struct rpc_msg *)mr->private_data;
    if (msg != NULL) {
        rpc_msg_free(msg);
        mr->private_data = NULL;
    }
}

static int sock_mbox_private_init(sys_mbox_t mb, rpc_func_t func)
{
    struct rpc_msg *msg = rpc_msg_alloc(get_protocol_stack()->stack_idx, true, func);
    if (msg == NULL)
        return -1;

    memset_s(msg->args, sizeof(msg->args), 0, sizeof(msg->args));

    mb->mring.private_data = msg;
    mb->mring.private_data_free_fn = sock_mbox_private_free;
    return 0;
}

static inline struct rpc_msg *sock_mbox_private_get(sys_mbox_t mb)
{
    return (struct rpc_msg *)mb->mring.private_data;
}


static inline uint16_t write_pbuf(struct pbuf *p, const char *data, uint16_t len, uint8_t optlen)
{
    mem_init_pbuf(p, PBUF_TRANSPORT, len, len, PBUF_POOL);
    if (optlen > 0) {
        /* see pbuf_remove_header() */
        p->payload = (uint8_t *)p->payload + optlen;
    }

    if (get_protocol_stack_group()->latency_start)
        time_stamp_into_write(&p, 1);

    pbuf_take(p, data, len);
    return len;
}

static inline void write_pbuf_bulk(struct pbuf *pbuf_pkts[], unsigned n, uint16_t payload_size, 
    const char *data, uint16_t len, uint8_t optlen)
{
    unsigned i;
    uint16_t copied_total = 0;

    for (i = 0; i < (n & ~0x3); i += 4) {
        rte_prefetch0(pbuf_pkts[i + 1]);
        rte_prefetch0(data + copied_total + payload_size);
        copied_total += write_pbuf(pbuf_pkts[i],     data + copied_total, payload_size, optlen);

        rte_prefetch0(pbuf_pkts[i + 2]);
        rte_prefetch0(data + copied_total + payload_size);
        copied_total += write_pbuf(pbuf_pkts[i + 1], data + copied_total, payload_size, optlen);

        rte_prefetch0(pbuf_pkts[i + 3]);
        rte_prefetch0(data + copied_total + payload_size);
        copied_total += write_pbuf(pbuf_pkts[i + 2], data + copied_total, payload_size, optlen);

        if (payload_size > len - copied_total)
            payload_size = len - copied_total;
        copied_total += write_pbuf(pbuf_pkts[i + 3], data + copied_total, payload_size, optlen);
    }
    switch (n & 0x3) {
    case 3:
        rte_prefetch0(pbuf_pkts[i + 1]);
        copied_total += write_pbuf(pbuf_pkts[i], data + copied_total, payload_size, optlen);
        ++i;    /* fallthrough */
    case 2:
        rte_prefetch0(pbuf_pkts[i + 1]);
        copied_total += write_pbuf(pbuf_pkts[i], data + copied_total, payload_size, optlen);
        ++i;    /* fallthrough */
    case 1:
        payload_size = len - copied_total;
        write_pbuf(pbuf_pkts[i], data + copied_total, payload_size, optlen);
        /* fallthrough */
    }
}

static inline void write_pbuf_list(struct pbuf *pbuf_pkts[], unsigned n, uint16_t payload_size, 
    const char *data, uint16_t len, uint8_t optlen)
{
    unsigned i;
    uint16_t copied_total = 0;

    for (i = 0; i < n - 1; ++i) {
        rte_prefetch0(pbuf_pkts[i + 1]);
        rte_prefetch0(data + copied_total + payload_size);
        write_pbuf(pbuf_pkts[i], data + copied_total, payload_size, optlen);
        pbuf_pkts[i]->next = pbuf_pkts[i + 1];
        pbuf_pkts[i]->tot_len = len - copied_total;
        copied_total += payload_size;
    }

    payload_size = len - copied_total;
    write_pbuf(pbuf_pkts[i], data + copied_total, payload_size, optlen);
    pbuf_pkts[i]->next = NULL;
}

static uint16_t stack_udp_write_one(const struct lwip_sock *sock, struct mbox_ring *mr, 
    const char *data, uint16_t len, int flags,
    const struct sockaddr *to, socklen_t tolen)
{
    struct pbuf **extcache_list = (struct pbuf **)&sock->conn->recvmbox->mring.st_obj;
    struct pbuf *p;
    struct netbuf *nbuf;

    p = mem_extcache_get_pbuf(sock->stack_id, true, extcache_list);
    if (p == NULL) {
        LSTACK_LOG(ERR, LSTACK, "mem_extcache_get_pbuf failed\n");
        set_errno(ENOMEM);
        return 0;
    }

    write_pbuf(p, data, len, 0);

    nbuf = netbuf_create(p);
    lwip_sendto_netbuf(sock->conn, nbuf, to, tolen);

    if (get_protocol_stack_group()->latency_start)
        calculate_lstack_latency(sock->stack_id, &nbuf->p, 1, GAZELLE_LATENCY_WRITE_INTO_RING, 0);

    mr->ops->enqueue_burst(mr, (void **)&nbuf, 1);
    mr->app_free_count -= 1;

    SOCK_WAIT_STAT(sock->sk_wait, app_write_cnt, 1);

    return len;
}

static uint16_t stack_udp_write_bulk(const struct lwip_sock *sock, struct mbox_ring *mr, 
    const char *data, uint16_t len, int flags,
    const struct sockaddr *to, socklen_t tolen)
{
    struct pbuf *pbuf_pkts[UDP_SND_QUEUELEN_MAX];
    unsigned pbuf_num = 0;
    struct netbuf *nbuf;
    uint16_t payload_size;
    uint8_t optlen;
    uint16_t copied_total = 0;

    if (NETCONNTYPE_ISIPV6(netconn_type(sock->conn))) {
        optlen = IP6_FRAG_HLEN;
        payload_size = UDP_MSS - IP6_FRAG_HLEN;
    } else {
        optlen = 0;
        payload_size = UDP_MSS;
    }

    /* step1. udp append data */
    nbuf = (struct netbuf *)mr->ops->pop_tail(mr, NULL);
    if (nbuf != NULL) {
        copied_total = LWIP_MIN(len, payload_size - nbuf->tail->len);
        pbuf_append_take(nbuf->p, nbuf->tail, data, copied_total, NULL);
        len -= copied_total;
    }

    /* step2. alloc a batch of pbufs */
    if (len > 0) {
        struct pbuf **extcache_list = (struct pbuf **)&sock->conn->recvmbox->mring.st_obj;
        pbuf_num = (len + payload_size - 1) / payload_size;
        pbuf_num = mem_extcache_get_pbuf_bulk(sock->stack_id, pbuf_pkts, pbuf_num, true, extcache_list);
        if (pbuf_num == 0) {
            /* drop netbuf */
            if (nbuf != NULL) {
                netbuf_free(nbuf);
            }
            LSTACK_LOG(ERR, LSTACK, "mem_extcache_get_pbuf_bulk failed, pbuf_num %u\n", pbuf_num);
            set_errno(ENOMEM);
            return 0;
        }

        write_pbuf_list(pbuf_pkts, pbuf_num, payload_size, data + copied_total, len, optlen);
        copied_total += len;

        if (nbuf == NULL) {
            nbuf = netbuf_create(pbuf_pkts[0]);
            lwip_sendto_netbuf(sock->conn, nbuf, to, tolen);
        } else {
            pbuf_cat(nbuf->p, pbuf_pkts[0]);
        }
        nbuf->tail = pbuf_pkts[pbuf_num - 1];
    }

    /* step3. enqueue the new netbuf */
    if ((flags & MSG_MORE) == 0) {
        if (get_protocol_stack_group()->latency_start)
            calculate_lstack_latency(sock->stack_id, &nbuf->p, 1, GAZELLE_LATENCY_WRITE_INTO_RING, 0);

        mr->ops->enqueue_burst(mr, (void **)&nbuf, 1);
        mr->app_free_count -= 1;
    } else {
        mr->ops->push_tail(mr, nbuf);
    }

    SOCK_WAIT_STAT(sock->sk_wait, app_write_cnt, pbuf_num);

    return copied_total;
}

static ssize_t stack_udp_write(struct lwip_sock *sock, const void *data, size_t len, int flags, 
    const struct sockaddr *to, socklen_t tolen)
{
    struct mbox_ring *mr = &sock->conn->sendmbox->mring;
    uint16_t copied_total;

    LWIP_DEBUGF(SOCKETS_DEBUG, ("%s(sock=%p, data=%p, size=%"SZT_F", flags=0x%x)\n",
                __FUNCTION__, sock, data, len, flags));

    if (unlikely(sock_event_hold_pending(sock, WAIT_BLOCK, NETCONN_EVT_ERROR, 0))) {
        set_errno(ENOTCONN);
        return -1;
    }

    if (unlikely(len > UDP_SND_SIZE_MAX(sock->conn))) {
        LSTACK_LOG(ERR, LSTACK, "Message too long\n");
        set_errno(EMSGSIZE);
        return -1;
    }

    if (unlikely(mr->app_free_count < 1)) {
        mr->app_free_count = mr->ops->free_count(mr);
        if (unlikely(mr->app_free_count < 1)) {
            API_EVENT(sock->conn, NETCONN_EVT_SENDMINUS, 0);
            set_errno(EWOULDBLOCK);
            return -1;
        }
    }

    if (len <= UDP_MSS && (flags & MSG_MORE) == 0) {
        copied_total = stack_udp_write_one(sock, mr, data, len, flags, to, tolen);
    } else {
        copied_total = stack_udp_write_bulk(sock, mr, data, len, flags, to, tolen);
    }

    return copied_total > 0 ? copied_total : -1;
}

static ssize_t stack_udp_output(struct netconn *conn, bool *output_again, struct mem_thread *mt)
{
    struct mbox_ring *mr = &conn->sendmbox->mring;
    err_t err;
    struct netbuf *nbuf_pkts[UDP_SND_OUTPUT_NUM];
    unsigned nbuf_num = 0;
    unsigned pbuf_num = 0;
    size_t send_total = 0;
    size_t send_len;

    *output_again = false;

    nbuf_num = mr->ops->dequeue_burst(mr, (void **)nbuf_pkts, UDP_SND_OUTPUT_NUM);
    if (unlikely(nbuf_num == 0)) {
        return 0;
    }
    if (unlikely(nbuf_num == UDP_SND_OUTPUT_NUM) && 
        mr->ops->count(mr) > 0) {
        *output_again = true;
    }

    for (unsigned i = 0; i < nbuf_num; ++i) {
        LWIP_DEBUGF(SOCKETS_DEBUG, ("%s(conn=%p, fd=%d, nbuf_pkts[%d]=%p {.p=%p, .tot_len=%u})\n",
                    __FUNCTION__, conn, conn->callback_arg.socket, 
                    i, nbuf_pkts[i], nbuf_pkts[i]->p, nbuf_pkts[i]->p->tot_len));

        if (get_protocol_stack_group()->latency_start)
            calculate_lstack_latency(get_protocol_stack()->stack_idx, &(nbuf_pkts[i]->p), 1, GAZELLE_LATENCY_WRITE_LWIP, 0);

        if (mt != NULL) {
            pbuf_num += pbuf_clen(nbuf_pkts[i]->p);
        }

        /* ip4_frag/ip6_frag would:
         * 1. split pbuf list and modify tot_len.
         * 2. free node of pbuf list, except for the pbuf head.
         */
        send_len = nbuf_pkts[i]->p->tot_len;
        /* This would add header 'UDP_HLEN' ! */
        err = netconn_send(conn, nbuf_pkts[i]);
        if (err != ERR_OK) {
            LSTACK_LOG(ERR, LSTACK, "netconn_send failed, err %d\n", err);
            break;
        }
        send_total += send_len;
    }
    for (unsigned i = 0; i < nbuf_num; ++i) {
        netbuf_free(nbuf_pkts[i]);
    }

    if (mt != NULL) {
        mem_mbuf_migrate_enqueue(mt, pbuf_num);
    }

    return (err == ERR_OK ? send_total : -1);
}

static void callback_udp_send(struct rpc_msg *msg)
{
    struct protocol_stack *stack = get_protocol_stack();
    struct lwip_sock *sock = msg->args[MSG_ARG_0].p;
    struct mem_thread *mt = msg->args[MSG_ARG_1].p;
    bool output_again;

    if (get_protocol_stack_group()->latency_start)
        calculate_sock_latency(sock, GAZELLE_LATENCY_WRITE_RPC_MSG);

    msg->result = stack_udp_output(sock->conn, &output_again, mt);
    if (output_again) {
        rpc_async_call(&stack->rpc_queue, msg, RPC_MSG_REUSE | RPC_MSG_RECALL);
    }

    return;
}

static inline int rpc_call_udp_send(rpc_queue *queue, struct lwip_sock *sock)
{
    struct rpc_msg *msg;

    if (get_protocol_stack_group()->latency_start)
        time_stamp_into_rpcmsg(sock);

    msg = sock_mbox_private_get(sock->conn->sendmbox);
    msg->args[MSG_ARG_0].p = sock;
    msg->args[MSG_ARG_1].p = mem_thread_migrate_get(sock->stack_id);

    rpc_async_call(queue, msg, RPC_MSG_REUSE);
    return 0;
}

static void rtw_stack_udp_send(struct lwip_sock *sock)
{
    struct protocol_stack *stack = get_protocol_stack_by_id(sock->stack_id);
    rpc_call_udp_send(&stack->rpc_queue, sock);
}

static void rtc_stack_udp_send(struct lwip_sock *sock)
{
    bool output_again;
    do {
        stack_udp_output(sock->conn, &output_again, NULL);
    } while (output_again);
}

static ssize_t stack_udp_readmsg(struct lwip_sock *sock, struct msghdr *msg, size_t len, int flags)
{
    struct mbox_ring *mr = &sock->conn->recvmbox->mring;
    struct pbuf **extcache_list;
    struct netbuf *nbuf;
    err_t err = ERR_OK;
    uint16_t copied_total = 0;

    LWIP_DEBUGF(SOCKETS_DEBUG, ("%s(sock=%p, msg=%p, size=%"SZT_F", flags=0x%x)\n",
                __FUNCTION__, sock, msg, len, flags));

    if (mr->ops->recv_start_burst(mr, (void **)&nbuf, 1) == 0) {
        if (unlikely(sock_event_hold_pending(sock, WAIT_BLOCK, NETCONN_EVT_ERROR, 0))) {
            err = ERR_CONN;
        } else {
            err = ERR_WOULDBLOCK;
        }
        goto out;
    }
    if (unlikely(lwip_netconn_is_err_msg(nbuf, &err))) {
        API_EVENT(sock->conn, NETCONN_EVT_RCVMINUS, 0);
        goto out;
    }

    if (get_protocol_stack_group()->latency_start)
        calculate_lstack_latency(sock->stack_id, &nbuf->p, 1, GAZELLE_LATENCY_READ_APP_CALL, sys_now_us());

    /* let not free inside by MSG_PEEK */
    sock->lastdata.netbuf = nbuf;
    err = lwip_recvfrom_udp_raw(sock, flags | MSG_PEEK, msg, &copied_total, 0);
    sock->lastdata.netbuf = NULL;

    SOCK_WAIT_STAT(sock->sk_wait, app_read_cnt, 1);
    SOCK_WAIT_STAT(sock->sk_wait, sock_rx_drop, copied_total < len ? 1 : 0);
    if (get_protocol_stack_group()->latency_start)
        calculate_lstack_latency(sock->stack_id, &nbuf->p, 1, GAZELLE_LATENCY_READ_LSTACK, 0);

    if (mr->flags & MBOX_FLAG_PEEK) {
        extcache_list = NULL;
    } else {
        extcache_list = (struct pbuf **)&mr->st_obj;
        mem_extcache_put_pbuf(nbuf->p, NULL, extcache_list);
    }

    mr->app_recvd_len += copied_total;
    mr->app_queued_num++;
    if (mr->app_queued_num >= RECV_EXTEND_CACHE_MAX || 
        mr->app_recvd_len >= RECV_EXTEND_CACHE_LEN) {
        if (extcache_list != NULL) {
            mem_extcache_flush_pbuf(extcache_list);
        }
        mr->ops->recv_finish_burst(mr);
        mr->app_queued_num = 0;
        mr->app_recvd_len = 0;
    }

    if (err == ERR_OK) {
        API_EVENT(sock->conn, NETCONN_EVT_RCVMINUS, copied_total);
        return copied_total;
    }
out:
    SOCK_WAIT_STAT(sock->sk_wait, read_null, 1);

    set_errno(err_to_errno(err));
    return -1;
}


static uint16_t rtw_stack_tcp_write_one(const struct lwip_sock *sock, struct mbox_ring *mr, 
    const char *data, uint16_t len, int flags)
{
    struct pbuf **extcache_list = (struct pbuf **)&sock->conn->recvmbox->mring.st_obj;
    struct pbuf *p;

    p = mem_extcache_get_pbuf(sock->stack_id, true, extcache_list);
    if (p == NULL) {
        LSTACK_LOG(ERR, LSTACK, "mem_extcache_get_pbuf failed\n");
        set_errno(ENOMEM);
        return 0;
    }

    write_pbuf(p, data, len, 0);
    if ((flags & MSG_MORE) == 0) {
        p->tcp_psh = 1;
    }

    if (get_protocol_stack_group()->latency_start)
        calculate_lstack_latency(sock->stack_id, &p, 1, GAZELLE_LATENCY_WRITE_INTO_RING, 0);

    mr->ops->enqueue_burst(mr, (void **)&p, 1);
    mr->app_free_count -= 1;

    SOCK_WAIT_STAT(sock->sk_wait, app_write_cnt, 1);

    return len;
}

static uint16_t rtw_stack_tcp_write_bulk(const struct lwip_sock *sock, struct mbox_ring *mr, 
    const char *data, uint16_t len, int flags)
{
    struct pbuf **extcache_list = (struct pbuf **)&sock->conn->recvmbox->mring.st_obj;
    unsigned pbuf_num;
    struct pbuf *pbuf_pkts[TCP_SND_QUEUELEN_MAX];
    struct pbuf *tail;

    pbuf_num = (len + TCP_MSS - 1) / TCP_MSS;
    pbuf_num = mem_extcache_get_pbuf_bulk(sock->stack_id, pbuf_pkts, pbuf_num, true, extcache_list);
    if (unlikely(pbuf_num == 0)) {
        LSTACK_LOG(ERR, LSTACK, "mem_extcache_get_pbuf_bulk failed, pbuf_num %u\n", pbuf_num);
        set_errno(ENOMEM);
        return 0;
    }

    write_pbuf_bulk(pbuf_pkts, pbuf_num, TCP_MSS, data, len, 0);

    SOCK_WAIT_STAT(sock->sk_wait, app_write_cnt, pbuf_num);
    if (get_protocol_stack_group()->latency_start)
        calculate_lstack_latency(sock->stack_id, pbuf_pkts, pbuf_num, GAZELLE_LATENCY_WRITE_INTO_RING, 0);

    tail = pbuf_pkts[pbuf_num - 1];
    if ((flags & MSG_MORE) == 0) {
        tail->tcp_psh = 1;
    }

    mr->app_tail_left = TCP_MSS - tail->tot_len;
    if (mr->app_tail_left > TCP_SND_APPEND_LEN) {
        pbuf_num--;
    } else {
        mr->app_tail_left = 0;
        tail = NULL;
    }

    /* must first enqueue before push_tail !!! */
    mr->app_free_count -= pbuf_num;
    mr->ops->enqueue_burst(mr, (void **)pbuf_pkts, pbuf_num);
    if (tail != NULL) {
        mr->ops->push_tail(mr, tail);
    }

    return len;
}

static inline bool tcp_seg_need_append(uint16_t oversize_left, uint16_t payload_size, uint16_t data_len, int flags)
{
    if (flags & MSG_MORE) {
        return true;
    }
    /* Avoid splitting once write len into 3 segs. */
    if ((data_len % payload_size) <= oversize_left)
        return true;
    return false;
}
static uint16_t rtw_stack_tcp_append(struct mbox_ring *mr, const char *data, uint16_t len, int flags)
{
    struct pbuf *p;
    bool need_append;
    uint16_t buf_copy_len;

    if (mr->app_tail_left == 0) {
        return 0;
    }

    buf_copy_len = 0;
    p = (struct pbuf *)mr->ops->pop_tail(mr, NULL);
    if (p != NULL) {
        need_append = tcp_seg_need_append(mr->app_tail_left, TCP_MSS, len, flags);
        if (need_append) {
            buf_copy_len = LWIP_MIN(len, mr->app_tail_left);
            pbuf_append_take(p, p, data, buf_copy_len, NULL);
        }
        mr->ops->enqueue_burst(mr, (void **)&p, 1);
        mr->app_free_count -= 1;
    }

    mr->app_tail_left = 0;

    return buf_copy_len;
}

static ssize_t rtw_stack_tcp_write(struct lwip_sock *sock, const char *data, size_t len, int flags)
{
    struct mbox_ring *mr = &sock->conn->sendmbox->mring;
    uint16_t buf_copy_len;
    uint32_t total_copy_len = (uint32_t)len;
    uint32_t copied_total = 0;

    LWIP_DEBUGF(SOCKETS_DEBUG, ("%s(sock=%p, data=%p, size=%"SZT_F", flags=0x%x)\n",
                __FUNCTION__, sock, data, len, flags));

    if (unlikely(sock_event_hold_pending(sock, WAIT_BLOCK, NETCONN_EVT_ERROR, 0))) {
        set_errno(ENOTCONN);
        return -1;
    }

    if (unlikely(mr->app_free_count < 2) || 
        total_copy_len > mr->app_free_count * TCP_MSS) {
        mr->app_free_count = mr->ops->free_count(mr);
        if (unlikely(mr->app_free_count < 2)) {
            API_EVENT(sock->conn, NETCONN_EVT_SENDMINUS, 0);
            set_errno(EWOULDBLOCK);
            return -1;
        }
    }

    copied_total = rtw_stack_tcp_append(mr, data, LWIP_MIN(TCP_MSS, total_copy_len), flags);
    SOCK_WAIT_STAT(sock->sk_wait, sock_tx_merge, copied_total > 0 ? 1 : 0);
    if (copied_total == total_copy_len) {
        return copied_total;
    }

    if (total_copy_len <= TCP_MSS) {
        /* write one pbuf */
        copied_total += rtw_stack_tcp_write_one(sock, mr, data + copied_total, total_copy_len, flags);
    } else {
        if (total_copy_len > mr->app_free_count * TCP_MSS) {
            total_copy_len = mr->app_free_count * TCP_MSS;
        }
        /* write bulk pbuf */
        while (total_copy_len > 0) {
            buf_copy_len = LWIP_MIN(total_copy_len, TCP_SND_SIZE_MAX);
            buf_copy_len = rtw_stack_tcp_write_bulk(sock, mr, data + copied_total, buf_copy_len, flags);
            if (unlikely(buf_copy_len == 0)) {
                goto out;
            }
            copied_total += buf_copy_len;
            total_copy_len -= buf_copy_len;
        }
    }

out:
    return copied_total > 0 ? copied_total : -1;
}

static struct pbuf *rtw_tcp_output_pop_tail(struct mbox_ring *mr)
{
    void *tail;

    tail = mr->ops->read_tail(mr);
    if (tail == NULL)
        return NULL;

    if (mr->ops->count(mr) > 0)
        return NULL;
    return mr->ops->pop_tail(mr, tail);
}

static uint16_t rtw_stack_tcp_output(struct netconn *conn, bool *output_again, struct mem_thread *mt)
{
    struct mbox_ring *mr = &conn->sendmbox->mring;
    struct pbuf *pbuf_pkts[TCP_SND_OUTPUT_NUM];
    uint16_t pbuf_num;

    *output_again = false;

    /* must first dequeue before pop_tail !!! */
    pbuf_num = mr->ops->dequeue_burst(mr, (void **)pbuf_pkts, TCP_SND_OUTPUT_NUM);

    if (pbuf_num < TCP_SND_OUTPUT_NUM) {
        if (pbuf_num == 0 || pbuf_pkts[pbuf_num - 1]->len == TCP_MSS) {
            pbuf_pkts[pbuf_num] = rtw_tcp_output_pop_tail(mr);
            if (pbuf_pkts[pbuf_num] != NULL) {
                pbuf_num++;
            }
        }

        if (unlikely(pbuf_num == 0)) {
            return 0;
        }
    } else {
        if (mr->ops->count(mr) > 0 || mr->ops->read_tail(mr) != NULL) {
            *output_again = true;
        }
    }

    LWIP_DEBUGF(SOCKETS_DEBUG, ("%s(conn=%p, fd=%d, pbuf_num=%u)\n",
                __FUNCTION__, conn, conn->callback_arg.socket, pbuf_num));

    if (get_protocol_stack_group()->latency_start)
        calculate_lstack_latency(get_protocol_stack()->stack_idx, pbuf_pkts, pbuf_num, GAZELLE_LATENCY_WRITE_LWIP, 0);

    if (mt != NULL) {
        mem_mbuf_migrate_enqueue(mt, pbuf_num);
    }

    if (pbuf_num > 1) {
        lwip_tcp_tso_merge_seg(conn->pcb.tcp, pbuf_pkts, &pbuf_num);
    }
    return lwip_tcp_prepare_seg(conn->pcb.tcp, pbuf_pkts, pbuf_num);
}


static uint32_t pbuf_copy_and_free(struct pbuf **left_pbuf, struct pbuf **extcache_list, char *data, uint32_t len)
{
    struct pbuf *q, *t;
    uint16_t buf_copy_len;
    uint32_t copied_total = 0;

    q = *left_pbuf;
    t = NULL;
    while (copied_total < len && q != NULL) {
        buf_copy_len = LWIP_MIN(q->len, len - copied_total);

        if (buf_copy_len > 0) {
            MEMCPY(data + copied_total, q->payload, buf_copy_len);
            copied_total += buf_copy_len;

            if (buf_copy_len < q->len) {
                pbuf_remove_header(q, buf_copy_len);
                break;
            } else {
                q->tot_len = q->len = 0;
            }
        }

        t = q;
        q = q->next;
    }

    if (t != NULL && extcache_list != NULL) {
        t->next = NULL;
        mem_extcache_put_pbuf(*left_pbuf, t, extcache_list);
    }
    *left_pbuf = q;

    return copied_total;
}

static ssize_t stack_tcp_read(struct lwip_sock *sock, char *data, size_t len, int flags,
    struct sockaddr *from, socklen_t *fromlen)
{
    struct mbox_ring *mr = &sock->conn->recvmbox->mring;
    struct pbuf **extcache_list;
    err_t err = ERR_OK;
    struct pbuf *p = NULL;

    uint32_t buf_copy_len;
    uint32_t total_copy_len = len;
    uint32_t copied_total = 0;

    LWIP_DEBUGF(SOCKETS_DEBUG, ("%s(sock=%p, data=%p, size=%"SZT_F", flags=0x%x)\n",
                __FUNCTION__, sock, data, len, flags));

    if (mr->flags & MBOX_FLAG_PEEK) {
        extcache_list = NULL;
    } else {
        extcache_list = (struct pbuf **)&mr->st_obj;
    }

    while (total_copy_len > 0) {
        if (sock->lastdata.pbuf == NULL) {
            if (mr->ops->recv_start_burst(mr, (void **)&sock->lastdata.pbuf, 1) == 0) {
                if (unlikely(sock_event_hold_pending(sock, WAIT_BLOCK, NETCONN_EVT_ERROR, 0))) {
                    err = ERR_CONN;
                } else {
                    err = ERR_WOULDBLOCK;
                }
                break;
            }
            mr->app_queued_num++;
            SOCK_WAIT_STAT(sock->sk_wait, app_read_cnt, 1);
        }

        if (unlikely(lwip_netconn_is_err_msg(sock->lastdata.pbuf, &err))) {
            API_EVENT(sock->conn, NETCONN_EVT_RCVMINUS, copied_total);
            break;
        }

        if (get_protocol_stack_group()->latency_start) {
            p = sock->lastdata.pbuf;
            calculate_lstack_latency(sock->stack_id, &p, 1, GAZELLE_LATENCY_READ_APP_CALL, sys_now_us());
        }

        // TODO: support MSG_PEEK
        buf_copy_len = pbuf_copy_and_free(&sock->lastdata.pbuf, extcache_list, data + copied_total, total_copy_len);
        copied_total += buf_copy_len;
        total_copy_len -= buf_copy_len;
        mr->app_recvd_len += buf_copy_len;

        if (get_protocol_stack_group()->latency_start) {
            calculate_lstack_latency(sock->stack_id, &p, 1, GAZELLE_LATENCY_READ_LSTACK, 0);
            p = NULL;
        }

        if (mr->app_queued_num >= RECV_EXTEND_CACHE_MAX || 
            mr->app_recvd_len >= RECV_EXTEND_CACHE_LEN) {
            if (sock->lastdata.pbuf == NULL) {
                mr->ops->recv_finish_burst(mr);
                mr->app_queued_num = 0;
            }
        }
    }

    if (mr->app_recvd_len >= RECV_EXTEND_CACHE_LEN) {
        if (extcache_list != NULL) {
            mem_extcache_flush_pbuf(extcache_list);
        }
        mr->app_recvd_len = 0;
    }

    lwip_tcp_recv_from(sock->conn, from, fromlen, copied_total);

    if (copied_total > 0) {
        API_EVENT(sock->conn, NETCONN_EVT_RCVMINUS, copied_total);
        return copied_total;
    }

    SOCK_WAIT_STAT(sock->sk_wait, read_null, 1);

    set_errno(err_to_errno(err));
    if (err == ERR_CLSD) {
        return 0;
    }
    return -1;
}


#if GAZELLE_TCP_ASYNC_RECVD
#define RECVD_UNSUBMITED(msg)  ((msg)->args[MSG_ARG_2].ul)
static inline bool rpc_submit_tcp_recvd(struct rpc_msg *recvmsg, size_t threshold, size_t recvd)
{
    RECVD_UNSUBMITED(recvmsg) += recvd;
    if (RECVD_UNSUBMITED(recvmsg) >= threshold) {
        RECVD_UNSUBMITED(recvmsg) = 0;
        return true;
    }
    return false;
}

static void callback_tcp_recvd(struct rpc_msg *recvmsg)
{
    struct lwip_sock *sock = recvmsg->args[MSG_ARG_0].p;
    struct mbox_ring *mr;
    u32_t recvd;

    mr = &sock->conn->recvmbox->mring;
    if (mr->flags & MBOX_FLAG_PEEK) {
        sockio_peek_recv_free(mr, 0);
    }

    recvd = lwip_netconn_get_recvd(sock->conn, 0, 0);
    lwip_netconn_update_recvd(sock->conn, recvd);
    recvmsg->result = recvd;
    return;
}

static inline int rpc_call_tcp_recvd(rpc_queue *queue, struct lwip_sock *sock, size_t recvd, int flags)
{
    struct rpc_msg *recvmsg;

    recvmsg = sock_mbox_private_get(sock->conn->recvmbox);
    recvmsg->args[MSG_ARG_0].p  = sock;
    recvmsg->result = 0;

    if (rpc_submit_tcp_recvd(recvmsg, TCP_WND >> 1, recvd)) {
        rpc_async_call(queue, recvmsg, RPC_MSG_REUSE);
    }
    return 0;
}
#endif /* GAZELLE_TCP_ASYNC_RECVD */

static void rtw_stack_tcp_recvd(struct lwip_sock *sock, ssize_t recvd, int flags)
{
#if GAZELLE_TCP_ASYNC_RECVD
    struct protocol_stack *stack = get_protocol_stack_by_id(sock->stack_id);

    if (recvd <= 0 || flags & MSG_PEEK) {
        return;
    }
    rpc_call_tcp_recvd(&stack->rpc_queue, sock, recvd, flags);
#endif /* GAZELLE_TCP_ASYNC_RECVD */
}

static void rtc_stack_tcp_recvd(struct lwip_sock *sock, ssize_t recvd, int flags)
{
    if (recvd <= 0 || flags & MSG_PEEK) {
        return;
    }
    lwip_tcp_recvd(sock->conn, recvd, flags);
}

static void callback_tcp_send(struct rpc_msg *sendmsg)
{
    struct protocol_stack *stack = get_protocol_stack();
    struct lwip_sock *sock = sendmsg->args[MSG_ARG_0].p;
    struct mem_thread *mt = sendmsg->args[MSG_ARG_1].p;
    bool output_again;
    err_t err;

    if (unlikely(sock->conn->pcb.tcp == NULL))
        return;

    if (get_protocol_stack_group()->latency_start)
        calculate_sock_latency(sock, GAZELLE_LATENCY_WRITE_RPC_MSG);

    do {
        if (!lwip_tcp_allow_send(sock->conn->pcb.tcp)) {
            rpc_async_call(&stack->rpc_queue, sendmsg, RPC_MSG_REUSE | RPC_MSG_RECALL);
            break;
        }
        sendmsg->result += rtw_stack_tcp_output(sock->conn, &output_again, mt);
    } while (output_again);
    err = tcp_output(sock->conn->pcb.tcp);
    if (unlikely(err != ERR_OK)) {
        LSTACK_LOG(ERR, LSTACK, "tcp_output failed, sock %p, err %u\n", sock, err);
    }

#if GAZELLE_TCP_ASYNC_RECVD
    struct rpc_msg *recvmsg;
    if (RECVD_UNSUBMITED(sendmsg)) {
        RECVD_UNSUBMITED(sendmsg) = 0;
        recvmsg = sock_mbox_private_get(sock->conn->recvmbox);
        callback_tcp_recvd(recvmsg);
    }
#endif /* GAZELLE_TCP_ASYNC_RECVD */

    return;
}

static inline int rpc_call_tcp_send(rpc_queue *queue, struct lwip_sock *sock)
{
    struct rpc_msg *sendmsg;

    if (get_protocol_stack_group()->latency_start)
        time_stamp_into_rpcmsg(sock);

    sendmsg = sock_mbox_private_get(sock->conn->sendmbox);
    sendmsg->result = 0;
    sendmsg->args[MSG_ARG_0].p = sock;
    sendmsg->args[MSG_ARG_1].p = mem_thread_migrate_get(sock->stack_id);

#if GAZELLE_TCP_ASYNC_RECVD
    struct rpc_msg *recvmsg;
    recvmsg = sock_mbox_private_get(sock->conn->recvmbox);
    RECVD_UNSUBMITED(sendmsg) = rpc_submit_tcp_recvd(recvmsg, TCP_WND >> 2, 0);
#endif /* GAZELLE_TCP_ASYNC_RECVD */

    rpc_async_call(queue, sendmsg, RPC_MSG_REUSE);
    return 0;
}

static void rtw_stack_tcp_send(struct lwip_sock *sock)
{
    struct protocol_stack *stack = get_protocol_stack_by_id(sock->stack_id);
    rpc_call_tcp_send(&stack->rpc_queue, sock);
}


static ssize_t rtc_stack_tcp_write(struct lwip_sock *sock, const char *data, size_t len, int flags)
{
    struct tcp_pcb *pcb = sock->conn->pcb.tcp;
    err_t err = ERR_OK;
    int write_flags, write_more;

    uint16_t buf_copy_len;
    uint32_t total_copy_len;
    uint32_t copied_total = 0;

    write_more = TCP_WRITE_FLAG_MORE;
    write_flags = NETCONN_COPY |
                  ((flags & MSG_MORE)     ? NETCONN_MORE      : 0) |
                  ((flags & MSG_DONTWAIT) ? NETCONN_DONTBLOCK : 0);

    if (unlikely(sock_event_hold_pending(sock, WAIT_BLOCK, NETCONN_EVT_ERROR, 0))) {
        set_errno(ENOTCONN);
        return -1;
    }

    total_copy_len = LWIP_MIN((uint32_t)len, (uint32_t)pcb->snd_buf);
    if (unlikely(total_copy_len == 0)) {
        API_EVENT(sock->conn, NETCONN_EVT_SENDMINUS, 0);
        set_errno(EWOULDBLOCK);
        return -1;
    }

    while (total_copy_len > 0) {
        if (total_copy_len <= TCP_SND_SIZE_MAX) {
            buf_copy_len = total_copy_len;
            write_more = 0;
        } else {
            buf_copy_len = TCP_SND_SIZE_MAX;
        }

        err = tcp_write(pcb, data + copied_total, buf_copy_len, write_flags | write_more);
        if (err != ERR_OK) {
            LSTACK_LOG(ERR, LSTACK, "tcp_write failed, errno %d\n", err_to_errno(err));
            break;
        }
        total_copy_len -= buf_copy_len;
        copied_total += buf_copy_len;
    }

    if (copied_total > 0) {
        return copied_total;
    }
    set_errno(err_to_errno(err));
    return -1;
}

static void rtc_stack_tcp_send(struct lwip_sock *sock)
{
    tcp_output(sock->conn->pcb.tcp);
}


ssize_t sockio_recvfrom(int fd, void *mem, size_t len, int flags,
    struct sockaddr *from, socklen_t *fromlen)
{
    struct lwip_sock *sock = lwip_get_socket(fd);
    ssize_t recvd;
    struct iovec vec;
    struct msghdr msg;

    LWIP_DEBUGF(SOCKETS_DEBUG, ("%s(%d, mem=%p, size=%"SZT_F", flags=0x%x)\n",
                __FUNCTION__, fd, mem, len, flags));

    if (unlikely(mem == NULL || len <= 0)) {
        set_errno(EINVAL);
        return -1;
    }

    if (unlikely(!sock->affinity_numa)) {
        thread_bind_stack(sock->stack_id);
        sock->affinity_numa = true;
    }

    switch (NETCONN_TYPE(sock->conn)) {
    case NETCONN_TCP:
        /* TODO: support MSG_WAITALL */
        recvd = ioops.stack_tcp_read(sock, mem, len, flags, from, fromlen);
        if (recvd < 0 && errno == EWOULDBLOCK) {
            if (sock_event_wait(sock, NETCONN_EVT_RCVPLUS, netconn_is_nonblocking(sock->conn) || (flags & MSG_DONTWAIT))) {
                recvd = ioops.stack_tcp_read(sock, mem, len, flags, from, fromlen);
            }
        }
        if (recvd > 0) {
            ioops.stack_tcp_recvd(sock, recvd, flags);
        }
        break;
    case NETCONN_UDP:
        vec.iov_base = mem;
        vec.iov_len = len;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;
        msg.msg_iov = &vec;
        msg.msg_iovlen = 1;
        msg.msg_name = from;
        msg.msg_namelen = (fromlen ? *fromlen : 0);
        recvd = ioops.stack_udp_readmsg(sock, &msg, len, flags);
        if (recvd < 0 && errno == EWOULDBLOCK) {
            if (sock_event_wait(sock, NETCONN_EVT_RCVPLUS, netconn_is_nonblocking(sock->conn) || (flags & MSG_DONTWAIT))) {
                recvd = ioops.stack_udp_readmsg(sock, &msg, len, flags);
            }
        }
        if (recvd > 0 && fromlen != NULL) {
            *fromlen = msg.msg_namelen;
        }
        break;
    default:
        recvd = -1;
        break;
    }

    return recvd;
}

ssize_t sockio_recvmsg(int fd, struct msghdr *msg, int flags)
{
    struct lwip_sock *sock = lwip_get_socket(fd);
    ssize_t len, recvd = 0;

    len = lwip_recvmsg_check(NULL, msg, flags);
    if (unlikely(len <= 0)) {
        return len;
    }

    if (unlikely(!sock->affinity_numa)) {
        thread_bind_stack(sock->stack_id);
        sock->affinity_numa = true;
    }

    switch (NETCONN_TYPE(sock->conn)) {
    case NETCONN_TCP:
        for (int i = 0; i < msg->msg_iovlen; ++i) {
            len = sockio_recvfrom(fd, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, flags, NULL, NULL);
            if (len <= 0) {
                if (recvd == 0)
                    recvd = len;
                break;
            }
            recvd += len;
        }
        break;
    case NETCONN_UDP:
        recvd = ioops.stack_udp_readmsg(sock, msg, len, flags);
        if (recvd < 0 && errno == EWOULDBLOCK) {
            if (sock_event_wait(sock, NETCONN_EVT_RCVPLUS, netconn_is_nonblocking(sock->conn) || (flags & MSG_DONTWAIT))) {
                recvd = ioops.stack_udp_readmsg(sock, msg, len, flags);
            }
        }
        break;
    default:
        recvd = -1;
        break;
    }

    return recvd;
}

ssize_t sockio_sendto(int fd, const void *mem, size_t len, int flags,
    const struct sockaddr *to, socklen_t tolen)
{
    struct lwip_sock *sock = lwip_get_socket(fd);
    ssize_t ret;

    LWIP_DEBUGF(SOCKETS_DEBUG, ("%s(%d, mem=%p, size=%"SZT_F", flags=0x%x)\n",
                __FUNCTION__, fd, mem, len, flags));

    if (unlikely(mem == NULL || len <= 0)) {
        set_errno(EINVAL);
        return -1;
    }

    if (unlikely(!sock->affinity_numa)) {
        thread_bind_stack(sock->stack_id);
        sock->affinity_numa = true;
    }

    switch (NETCONN_TYPE(sock->conn)) {
    case NETCONN_TCP:
        ret = ioops.stack_tcp_write(sock, mem, len, flags);
        if (ret < 0) {
            if (errno == EWOULDBLOCK) {
                sock_event_wait(sock, NETCONN_EVT_SENDPLUS, true);
            }
        } else {
            ioops.stack_tcp_send(sock);
        }
        break;
    case NETCONN_UDP:
        ret = ioops.stack_udp_write(sock, mem, len, flags, to, tolen);
        if (ret < 0) {
            if (errno == EWOULDBLOCK) {
                sock_event_wait(sock, NETCONN_EVT_SENDPLUS, true);
            }
        } else {
            ioops.stack_udp_send(sock);
        }
        break;
    default:
        ret = -1;
        break;
    }

    return ret;
}

ssize_t sockio_sendmsg(int fd, const struct msghdr *msg, int flags)
{
    struct lwip_sock *sock = lwip_get_socket(fd);
    ssize_t ret = -1;
    size_t written = 0;
    int write_more = MSG_MORE;
    int i;

    ret = lwip_sendmsg_check(sock, msg, flags);
    if (unlikely(ret <= 0)) {
        return ret;
    }

    if (unlikely(!sock->affinity_numa)) {
        thread_bind_stack(sock->stack_id);
        sock->affinity_numa = true;
    }

    switch (NETCONN_TYPE(sock->conn)) {
    case NETCONN_TCP:
        for (i = 0; i < msg->msg_iovlen; ++i) {
            if (i == msg->msg_iovlen - 1) {
                write_more = 0;
            }
            ret = ioops.stack_tcp_write(sock, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, flags | write_more);
            if (ret < 0) {
                if (errno == EWOULDBLOCK) {
                    sock_event_wait(sock, NETCONN_EVT_SENDPLUS, true);
                }
                break;
            }
            written += ret;
        }
        if (written > 0) {
            ioops.stack_tcp_send(sock);
        }
        break;
    case NETCONN_UDP:
        for (i = 0; i < msg->msg_iovlen; ++i) {
            if (i == msg->msg_iovlen - 1) {
                write_more = 0;
            }
            ret = ioops.stack_udp_write(sock, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, flags | write_more, NULL, 0);
            if (ret < 0) {
                if (errno == EWOULDBLOCK) {
                    sock_event_wait(sock, NETCONN_EVT_SENDPLUS, true);
                }
                break;
            }
            written += ret;
        }
        if (written > 0) {
            ioops.stack_udp_send(sock);
        }
        break;
    default:
        written = -1;
        break;
    }

    return written > 0 ? written : ret;
}

ssize_t sockio_read(int fd, void *mem, size_t len)
{
    return sockio_recvfrom(fd, mem, len, 0, NULL, NULL);
}

ssize_t sockio_write(int fd, const void *mem, size_t len)
{
    return sockio_sendto(fd, mem, len, 0, NULL, 0);
}

ssize_t sockio_recv(int fd, void *mem, size_t len, int flags)
{
    return sockio_recvfrom(fd, mem, len, flags, NULL, NULL);
}

ssize_t sockio_send(int fd, const void *mem, size_t len, int flags)
{
    return sockio_sendto(fd, mem, len, flags, NULL, 0);
}

ssize_t sockio_readv(int fd, const struct iovec *iov, int iovcnt)
{
    struct msghdr msg;

    msg.msg_name    = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov     = LWIP_CONST_CAST(struct iovec *, iov);
    msg.msg_iovlen  = iovcnt;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags   = 0;

    return sockio_recvmsg(fd, &msg, 0);
}

ssize_t sockio_writev(int fd, const struct iovec *iov, int iovcnt)
{
    struct msghdr msg;

    msg.msg_name    = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov     = LWIP_CONST_CAST(struct iovec *, iov);
    msg.msg_iovlen  = iovcnt;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags   = 0;

    return sockio_sendmsg(fd, &msg, 0);
}

void sockio_ops_init(void)
{
    struct sockio_ops *ops = &ioops;

    ops->stack_udp_write = stack_udp_write;
    ops->stack_udp_readmsg = stack_udp_readmsg;
    ops->stack_tcp_read  = stack_tcp_read;

    if (get_global_cfg_params()->stack_mode_rtc) {
        ops->stack_udp_send  = rtc_stack_udp_send;
        ops->stack_tcp_write = rtc_stack_tcp_write;
        ops->stack_tcp_send  = rtc_stack_tcp_send;
        ops->stack_tcp_recvd = rtc_stack_tcp_recvd;
    } else {
        ops->stack_udp_send  = rtw_stack_udp_send;
        ops->stack_tcp_write = rtw_stack_tcp_write;
        ops->stack_tcp_send  = rtw_stack_tcp_send;
        ops->stack_tcp_recvd = rtw_stack_tcp_recvd;
    }
}

static int sockio_mbox_init(struct lwip_sock *sock)
{
    int ret;
    sys_mbox_t sendmbox = sock->conn->sendmbox;
    sys_mbox_t recvmbox = sock->conn->recvmbox;

    if (get_global_cfg_params()->stack_mode_rtc) {
        return 0;
    }

    switch (NETCONN_TYPE(sock->conn)) {
    case NETCONN_TCP:
        ret = sock_mbox_private_init(sendmbox, callback_tcp_send);
#if GAZELLE_TCP_ASYNC_RECVD
        if (sys_mbox_valid(&recvmbox)) {
            ret |= sock_mbox_private_init(recvmbox, callback_tcp_recvd);
        }
#endif /* GAZELLE_TCP_ASYNC_RECVD */
        break;
    case NETCONN_UDP:
        ret = sock_mbox_private_init(sendmbox, callback_udp_send);
        break;
    default:
        ret = 0;
    }

    if (ret != 0) {
        sock_mbox_private_free(&sendmbox->mring);
        if (sys_mbox_valid(&recvmbox)) {
            sock_mbox_private_free(&recvmbox->mring);
        }
    }
    return ret;
}

bool sockio_mbox_pending(struct lwip_sock *sock)
{
    const struct rpc_msg *msg;
    const struct mbox_ring *mr;
    err_t err;

    if (POSIX_IS_CLOSED(sock))
        return false;

    if (sys_mbox_valid(&sock->conn->sendmbox)) {
        msg = sock_mbox_private_get(sock->conn->sendmbox);
        if (msg != NULL && !lockless_queue_node_is_poped(&msg->queue_node)) {
            return true;
        }
    }
    if (sys_mbox_valid(&sock->conn->recvmbox)) {
        msg = sock_mbox_private_get(sock->conn->recvmbox);
        if (msg != NULL && !lockless_queue_node_is_poped(&msg->queue_node)) {
            return true;
        }

        /* PEEK lastdata is only used to mark the last read location and not for releasing.
         * all peek bufs should free after pk_ring_dequeue_burst. */
        mr = &sock->conn->recvmbox->mring;
        if (mr->flags & MBOX_FLAG_PEEK && mr->flags & MBOX_FLAG_TCP) {
            if (sock->lastdata.pbuf != NULL && 
                !lwip_netconn_is_err_msg(sock->lastdata.pbuf, &err)) {
                sock->lastdata.pbuf = NULL;
            }
        }
    }

    return false;
}

int do_lwip_init_sock(int fd)
{
    int ret;
    struct protocol_stack *stack = get_protocol_stack();
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (sock == NULL) {
        return -1;
    }

    sock->type = 0;
    sock->listen_next = NULL;
    sock->stack_id = stack->stack_idx;

    /* RTC affinity by stack_setup_app_thread() */
    if (get_global_cfg_params()->stack_mode_rtc) {
        sock->affinity_numa = true;
    } else {
        sock->affinity_numa = false;
    }

    sock->sk_wait = NULL;
    ret = sock_event_init(&sock->sk_event);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "sock_event_init failed\n");
        return -1;
    }

    ret = sockio_mbox_init(sock);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "sockio_mbox_init failed\n");
        return -1;
    }

    get_protocol_stack_by_id(sock->stack_id)->conn_num++;
    return 0;
}

void do_lwip_clean_sock(int fd)
{
    struct lwip_sock *sock = lwip_get_socket(fd);
    if (POSIX_IS_CLOSED(sock)) {
        return;
    }

    sock_event_free(&sock->sk_event, sock->sk_wait);
    sock->sk_wait = NULL;

    sock->listen_next = NULL;

    get_protocol_stack_by_id(sock->stack_id)->conn_num--;
    sock->stack_id = -1;
}
