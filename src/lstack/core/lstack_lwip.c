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

#include <sys/types.h>
#include <stdatomic.h>
#include <lwip/sockets.h>
#include <lwip/tcp.h>
#include <lwipsock.h>
#include <arch/sys_arch.h>
#include <lwip/pbuf.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/posix_api.h>
#include <securec.h>
#include <rte_errno.h>
#include <rte_malloc.h>

#include "gazelle_base_func.h"
#include "lstack_ethdev.h"
#include "lstack_protocol_stack.h"
#include "lstack_log.h"
#include "lstack_dpdk.h"
#include "lstack_stack_stat.h"
#include "lstack_lwip.h"

#define HALF_DIVISOR                    (2)
#define USED_IDLE_WATERMARK             (VDEV_IDLE_QUEUE_SZ >> 2)

void listen_list_add_node(int32_t head_fd, int32_t add_fd)
{
    struct lwip_sock *sock = NULL;
    int32_t fd = head_fd;

    while (fd > 0) {
        sock = get_socket(fd);
        if (sock == NULL) {
            LSTACK_LOG(ERR, LSTACK, "tid %ld, %d get sock null\n", get_stack_tid(), fd);
            return;
        }
        fd = sock->nextfd;
    }
    sock->nextfd = add_fd;
}

static void free_ring_pbuf(struct rte_ring *ring)
{
    while (1) {
        struct pbuf *pbuf = NULL;
        int32_t ret = rte_ring_sc_dequeue(ring, (void **)&pbuf);
        if (ret != 0) {
            break;
        }

        pbuf_free(pbuf);
    }
}

static void reset_sock_data(struct lwip_sock *sock)
{
    /* check null pointer in ring_free func */
    if (sock->recv_ring) {
        free_ring_pbuf(sock->recv_ring);
        rte_ring_free(sock->recv_ring);
    }
    sock->recv_ring = NULL;

    if (sock->recv_wait_free) {
        free_ring_pbuf(sock->recv_wait_free);
        rte_ring_free(sock->recv_wait_free);
    }
    sock->recv_wait_free = NULL;

    if (sock->send_ring) {
        free_ring_pbuf(sock->send_ring);
        rte_ring_free(sock->send_ring);
    }
    sock->send_ring = NULL;

    if (sock->send_idle_ring) {
        free_ring_pbuf(sock->send_idle_ring);
        rte_ring_free(sock->send_idle_ring);
    }
    sock->send_idle_ring = NULL;

    sock->stack = NULL;
    sock->wakeup = NULL;
    sock->events = 0;
    sock->nextfd = -1;
    sock->attach_fd = -1;
    sock->wait_close = false;
    sock->shadowed_sock = NULL;
    sock->epoll_events = 0;
    sock->events = 0;

    if (sock->recv_lastdata) {
        pbuf_free(sock->recv_lastdata);
    }
    sock->recv_lastdata = NULL;

    if (sock->send_lastdata) {
        pbuf_free(sock->send_lastdata);
    }
    sock->send_lastdata = NULL;
}

static void replenish_send_idlembuf(struct rte_ring *ring)
{
    uint32_t replenish_cnt = rte_ring_free_count(ring);

    for (uint32_t i = 0; i < replenish_cnt; i++) {
        struct pbuf *pbuf = lwip_alloc_pbuf(PBUF_TRANSPORT, TCP_MSS, PBUF_RAM);
        if (pbuf == NULL) {
            break;
        }

        int32_t ret = rte_ring_sp_enqueue(ring, (void *)pbuf);
        if (ret < 0) {
            pbuf_free(pbuf);
            break;
        }
    }
}

void gazelle_init_sock(int32_t fd)
{
    static uint32_t name_tick = 0;
    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        return;
    }

    reset_sock_data(sock);

    sock->recv_ring = create_ring("sock_recv", SOCK_RECV_RING_SIZE, 0, atomic_fetch_add(&name_tick, 1));
    if (sock->recv_ring == NULL) {
        LSTACK_LOG(ERR, LSTACK, "sock_recv create failed. errno: %d.\n", rte_errno);
        return;
    }

    sock->recv_wait_free = create_ring("wait_free", SOCK_RECV_RING_SIZE, 0, atomic_fecth_add(&name_tick, 1));
    if (sock->recv_wait_free == NULL) {
        LSTACK_LOG(ERR, LSTACK, "wait_free create failed. errno: %d.\n", rte_errno);
        return;
    }

    sock->send_ring = create_ring("sock_send", SOCK_SEND_RING_SIZE, 0, atomic_fecth_add(&name_tick, 1));
    if (sock->send_ring == NULL) {
        LSTACK_LOG(ERR, LSTACK, "sock_send create failed. errno: %d.\n", rte_errno);
        return;
    }

    sock->send_idle_ring = create_ring("idle_send", SOCK_SEND_RING_SIZE, 0, atomic_fetch_add(&name_tick, 1));
    if (sock->send_idle_ring == NULL) {
        LSTACK_LOG(ERR, LSTACK, "idle_send create failed. errno: %d.\n", rte_errno);
        return;
    }
    replenish_send_idlembuf(sock->send_idle_ring);

    sock->stack = get_protocol_stack();
    sock->stack->conn_num++;
    init_list_node(&sock->recv_list);
    init_list_node(&sock->attach_list);
    init_list_node(&sock->listen_list);
    init_list_node(&sock->event_list);
    init_list_node(&sock->send_list);
}

void gazelle_clean_sock(int32_t fd)
{
    struct lwip_sock *sock = get_socket_by_fd(fd);
    if (sock == NULL || sock->stack == NULL) {
        return;
    }

    sock->stack->conn_num--;

    reset_sock_data(sock);

    list_del_node_init(&sock->recv_list);
    list_del_node_init(&sock->attach_list);
    list_del_node_init(&sock->listen_list);
#ifdef GAZELLE_USE_EPOLL_EVENT_STACK
    list_del_node_init(&sock->event_list);
#endif
    list_del_node_init(&sock->send_list);
}

void gazelle_free_pbuf(struct pbuf *pbuf)
{
    if (pbuf == NULL) {
        return;
    }

    struct rte_mbuf *mbuf = pbuf_to_mbuf(pbuf);
    if (mbuf->pool != NULL) {
        rte_pktmbuf_free(mbuf);
    } else {
        rte_free(mbuf);
    }
}

static int32_t alloc_mbufs(struct rte_mempool *pool, struct rte_mbuf **mbufs, uint32_t num)
{
    // alloc mbuf from pool
    if (rte_pktmbuf_alloc_bulk(pool, mbufs, num) == 0) {
        return 0;
    }

    // alloc mbuf from system
    for (uint32_t i = 0; i < num; i++) {
        struct rte_mbuf *mbuf = (struct rte_mbuf *)rte_malloc(NULL, pool->elt_size, sizeof(uint64_t));
        if (mbuf == NULL) {
            for (uint32_t j = 0; j < i; j++) {
                rte_free(mbufs[j]);
                mbufs[j] = NULL;
            }
            return -1;
        }

        mbufs[i] = mbuf;
        rte_pktmbuf_init(pool, NULL, mbuf, 0);
        rte_pktmbuf_reset(mbuf);
        mbuf->pool = NULL;
    }

    return 0;
}

int32_t gazelle_alloc_pktmbuf(struct rte_mempool *pool, struct rte_mbuf **mbufs, uint32_t num)
{
    struct pbuf_custom *pbuf_custom = NULL;

    int32_t ret = alloc_mbufs(pool, mbufs, num);
    if (ret != 0) {
        return ret;
    }

    for (uint32_t i = 0; i < num; i++) {
        pbuf_custom = mbuf_to_pbuf(mbufs[i]);
        pbuf_custom->custom_free_function = gazelle_free_pbuf;
    }

    return 0;
}

struct pbuf *lwip_alloc_pbuf(pbuf_layer layer, uint16_t length, pbuf_type type)
{
    struct rte_mbuf *mbuf;
    int32_t ret = alloc_mbufs(get_protocol_stack()->tx_pktmbuf_pool, &mbuf, 1);
    if (ret != 0) {
        get_protocol_stack()->stats.tx_allocmbuf_fail++;
        return NULL;
    }

    struct pbuf_custom *pbuf_custom = mbuf_to_pbuf(mbuf);
    pbuf_custom->custom_free_function = gazelle_free_pbuf;

    void *data = rte_pktmbuf_mtod(mbuf, void *);
    struct pbuf *pbuf = pbuf_alloced_custom(layer, length, type, pbuf_custom, data, MAX_PACKET_SZ);

#if CHECKSUM_CHECK_IP_HW || CHECKSUM_CHECK_TCP_HW
    if (pbuf) {
        pbuf->ol_flags = 0;
        pbuf->l2_len = 0;
        pbuf->l3_len = 0;
    }
#endif

    return pbuf;
}

struct pbuf *write_lwip_data(struct lwip_sock *sock, uint16_t remain_size, uint8_t *apiflags)
{
    struct pbuf *pbuf = NULL;

    if (sock->send_lastdata) {
        pbuf = sock->send_lastdata;
        sock->send_lastdata = NULL;
    } else {
        int32_t ret = rte_ring_sc_dequeue(sock->send_ring, (void **)&pbuf);
        if (ret != 0) {
            *apiflags &= ~TCP_WRITE_FLAG_MORE;
            return NULL;
        }
    }

    if (pbuf->tot_len >= remain_size) {
        sock->send_lastdata = pbuf;
        *apiflags |= TCP_WRITE_FLAG_MORE; /* set TCP_PSH flag */
        return NULL;
    }

    replenish_send_idlembuf(sock->send_idle_ring);

    if ((sock->epoll_events & EPOLLOUT) && rte_ring_free_count(sock->send_ring)) {
        add_epoll_event(sock->conn, EPOLLOUT);
    }

    sock->stack->stats.write_lwip_cnt++;
    return pbuf;
}

ssize_t write_stack_data(struct lwip_sock *sock, const void *buf, size_t len)
{
    if (sock->events & EPOLLERR) {
        return 0;
    }

    uint32_t free_count = rte_ring_free_count(sock->send_ring);
    if (free_count == 0) {
        return -1;
    }

    uint32_t avaible_cont = rte_ring_count(sock->send_idle_ring);
    avaible_cont = LWIP_MIN(free_count, avaible_cont);

    struct pbuf *pbuf = NULL;
    ssize_t send_len = 0;
    size_t copy_len;
    uint32_t send_pkt = 0;

    while (send_len < len && send_pkt < avaible_cont) {
        int32_t ret = rte_ring_sc_dequeue(sock->send_idle_ring, (void **)&pbuf);
        if (ret < 0) {
            sock->stack->stats.app_write_idlefail++;
            break;
        }

        copy_len = (len - send_len > pbuf->len) ? pbuf->len : (len - send_len);
        pbuf_take(pbuf, (char *)buf + send_len, copy_len);
        pbuf->tot_len = pbuf->len = copy_len;

        ret = rte_ring_sp_enqueue(sock->send_ring, pbuf);
        if (ret != 0) {
            sock->stack->stats.app_write_drop++;
            pbuf_free(pbuf);
            break;
        }

        send_len += copy_len;
        send_pkt++;
    }
    __sync_fetch_and_add(&sock->stack->stats.app_write_cnt, send_pkt);

    return (send_len <= 0) ? -1 : send_len;
}

void stack_send(struct rpc_msg *msg)
{
    int32_t fd = msg->args[MSG_ARG_0].i;
    int32_t flags = msg->args[MSG_ARG_2].i;

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        msg->result = -1;
        return;
    }

    if (!NETCONN_IS_DATAOUT(sock)) {
        return;
    }

    /* send all send_ring, so len set lwip send max. */
    ssize_t len = lwip_send(fd, sock, UINT16_MAX, flags);
    if (len == 0) {
        /* FIXME: should use POLLRDHUP, when connection be closed. lwip event-callback no POLLRDHUP */
        add_epoll_event(sock->conn, EPOLLERR);
    }

    /* have remain data add sendlist */
    if (NETCONN_IS_DATAOUT(sock)) {
        if (list_is_empty(&sock->send_list)) {
            sock->send_flags = flags;
            list_add_node(&sock->stack->send_list, &sock->send_list);
        }
        sock->stack->stats.send_self_rpc++;
    }
}

void send_stack_list(struct protocol_stack *stack, uint32_t send_max)
{
    struct list_node *node, *temp;
    struct lwip_sock *sock;
    uint32_t read_num = 0;

    list_for_each_safe(node, temp, &stack->send_list) {
        sock = container_of(node, struct lwip_sock, send_list);

        if (sock->conn == NULL || !NETCONN_IS_DATAOUT(sock)) {
            list_del_node_init(&sock->send_list);
            continue;
        }

        /* send all send_ring, so len set lwip send max. */
        ssize_t len = lwip_send(sock->conn->socket, sock, UINT16_MAX, sock->send_flags);
        if (len == 0) {
            /* FIXME: should use POLLRDHUP, when connection be closed. lwip event-callback no POLLRDHUP */
            add_epoll_event(sock->conn, EPOLLERR);
            list_del_node_init(&sock->send_list);
        }

        if (!NETCONN_IS_DATAOUT(sock)) {
            list_del_node_init(&sock->send_list);
        }

        if (++read_num >= send_max) {
            break;
        }
    }
}

ssize_t read_lwip_data(struct lwip_sock *sock, int32_t flags, u8_t apiflags)
{
    if (sock->conn->recvmbox == NULL) {
        return 0;
    }

    if (rte_ring_count(sock->recv_wait_free)) {
        free_ring_pbuf(sock->recv_wait_free);
    }

    uint32_t free_count = rte_ring_free_count(sock->recv_ring);
    uint32_t data_count = rte_ring_count(sock->conn->recvmbox->ring);
    uint32_t read_max = LWIP_MIN(free_count, data_count);
    struct pbuf *pbuf = NULL;
    uint32_t read_count = 0;
    ssize_t recv_len = 0;
    int32_t ret;

    for (uint32_t i = 0; i < read_max; i++) {
        err_t err = netconn_recv_tcp_pbuf_flags(sock->conn, &pbuf, apiflags);
        if (err != ERR_OK) {
            if (recv_len > 0) {
                /* already received data, return that (this trusts in getting the same error from
                   netconn layer again next time netconn_recv is called) */
                break;
            }

            return (err == ERR_CLSD) ? 0 : -1;
        }

        if (!(flags & MSG_PEEK)) {
            ret = rte_ring_sp_enqueue(sock->recv_ring, pbuf);
            if (ret != 0) {
                pbuf_free(pbuf);
                sock->stack->stats.read_lwip_drop++;
                break;
            }
            read_count++;
        }

        if (get_protocol_stack_group()->latency_start) {
            calculate_lstack_latency(&sock->stack->latency, pbuf, GAZELLE_LATENCY_LWIP);
        }

        recv_len += pbuf->len;

        /* once we have some data to return, only add more if we don't need to wait */
        apiflags |= NETCONN_DONTBLOCK | NETCONN_NOFIN;
    }

    if (data_count > read_count) {
        add_recv_list(sock->conn->socket);
    }

    if (recv_len > 0 && (flags & MSG_PEEK) == 0) {
        add_epoll_event(sock->conn, EPOLLIN);
    }
    sock->stack->stats.read_lwip_cnt += read_count;

    if (recv_len == 0) {
        GAZELLE_RETURN(EAGAIN);
    }
    return recv_len;
}

ssize_t recvmsg_from_stack(int32_t s, struct msghdr *message, int32_t flags)
{
    ssize_t buflen = 0;
    int32_t i;

    if (message == NULL || message->msg_iovlen <= 0 || message->msg_iovlen > IOV_MAX) {
        GAZELLE_RETURN(EINVAL);
    }
    for (i = 0; i < message->msg_iovlen; i++) {
        if ((message->msg_iov[i].iov_base == NULL) || ((ssize_t)message->msg_iov[i].iov_len <= 0) ||
            ((size_t)(ssize_t)message->msg_iov[i].iov_len != message->msg_iov[i].iov_len) ||
            ((ssize_t)(buflen + (ssize_t)message->msg_iov[i].iov_len) <= 0)) {
            GAZELLE_RETURN(EINVAL);
        }
        buflen = (ssize_t)(buflen + (ssize_t)message->msg_iov[i].iov_len);
    }
    buflen = 0;
    for (i = 0; i < message->msg_iovlen; i++) {
        ssize_t recvd_local = read_stack_data(s, message->msg_iov[i].iov_base, message->msg_iov[i].iov_len, flags);
        if (recvd_local > 0) {
            buflen += recvd_local;
        }
        if (recvd_local < 0 || (recvd_local < (int)message->msg_iov[i].iov_len) || (flags & MSG_PEEK)) {
            if (buflen <= 0) {
                buflen = recvd_local;
            }
            break;
        }
        flags |= MSG_DONTWAIT;
    }

    return buflen;
}

ssize_t gazelle_send(int32_t fd, const void *buf, size_t len, int32_t flags)
{
    if (buf == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    if (len == 0) {
        return 0;
    }

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    sock->send_flags = flags;
    ssize_t send = write_stack_data(sock, buf, len);
    if (send < 0) {
        GAZELLE_RETURN(EAGAIN);
    } else if (send == 0) {
        return 0;
    }
    rte_smp_mb();

    rpc_call_send(fd, NULL, send, flags);
    return send;
}

ssize_t sendmsg_to_stack(int32_t s, const struct msghdr *message, int32_t flags)
{
    int32_t ret;
    int32_t i;
    ssize_t buflen = 0;

    if (message == NULL || message->msg_iovlen <= 0 || message->msg_iovlen > IOV_MAX) {
        GAZELLE_RETURN(EINVAL);
    }
    for (i = 0; i < message->msg_iovlen; i++) {
        if ((message->msg_iov[i].iov_base == NULL) || ((ssize_t)message->msg_iov[i].iov_len <= 0) ||
            ((size_t)(ssize_t)message->msg_iov[i].iov_len != message->msg_iov[i].iov_len) ||
            ((ssize_t)(buflen + (ssize_t)message->msg_iov[i].iov_len) <= 0)) {
            GAZELLE_RETURN(EINVAL);
        }
        buflen = (ssize_t)(buflen + (ssize_t)message->msg_iov[i].iov_len);
    }

    for (i = 0; i < message->msg_iovlen; i++) {
        ret = gazelle_send(s, message->msg_iov[i].iov_base, message->msg_iov[i].iov_len, flags);
        if (ret < 0) {
            return buflen == 0 ? ret : buflen;
        }
        buflen += ret;
    }

    return buflen;
}

ssize_t read_stack_data(int32_t fd, void *buf, size_t len, int32_t flags)
{
    size_t recv_left = len;
    struct pbuf *pbuf = NULL;
    ssize_t recvd = 0;
    int32_t ret;
    u16_t copy_len;

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "get_socket null fd %d.\n", fd);
        GAZELLE_RETURN(EINVAL);
    }
    sock->recv_flags = flags;

    if ((sock->events & EPOLLERR) && !NETCONN_IS_DATAIN(sock)) {
        return 0;
    }

    while (recv_left > 0) {
        if (sock->recv_lastdata) {
            pbuf = sock->recv_lastdata;
            sock->recv_lastdata = NULL;
        } else {
            ret = rte_ring_sc_dequeue(sock->recv_ring, (void **)&pbuf);
            if (ret != 0) {
                break;
            }
        }

        copy_len = (recv_left > pbuf->tot_len) ? pbuf->tot_len : (u16_t)recv_left;
        pbuf_copy_partial(pbuf, (char *)buf + recvd, copy_len, 0);

        recvd += copy_len;
        recv_left -= copy_len;

        if (pbuf->tot_len > copy_len) {
            sock->recv_lastdata = pbuf_free_header(pbuf, copy_len);
        } else {
            if (get_protocol_stack_group()->latency_start) {
                calculate_lstack_latency(&sock->stack->latency, pbuf, GAZELLE_LATENCY_READ);
            }
            ret = rte_ring_sp_enqueue(sock->recv_wait_free, pbuf);
            if (ret != 0) {
                pbuf_free(pbuf);
            }
            sock->recv_lastdata = NULL;
            __sync_fetch_and_add(&sock->stack->stats.app_read_cnt, 1);
        }
    }

    if (recvd == 0) {
        sock->stack->stats.read_null++;
        GAZELLE_RETURN(EAGAIN);
    }
    return recvd;
}

void add_recv_list(int32_t fd)
{
    struct lwip_sock *sock = get_socket(fd);

    if (sock->stack && list_is_empty(&sock->recv_list)) {
        list_add_node(&sock->stack->recv_list, &sock->recv_list);
    }
}

void read_recv_list(struct protocol_stack *stack, uint32_t max_num)
{
    struct list_node *list = &(stack->recv_list);
    struct list_node *node, *temp;
    struct lwip_sock *sock;
    uint32_t read_num = 0;

    list_for_each_safe(node, temp, list) {
        sock = container_of(node, struct lwip_sock, recv_list);

        if (sock->conn == NULL || sock->recv_ring == NULL || sock->send_ring == NULL || sock->conn->pcb.tcp == NULL) {
            list_del_node_init(&sock->recv_list);
            continue;
        }

        if (rte_ring_free_count(sock->recv_ring)) {
            list_del_node_init(&sock->recv_list);
            ssize_t len = lwip_recv(sock->conn->socket, NULL, 0, sock->recv_flags);
            if (len == 0) {
                /* FIXME: should use POLLRDHUP, when connection be closed. lwip event-callback no POLLRDHUP */
                add_epoll_event(sock->conn, EPOLLERR);
            }
        }

        if (++read_num >= max_num) {
            break;
        }
    }
}

static void copy_pcb_to_conn(struct gazelle_stat_lstack_conn_info *conn, const struct tcp_pcb *pcb)
{
    struct netconn *netconn = (struct netconn *)pcb->callback_arg;

    conn->lip = pcb->local_ip.addr;
    conn->rip = pcb->remote_ip.addr;
    conn->l_port = pcb->local_port;
    conn->r_port = pcb->remote_port;
    conn->in_send = pcb->snd_queuelen;
    conn->tcp_sub_state = pcb->state;

    if (netconn != NULL && netconn->recvmbox != NULL) {
        conn->recv_cnt = rte_ring_count(netconn->recvmbox->ring);

        struct lwip_sock *sock = get_socket(netconn->socket);
        if (netconn->socket > 0 && sock != NULL && sock->recv_ring != NULL && sock->send_ring != NULL) {
            conn->recv_ring_cnt = rte_ring_count(sock->recv_ring);
            conn->recv_ring_cnt += (sock->recv_lastdata) ? 1 : 0;

            conn->send_ring_cnt = rte_ring_count(sock->send_ring);
            conn->send_ring_cnt += (sock->send_lastdata) ? 1 : 0;

            if (sock->wakeup) {
                sem_getvalue(&sock->wakeup->event_sem, &conn->sem_cnt);
            }
        }
    }
}

static inline void clone_lwip_socket_opt(struct lwip_sock *dst_sock, struct lwip_sock *src_sock)
{
    dst_sock->conn->pcb.ip->so_options = src_sock->conn->pcb.ip->so_options;
    dst_sock->conn->pcb.ip->ttl = src_sock->conn->pcb.ip->ttl;
    dst_sock->conn->pcb.ip->tos = src_sock->conn->pcb.ip->tos;
    dst_sock->conn->pcb.tcp->netif_idx = src_sock->conn->pcb.tcp->netif_idx;
    dst_sock->conn->pcb.tcp->flags = src_sock->conn->pcb.tcp->flags;
    dst_sock->conn->pcb.tcp->keep_idle = src_sock->conn->pcb.tcp->keep_idle;
    dst_sock->conn->pcb.tcp->keep_idle = src_sock->conn->pcb.tcp->keep_idle;
    dst_sock->conn->pcb.tcp->keep_intvl = src_sock->conn->pcb.tcp->keep_intvl;
    dst_sock->conn->pcb.tcp->keep_cnt = src_sock->conn->pcb.tcp->keep_cnt;
    dst_sock->conn->flags = src_sock->conn->flags;
}

int32_t gazelle_socket(int domain, int type, int protocol)
{
    int32_t fd = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return fd;
    }

    gazelle_init_sock(fd);

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL || sock->stack == NULL) {
        lwip_close(fd);
        gazelle_clean_sock(fd);
        posix_api->close_fn(fd);
        return -1;
    }

    return fd;
}

void create_shadow_fd(struct rpc_msg *msg)
{
    int32_t fd = msg->args[MSG_ARG_0].i;
    struct sockaddr *addr = msg->args[MSG_ARG_1].p;
    socklen_t addr_len = msg->args[MSG_ARG_2].socklen;

    int32_t clone_fd = gazelle_socket(AF_INET, SOCK_STREAM, 0);
    if (clone_fd < 0) {
        LSTACK_LOG(ERR, LSTACK, "clone socket failed clone_fd=%d errno=%d\n", clone_fd, errno);
        msg->result = clone_fd;
        return;
    }

    struct lwip_sock *sock = get_socket_by_fd(fd);
    struct lwip_sock *clone_sock = get_socket_by_fd(clone_fd);
    if (sock == NULL || clone_sock == NULL) {
        LSTACK_LOG(ERR, LSTACK, "get sock null fd=%d clone_fd=%d\n", fd, clone_fd);
        msg->result = -1;
        return;
    }

    clone_lwip_socket_opt(clone_sock, sock);
    clone_sock->shadowed_sock = sock;

    listen_list_add_node(fd, clone_fd);

    int32_t ret = lwip_bind(clone_fd, addr, addr_len);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "clone bind failed clone_fd=%d errno=%d\n", ret, errno);
        msg->result = ret;
        return;
    }

    msg->result = clone_fd;
}

void get_lwip_conntable(struct rpc_msg *msg)
{
    struct tcp_pcb *pcb = NULL;
    uint32_t conn_num = 0;
    struct gazelle_stat_lstack_conn_info *conn = (struct gazelle_stat_lstack_conn_info *)msg->args[MSG_ARG_0].p;
    uint32_t max_num = msg->args[MSG_ARG_1].u;

    if (conn == NULL) {
        msg->result = -1;
        return;
    }

    for (pcb = tcp_active_pcbs; pcb != NULL && conn_num < max_num; pcb = pcb->next) {
        conn[conn_num].state = ACTIVE_LIST;
        copy_pcb_to_conn(conn + conn_num, pcb);
        conn_num++;
    }

    for (pcb = tcp_tw_pcbs; pcb != NULL && conn_num < max_num; pcb = pcb->next) {
        conn[conn_num].state = TIME_WAIT_LIST;
        copy_pcb_to_conn(conn + conn_num, pcb);
        conn_num++;
    }

    for (struct tcp_pcb_listen *pcbl = tcp_listen_pcbs.listen_pcbs; pcbl != NULL && conn_num < max_num;
        pcbl = pcbl->next) {
        conn[conn_num].state = LISTEN_LIST;
        conn[conn_num].lip = pcbl->local_ip.addr;
        conn[conn_num].l_port = pcbl->local_port;
        conn[conn_num].tcp_sub_state = pcbl->state;
        struct netconn *netconn = (struct netconn *)pcbl->callback_arg;
        if (netconn != NULL && netconn->acceptmbox != NULL) {
            conn[conn_num].recv_cnt = rte_ring_count(netconn->acceptmbox->ring);
        }
        conn_num++;
    }

    msg->result = conn_num;
}

void get_lwip_connnum(struct rpc_msg *msg)
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

    msg->result = conn_num;
}

static uint32_t get_list_count(struct list_node *list)
{
    struct list_node *node, *temp;
    uint32_t count = 0;

    list_for_each_safe(node, temp, list) {
        count++;
    }

    return count;
}

void stack_eventlist_count(struct rpc_msg *msg)
{
    msg->result = get_list_count(&get_protocol_stack()->event_list);
}

void stack_sendlist_count(struct rpc_msg *msg)
{
    msg->result = get_list_count(&get_protocol_stack()->send_list);
}

void stack_recvlist_count(struct rpc_msg *msg)
{
    msg->result = get_list_count(&get_protocol_stack()->recv_list);
}
