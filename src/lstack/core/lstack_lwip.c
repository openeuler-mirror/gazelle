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
#include "posix/lstack_epoll.h"
#include "lstack_thread_rpc.h"
#include "dpdk_common.h"
#include "lstack_lwip.h"

#define HALF_DIVISOR                    (2)
#define USED_IDLE_WATERMARK             (VDEV_IDLE_QUEUE_SZ >> 2)

static void free_ring_pbuf(struct rte_ring *ring)
{
    void *pbufs[SOCK_RECV_RING_SIZE];

    do {
        gazelle_ring_read(ring, pbufs, RING_SIZE(SOCK_RECV_RING_SIZE));
        gazelle_ring_read_over(ring);
    } while (gazelle_ring_readable_count(ring));

    do {
        uint32_t num = gazelle_ring_sc_dequeue(ring, pbufs, RING_SIZE(SOCK_RECV_RING_SIZE));

        for (uint32_t i = 0; i < num; i++) {
            pbuf_free(pbufs[i]);
        }
    } while (gazelle_ring_readover_count(ring));
}

static void reset_sock_data(struct lwip_sock *sock)
{
    /* check null pointer in ring_free func */
    if (sock->recv_ring) {
        free_ring_pbuf(sock->recv_ring);
        rte_ring_free(sock->recv_ring);
    }
    sock->recv_ring = NULL;

    if (sock->send_ring) {
        free_ring_pbuf(sock->send_ring);
        rte_ring_free(sock->send_ring);
    }
    sock->send_ring = NULL;

    sock->stack = NULL;
    sock->wakeup = NULL;
    sock->listen_next = NULL;
    sock->epoll_events = 0;
    sock->events = 0;
    sock->in_send = 0;

    if (sock->recv_lastdata) {
        pbuf_free(sock->recv_lastdata);
    }
    sock->recv_lastdata = NULL;
}

static struct pbuf *init_mbuf_to_pbuf(struct rte_mbuf *mbuf, pbuf_layer layer, uint16_t length, pbuf_type type)
{
    struct pbuf_custom *pbuf_custom = mbuf_to_pbuf(mbuf);
    pbuf_custom->custom_free_function = gazelle_free_pbuf;

    void *data = rte_pktmbuf_mtod(mbuf, void *);
    struct pbuf *pbuf = pbuf_alloced_custom(layer, length, type, pbuf_custom, data, MAX_PACKET_SZ);
    if (pbuf) {
        pbuf->ol_flags = 0;
        pbuf->l2_len = 0;
        pbuf->l3_len = 0;
    }

    return pbuf;
}

static void replenish_send_idlembuf(struct protocol_stack *stack, struct rte_ring *ring)
{
    void *pbuf[SOCK_SEND_RING_SIZE];

    uint32_t replenish_cnt = gazelle_ring_free_count(ring);

    uint32_t alloc_num = LWIP_MIN(replenish_cnt, RING_SIZE(SOCK_SEND_RING_SIZE));
    if (rte_pktmbuf_alloc_bulk(stack->tx_pktmbuf_pool, (struct rte_mbuf **)pbuf, alloc_num) != 0) {
        stack->stats.tx_allocmbuf_fail++;
        return;
    }

    for (uint32_t i = 0; i < alloc_num; i++) {
        pbuf[i] = init_mbuf_to_pbuf(pbuf[i], PBUF_TRANSPORT, TCP_MSS, PBUF_RAM);
    }

    uint32_t num = gazelle_ring_sp_enqueue(ring, pbuf, alloc_num);
    for (uint32_t i = num; i < alloc_num; i++) {
        pbuf_free(pbuf[i]);
    }
}

void gazelle_init_sock(int32_t fd)
{
    static _Atomic uint32_t name_tick = 0;
    struct protocol_stack *stack = get_protocol_stack();
    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        return;
    }

    reset_sock_data(sock);

    sock->recv_ring = create_ring("sock_recv", SOCK_RECV_RING_SIZE, RING_F_SP_ENQ | RING_F_SC_DEQ,
        atomic_fetch_add(&name_tick, 1));
    if (sock->recv_ring == NULL) {
        LSTACK_LOG(ERR, LSTACK, "sock_recv create failed. errno: %d.\n", rte_errno);
        return;
    }

    sock->send_ring = create_ring("sock_send", SOCK_SEND_RING_SIZE, RING_F_SP_ENQ | RING_F_SC_DEQ,
        atomic_fetch_add(&name_tick, 1));
    if (sock->send_ring == NULL) {
        LSTACK_LOG(ERR, LSTACK, "sock_send create failed. errno: %d.\n", rte_errno);
        return;
    }
    replenish_send_idlembuf(stack, sock->send_ring);

    sock->stack = stack;
    sock->stack->conn_num++;
    init_list_node_null(&sock->recv_list);
    init_list_node_null(&sock->event_list);
    init_list_node_null(&sock->send_list);
}

void gazelle_clean_sock(int32_t fd)
{
    struct lwip_sock *sock = get_socket_by_fd(fd);
    if (sock == NULL || sock->stack == NULL) {
        return;
    }

    if (sock->wakeup && sock->wakeup->type == WAKEUP_EPOLL) {
        pthread_spin_lock(&sock->wakeup->event_list_lock);
        list_del_node_null(&sock->event_list);
        pthread_spin_unlock(&sock->wakeup->event_list_lock);
    }

    sock->stack->conn_num--;

    reset_sock_data(sock);

    list_del_node_null(&sock->recv_list);
    list_del_node_null(&sock->send_list);
}

void gazelle_free_pbuf(struct pbuf *pbuf)
{
    if (pbuf == NULL) {
        return;
    }

    struct rte_mbuf *mbuf = pbuf_to_mbuf(pbuf);
    rte_pktmbuf_free(mbuf);
}

int32_t gazelle_alloc_pktmbuf(struct rte_mempool *pool, struct rte_mbuf **mbufs, uint32_t num)
{
    struct pbuf_custom *pbuf_custom = NULL;

    int32_t ret = rte_pktmbuf_alloc_bulk(pool, mbufs, num);
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
    struct protocol_stack *stack = get_protocol_stack();

    if (rte_pktmbuf_alloc_bulk(stack->tx_pktmbuf_pool, &mbuf, 1) != 0) {
        stack->stats.tx_allocmbuf_fail++;
        return NULL;
    }

    return init_mbuf_to_pbuf(mbuf, layer, length, type);
}

struct pbuf *write_lwip_data(struct lwip_sock *sock, uint16_t remain_size, uint8_t *apiflags)
{
    struct pbuf *pbuf = NULL;

    if (gazelle_ring_sc_peek(sock->send_ring, (void **)&pbuf, 1) != 1) {
        *apiflags &= ~TCP_WRITE_FLAG_MORE;
        return NULL;
    }

    return pbuf;
}

void write_lwip_over(struct lwip_sock *sock, uint32_t n)
{
    gazelle_ring_dequeue_over(sock->send_ring, n);
    sock->stack->stats.write_lwip_cnt += n;
}

static inline void del_data_out_event(struct lwip_sock *sock)
{
    pthread_spin_lock(&sock->wakeup->event_list_lock);

    /* check again avoid cover event add in stack thread */
    if (!NETCONN_IS_OUTIDLE(sock)) {
        sock->events &= ~EPOLLOUT;

        if (sock->events == 0) {
            list_del_node_null(&sock->event_list);
        }
    }

    pthread_spin_unlock(&sock->wakeup->event_list_lock);
}

void write_stack_over(struct lwip_sock *sock)
{
    if (sock->send_lastdata) {
        sock->send_lastdata->tot_len = sock->send_lastdata->len = sock->send_datalen;
        sock->send_lastdata = NULL;
    }

    gazelle_ring_read_over(sock->send_ring);

    if (sock->wakeup) {
        sock->wakeup->stat.app_write_cnt++;
        if (sock->wakeup->type == WAKEUP_EPOLL && (sock->events & EPOLLOUT)) {
            del_data_out_event(sock);
        }
    }
}

ssize_t write_stack_data(struct lwip_sock *sock, const void *buf, size_t len)
{
    if (sock->errevent > 0) {
        GAZELLE_RETURN(ENOTCONN);
    }

    struct pbuf *pbuf = NULL;
    ssize_t send_len = 0;
    uint32_t send_pkt = 0;

    while (send_len < len) {
        if (sock->send_lastdata) {
            pbuf = sock->send_lastdata;
        } else {
            if (gazelle_ring_read(sock->send_ring, (void **)&pbuf, 1) != 1) {
                if (sock->wakeup) {
                    sock->wakeup->stat.app_write_idlefail++;
                }
                break;
            }
            sock->send_lastdata = pbuf;
            sock->send_datalen = 0;
        }

        uint16_t remian_len = pbuf->len - sock->send_datalen;
        uint16_t copy_len = (len - send_len > remian_len) ? remian_len : (len - send_len);
        pbuf_take_at(pbuf, (char *)buf + send_len, copy_len, sock->send_datalen);
        sock->send_datalen += copy_len;
        if (sock->send_datalen >= pbuf->len) {
            sock->send_lastdata = NULL;
            pbuf->tot_len = pbuf->len = sock->send_datalen;
            send_pkt++;
        }

        send_len += copy_len;
    }

    if (sock->wakeup) {
        sock->wakeup->stat.app_write_cnt += send_pkt;
    }

    return send_len;
}

static void do_lwip_send(struct protocol_stack *stack, int32_t fd, struct lwip_sock *sock, int32_t flags)
{
    /* send all send_ring, so len set lwip send max. */
    ssize_t len = lwip_send(fd, sock, UINT16_MAX, flags);
    if (len == 0) {
        /* FIXME: should use POLLRDHUP, when connection be closed. lwip event-callback no POLLRDHUP */
        sock->errevent = 1;
        add_sock_event(sock, EPOLLERR);
    }

    if (gazelle_ring_readable_count(sock->send_ring) < SOCK_SEND_REPLENISH_THRES) {
        replenish_send_idlembuf(stack, sock->send_ring);
    }

    if ((sock->epoll_events & EPOLLOUT) && NETCONN_IS_OUTIDLE(sock)) {
        add_sock_event(sock, EPOLLOUT);
    }
}

void stack_send(struct rpc_msg *msg)
{
    int32_t fd = msg->args[MSG_ARG_0].i;
    int32_t flags = msg->args[MSG_ARG_2].i;
    struct protocol_stack *stack = (struct protocol_stack *)msg->args[MSG_ARG_3].p;

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        msg->result = -1;
        return;
    }

    __atomic_store_n(&sock->in_send, 0, __ATOMIC_RELEASE);
    rte_mb();

    if (!NETCONN_IS_DATAOUT(sock) || sock->errevent > 0) {
        return;
    }

    do_lwip_send(stack, fd, sock, flags);

    /* have remain data add sendlist */
    if (NETCONN_IS_DATAOUT(sock)) {
        if (list_is_null(&sock->send_list)) {
            list_add_node(&stack->send_list, &sock->send_list);
            __atomic_store_n(&sock->in_send, 1, __ATOMIC_RELEASE);
        }
        stack->stats.send_self_rpc++;
    }
}

void send_stack_list(struct protocol_stack *stack, uint32_t send_max)
{
    struct list_node *node, *temp;
    struct lwip_sock *sock;
    uint32_t read_num = 0;

    list_for_each_safe(node, temp, &stack->send_list) {
        sock = container_of(node, struct lwip_sock, send_list);

        __atomic_store_n(&sock->in_send, 0, __ATOMIC_RELEASE);
        rte_mb();

        if (sock->conn == NULL || sock->errevent > 0 || !NETCONN_IS_DATAOUT(sock)) {
            list_del_node_null(&sock->send_list);
            continue;
        }

        do_lwip_send(stack, sock->conn->socket, sock, 0);

        if (!NETCONN_IS_DATAOUT(sock)) {
            list_del_node_null(&sock->send_list);
        } else {
            __atomic_store_n(&sock->in_send, 1, __ATOMIC_RELEASE);
        }

        if (++read_num >= send_max) {
            break;
        }
    }
}

static inline void free_recv_ring_readover(struct rte_ring *ring)
{
    void *pbufs[SOCK_RECV_RING_SIZE];
    uint32_t num = gazelle_ring_sc_dequeue(ring, pbufs, RING_SIZE(SOCK_RECV_RING_SIZE));
    for (uint32_t i = 0; i < num; i++) {
        pbuf_free(pbufs[i]);
    }
}

ssize_t read_lwip_data(struct lwip_sock *sock, int32_t flags, u8_t apiflags)
{
    if (sock->conn->recvmbox == NULL) {
        return 0;
    }

    if (gazelle_ring_readover_count(sock->recv_ring) >= SOCK_RECV_FREE_THRES) {
        free_recv_ring_readover(sock->recv_ring);
    }

    uint32_t free_count = gazelle_ring_free_count(sock->recv_ring);
    if (free_count == 0) {
        GAZELLE_RETURN(EAGAIN);
    }

    uint32_t data_count = rte_ring_count(sock->conn->recvmbox->ring);
    uint32_t read_num = LWIP_MIN(free_count, data_count);
    read_num = LWIP_MIN(read_num, SOCK_RECV_RING_SIZE);
    struct pbuf *pbufs[SOCK_RECV_RING_SIZE];
    uint32_t read_count = 0;
    ssize_t recv_len = 0;

    for (uint32_t i = 0; i < read_num; i++) {
        err_t err = netconn_recv_tcp_pbuf_flags(sock->conn, &pbufs[i], apiflags);
        if (err != ERR_OK) {
            if (recv_len > 0) {
                /* already received data, return that (this trusts in getting the same error from
                   netconn layer again next time netconn_recv is called) */
                break;
            }

            return (err == ERR_CLSD) ? 0 : -1;
        }

        recv_len += pbufs[i]->tot_len;
        read_count++;

        /* once we have some data to return, only add more if we don't need to wait */
        apiflags |= NETCONN_DONTBLOCK | NETCONN_NOFIN;
    }

    if (!(flags & MSG_PEEK)) {
        uint32_t enqueue_num = gazelle_ring_sp_enqueue(sock->recv_ring, (void **)pbufs, read_count);
        for (uint32_t i = enqueue_num; i < read_count; i++) {
            /* update receive window */
            tcp_recved(sock->conn->pcb.tcp, pbufs[i]->tot_len);
            pbuf_free(pbufs[i]);
            sock->stack->stats.read_lwip_drop++;
        }
    }

    for (uint32_t i = 0; get_protocol_stack_group()->latency_start && i < read_count; i++) {
        calculate_lstack_latency(&sock->stack->latency, pbufs[i], GAZELLE_LATENCY_LWIP);
    }

    sock->stack->stats.read_lwip_cnt += read_count;
    if (recv_len == 0) {
        GAZELLE_RETURN(EAGAIN);
    }
    return recv_len;
}

static int32_t check_msg_vaild(const struct msghdr *message)
{
    ssize_t buflen = 0;

    if (message == NULL || message->msg_iovlen <= 0 || message->msg_iovlen > IOV_MAX) {
        GAZELLE_RETURN(EINVAL);
    }

    for (int32_t i = 0; i < message->msg_iovlen; i++) {
        if ((message->msg_iov[i].iov_base == NULL) || ((ssize_t)message->msg_iov[i].iov_len < 0) ||
            ((size_t)(ssize_t)message->msg_iov[i].iov_len != message->msg_iov[i].iov_len) ||
            ((ssize_t)(buflen + (ssize_t)message->msg_iov[i].iov_len) <= 0)) {
            GAZELLE_RETURN(EINVAL);
        }
        buflen = (ssize_t)(buflen + (ssize_t)message->msg_iov[i].iov_len);
    }

    return 0;
}

ssize_t recvmsg_from_stack(int32_t s, struct msghdr *message, int32_t flags)
{
    ssize_t buflen = 0;

    if (check_msg_vaild(message)) {
        GAZELLE_RETURN(EINVAL);
    }

    for (int32_t i = 0; i < message->msg_iovlen; i++) {
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

static inline void notice_stack_send(struct lwip_sock *sock, int32_t fd, int32_t len, int32_t flags)
{
    if (__atomic_load_n(&sock->in_send, __ATOMIC_ACQUIRE) == 0) {
        __atomic_store_n(&sock->in_send, 1, __ATOMIC_RELEASE);
        if (rpc_call_send(fd, NULL, len, flags) != 0) {
            __atomic_store_n(&sock->in_send, 0, __ATOMIC_RELEASE);
        }
    }
}

ssize_t gazelle_send(int32_t fd, const void *buf, size_t len, int32_t flags)
{
    if (buf == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    if (len == 0) {
        return 0;
    }

    struct lwip_sock *sock = get_socket_by_fd(fd);
    ssize_t send = write_stack_data(sock, buf, len);
    if (send <= 0) {
        return send;
    }
    write_stack_over(sock);

    notice_stack_send(sock, fd, send, flags);
    return send;
}

ssize_t sendmsg_to_stack(int32_t s, const struct msghdr *message, int32_t flags)
{
    int32_t ret;
    int32_t i;
    ssize_t buflen = 0;
    struct lwip_sock *sock = get_socket_by_fd(s);

    if (check_msg_vaild(message)) {
        GAZELLE_RETURN(EINVAL);
    }

    for (i = 0; i < message->msg_iovlen; i++) {
        if (message->msg_iov[i].iov_len == 0) {
            continue;
        }

        ret = write_stack_data(sock, message->msg_iov[i].iov_base, message->msg_iov[i].iov_len);
        if (ret <= 0) {
            buflen = (buflen == 0) ? ret : buflen;
            break;
        }

        buflen += ret;

        if (ret < message->msg_iov[i].iov_len) {
           break;
        }
    }

    if (buflen > 0) {
        write_stack_over(sock);
        notice_stack_send(sock, s, buflen, flags);
    }
    return buflen;
}

static inline void del_data_in_event(struct lwip_sock *sock)
{
    pthread_spin_lock(&sock->wakeup->event_list_lock);

    /* check again avoid cover event add in stack thread */
    if (!NETCONN_IS_DATAIN(sock)) {
        sock->events &= ~EPOLLIN;

        if (sock->events == 0) {
            list_del_node_null(&sock->event_list);
        }
    }

    pthread_spin_unlock(&sock->wakeup->event_list_lock);
}

static struct pbuf *pbuf_free_partial(struct pbuf *pbuf, uint16_t free_len)
{
    uint16_t tot_len = pbuf->tot_len - free_len;

    while (free_len && pbuf) {
        if (free_len >= pbuf->len) {
            free_len = free_len - pbuf->len;
            pbuf = pbuf->next;
        } else {
            pbuf_remove_header(pbuf, free_len);
            break;
        }
    }

    pbuf->tot_len = tot_len;
    return pbuf;
}

ssize_t read_stack_data(int32_t fd, void *buf, size_t len, int32_t flags)
{
    size_t recv_left = len;
    struct pbuf *pbuf = NULL;
    ssize_t recvd = 0;
    uint16_t copy_len;
    struct lwip_sock *sock = get_socket_by_fd(fd);
    bool latency_enable = get_protocol_stack_group()->latency_start;

    if (sock->errevent > 0 && !NETCONN_IS_DATAIN(sock)) {
        return 0;
    }

    if (recv_left > UINT16_MAX) {
        recv_left = UINT16_MAX;
    }

    while (recv_left > 0) {
        if (sock->recv_lastdata) {
            pbuf = sock->recv_lastdata;
            sock->recv_lastdata = NULL;
        } else {
            if (gazelle_ring_read(sock->recv_ring, (void **)&pbuf, 1) != 1) {
                break;
            }
        }

        copy_len = (recv_left > pbuf->tot_len) ? pbuf->tot_len : (uint16_t)recv_left;
        pbuf_copy_partial(pbuf, (char *)buf + recvd, copy_len, 0);

        recvd += copy_len;
        recv_left -= copy_len;

        if (pbuf->tot_len > copy_len) {
            sock->recv_lastdata = pbuf_free_partial(pbuf, copy_len);
        } else {
            if (sock->wakeup) {
                sock->wakeup->stat.app_read_cnt += 1;
            }
            if (latency_enable) {
                calculate_lstack_latency(&sock->stack->latency, pbuf, GAZELLE_LATENCY_READ);
            }
            gazelle_ring_read_over(sock->recv_ring);
        }
    }

    /* rte_ring_count reduce lock */
    if (sock->wakeup && sock->wakeup->type == WAKEUP_EPOLL && (sock->events & EPOLLIN)) {
        del_data_in_event(sock);
    }

    if (recvd == 0) {
        if (sock->wakeup) {
            sock->wakeup->stat.read_null++;
        }
        GAZELLE_RETURN(EAGAIN);
    }
    return recvd;
}

void add_recv_list(int32_t fd)
{
    struct lwip_sock *sock = get_socket_by_fd(fd);

    if (sock && sock->stack && list_is_null(&sock->recv_list)) {
        list_add_node(&sock->stack->recv_list, &sock->recv_list);
    }
}

void read_recv_list(struct protocol_stack *stack, uint32_t max_num)
{
    struct list_node *list = &(stack->recv_list);
    struct list_node *node, *temp;
    struct lwip_sock *sock;
    uint32_t read_num = 0;

    struct list_node *last_node = list->prev;
    list_for_each_safe(node, temp, list) {
        sock = container_of(node, struct lwip_sock, recv_list);

        if (sock->conn == NULL || sock->conn->recvmbox == NULL || rte_ring_count(sock->conn->recvmbox->ring) == 0) {
            list_del_node_null(&sock->recv_list);
            continue;
        }

        ssize_t len = lwip_recv(sock->conn->socket, NULL, 0, 0);
        if (len == 0) {
            /* FIXME: should use POLLRDHUP, when connection be closed. lwip event-callback no POLLRDHUP */
            sock->errevent = 1;
            add_sock_event(sock, EPOLLERR);
        } else if (len > 0) {
            add_sock_event(sock, EPOLLIN);
        }

        /* last_node:recv only once per sock. max_num avoid cost too much time this loop  */
        if (++read_num >= max_num || last_node == node) {
            break;
        }
    }
}

void gazelle_connected_callback(struct netconn *conn)
{
    if (conn == NULL) {
        return;
    }

    int32_t fd = conn->socket;
    struct lwip_sock *sock = get_socket_by_fd(fd);
    if (sock == NULL || sock->conn == NULL) {
        return;
    }

    if (sock->wakeup != NULL && sock->wakeup->epollfd > 0){
	posix_api->epoll_ctl_fn(sock->wakeup->epollfd, EPOLL_CTL_DEL, fd, NULL);
    }

    posix_api->shutdown_fn(fd, SHUT_RDWR);

    SET_CONN_TYPE_LIBOS(conn);

    add_sock_event(sock, EPOLLOUT);
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
        conn->fd = netconn->socket;

        struct lwip_sock *sock = get_socket(netconn->socket);
        if (netconn->socket > 0 && sock != NULL && sock->recv_ring != NULL && sock->send_ring != NULL) {
            conn->recv_ring_cnt = gazelle_ring_readable_count(sock->recv_ring);
            conn->recv_ring_cnt += (sock->recv_lastdata) ? 1 : 0;

            conn->send_ring_cnt = gazelle_ring_readover_count(sock->send_ring);
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
    if (((type & SOCK_TYPE_MASK) & ~SOCK_STREAM) != 0){
        LSTACK_LOG(ERR, LSTACK, "sock type error:%d, only support SOCK_STREAM \n", type);
        return -1;
    }

    int32_t fd = lwip_socket(AF_INET, type, 0);
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

    while (sock->listen_next) {
        sock = sock->listen_next;
    }
    sock->listen_next = clone_sock;

    int32_t ret = lwip_bind(clone_fd, addr, addr_len);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "clone bind failed clone_fd=%d errno=%d\n", clone_fd, errno);
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
        conn[conn_num].fd = netconn->socket;
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

void stack_sendlist_count(struct rpc_msg *msg)
{
    msg->result = get_list_count(&get_protocol_stack()->send_list);
}

void stack_recvlist_count(struct rpc_msg *msg)
{
    msg->result = get_list_count(&get_protocol_stack()->recv_list);
}
