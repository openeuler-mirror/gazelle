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
#include "lstack_cfg.h"

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

static void free_list_pbuf(struct pbuf *pbuf)
{
    while (pbuf) {
        struct pbuf *del_pbuf = pbuf;
        pbuf = pbuf->next;

        del_pbuf->next = NULL;
        pbuf_free(del_pbuf);
    }
}

static void reset_sock_data(struct lwip_sock *sock)
{
    /* check null pointer in ring_free func */
    if (sock->recv_ring) {
        free_ring_pbuf(sock->recv_ring);
        rte_ring_free(sock->recv_ring);
        sock->recv_ring = NULL;
    }

    if (sock->send_ring) {
        free_ring_pbuf(sock->send_ring);
        rte_ring_free(sock->send_ring);
        sock->send_ring = NULL;
    }

    if (sock->send_lastdata) {
        free_list_pbuf(sock->send_lastdata);
        sock->send_lastdata = NULL;
    }

    if (sock->send_pre_del) {
        pbuf_free(sock->send_pre_del);
        sock->send_pre_del = NULL;
    }

    sock->stack = NULL;
    sock->wakeup = NULL;
    sock->listen_next = NULL;
    sock->epoll_events = 0;
    sock->events = 0;
    sock->in_send = 0;
    sock->remain_len = 0;

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
        pbuf->l4_len = 0;
        pbuf->header_off = 0;
        pbuf->rexmit = 0;
        pbuf->in_write = 0;
        pbuf->head = 0;
        pbuf->last = pbuf;
    }

    return pbuf;
}

/* true: need replenish again */
static bool replenish_send_idlembuf(struct protocol_stack *stack, struct rte_ring *ring)
{
    void *pbuf[SOCK_SEND_RING_SIZE_MAX];

    uint32_t replenish_cnt = gazelle_ring_free_count(ring);
    if (replenish_cnt == 0) {
        return false;
    }

    if (rte_pktmbuf_alloc_bulk(stack->rxtx_pktmbuf_pool, (struct rte_mbuf **)pbuf, replenish_cnt) != 0) {
        stack->stats.tx_allocmbuf_fail++;
        return true;
    }

    uint32_t i = 0;
    for (; i < replenish_cnt - 1; i++) {
        rte_prefetch0(mbuf_to_pbuf((void *)pbuf[i + 1]));
        pbuf[i] = init_mbuf_to_pbuf(pbuf[i], PBUF_TRANSPORT, MBUF_MAX_DATA_LEN, PBUF_RAM);
    }
    pbuf[i] = init_mbuf_to_pbuf((struct rte_mbuf *)pbuf[i], PBUF_TRANSPORT, MBUF_MAX_DATA_LEN, PBUF_RAM);

    uint32_t num = gazelle_ring_sp_enqueue(ring, pbuf, replenish_cnt);
    for (uint32_t i = num; i < replenish_cnt; i++) {
        pbuf_free(pbuf[i]);
    }

    return false;
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

    sock->send_ring = create_ring("sock_send",
        get_global_cfg_params()->send_ring_size,
        RING_F_SP_ENQ | RING_F_SC_DEQ,
        atomic_fetch_add(&name_tick, 1));
    if (sock->send_ring == NULL) {
        LSTACK_LOG(ERR, LSTACK, "sock_send create failed. errno: %d.\n", rte_errno);
        return;
    }
    (void)replenish_send_idlembuf(stack, sock->send_ring);

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

    rte_pktmbuf_free_seg(mbuf);
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

    if (rte_pktmbuf_alloc_bulk(stack->rxtx_pktmbuf_pool, &mbuf, 1) != 0) {
        stack->stats.tx_allocmbuf_fail++;
        return NULL;
    }

    return init_mbuf_to_pbuf(mbuf, layer, length, type);
}

struct pbuf *write_lwip_data(struct lwip_sock *sock, uint16_t remain_size, uint8_t *apiflags)
{
    struct pbuf *pbuf = NULL;

    if (unlikely(sock->send_pre_del)) {
        pbuf = sock->send_pre_del;
        if (pbuf->tot_len > remain_size ||
            (pbuf->head && __atomic_load_n(&pbuf->in_write, __ATOMIC_ACQUIRE))) {
            *apiflags &= ~TCP_WRITE_FLAG_MORE;
            return NULL;
        }

        if (pbuf->next) {
            sock->send_lastdata = pbuf->next;
            pbuf->next = NULL;
        }
        return pbuf;
    }

    if (sock->send_lastdata) {
        pbuf = sock->send_lastdata;
        if (pbuf->tot_len > remain_size) {
            *apiflags &= ~TCP_WRITE_FLAG_MORE;
            return NULL;
        }
        sock->send_pre_del = pbuf;
        sock->send_lastdata = pbuf->next;
        pbuf->next = NULL;
        return pbuf;
    }

    gazelle_ring_sc_dequeue(sock->send_ring, (void **)&pbuf, 1);
    if (pbuf == NULL) {
        return NULL;
    }
    sock->send_pre_del = pbuf;

    if (pbuf->tot_len > remain_size || __atomic_load_n(&pbuf->in_write, __ATOMIC_ACQUIRE)) {
        *apiflags &= ~TCP_WRITE_FLAG_MORE;
        pbuf->head = 1;
        return NULL;
    }

    sock->send_lastdata = pbuf->next;
    pbuf->next = NULL;
    return pbuf;
}

void write_lwip_over(struct lwip_sock *sock)
{
    sock->send_pre_del = NULL;
    sock->stack->stats.write_lwip_cnt++;
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

static ssize_t do_app_write(struct pbuf *pbufs[], void *buf, size_t len, uint32_t write_num)
{
    ssize_t send_len = 0;
    uint32_t i = 0;

    for (i = 0; i < write_num - 1; i++) {
        rte_prefetch0(pbufs[i + 1]);
        rte_prefetch0(pbufs[i + 1]->payload);
        rte_prefetch0((char *)buf + send_len + MBUF_MAX_DATA_LEN);
        pbuf_take(pbufs[i], (char *)buf + send_len, MBUF_MAX_DATA_LEN);
        pbufs[i]->tot_len = pbufs[i]->len = MBUF_MAX_DATA_LEN;
        send_len += MBUF_MAX_DATA_LEN;
    }

    /* reduce the branch in loop */
    uint16_t copy_len = len - send_len;
    pbuf_take(pbufs[i], (char *)buf + send_len, copy_len);
    pbufs[i]->tot_len = pbufs[i]->len = copy_len;
    send_len += copy_len;

    return send_len;
}

static inline ssize_t app_direct_write(struct protocol_stack *stack, struct lwip_sock *sock, void *buf,
    size_t len, uint32_t write_num)
{
    struct pbuf **pbufs = (struct pbuf **)malloc(write_num * sizeof(struct pbuf *));
    if (pbufs == NULL) {
        return 0;
    }

    /* first pbuf get from send_ring. and malloc pbufs attach to first pbuf */
    if (rte_pktmbuf_alloc_bulk(stack->rxtx_pktmbuf_pool, (struct rte_mbuf **)&pbufs[1], write_num - 1) != 0) {
        stack->stats.tx_allocmbuf_fail++;
        free(pbufs);
        return 0;
    }

    (void)gazelle_ring_read(sock->send_ring, (void **)&pbufs[0], 1);

    uint32_t i = 1;
    for (; i < write_num - 1; i++) {
        rte_prefetch0(mbuf_to_pbuf((void *)pbufs[i + 1]));
        pbufs[i] = init_mbuf_to_pbuf((struct rte_mbuf *)pbufs[i], PBUF_TRANSPORT, MBUF_MAX_DATA_LEN, PBUF_RAM);
        pbufs[i - 1]->next = pbufs[i];
    }
    pbufs[i] = init_mbuf_to_pbuf((struct rte_mbuf *)pbufs[i], PBUF_TRANSPORT, MBUF_MAX_DATA_LEN, PBUF_RAM);
    pbufs[i - 1]->next = pbufs[i];

    ssize_t send_len = do_app_write(pbufs, buf, len, write_num);

    gazelle_ring_read_over(sock->send_ring);

    pbufs[0]->last = pbufs[write_num - 1];
    sock->remain_len = 0;
    free(pbufs);
    return send_len;
}

static inline ssize_t app_direct_attach(struct protocol_stack *stack, struct pbuf *attach_pbuf, void *buf,
    size_t len, uint32_t write_num)
{
    struct pbuf **pbufs = (struct pbuf **)malloc(write_num * sizeof(struct pbuf *));
    if (pbufs == NULL) {
        return 0;
    }

    /* first pbuf get from send_ring. and malloc pbufs attach to first pbuf */
    if (rte_pktmbuf_alloc_bulk(stack->rxtx_pktmbuf_pool, (struct rte_mbuf **)pbufs, write_num) != 0) {
        stack->stats.tx_allocmbuf_fail++;
        free(pbufs);
        return 0;
    }

    pbufs[0] = init_mbuf_to_pbuf((struct rte_mbuf *)pbufs[0], PBUF_TRANSPORT, MBUF_MAX_DATA_LEN, PBUF_RAM);
    uint32_t i = 1;
    for (; i < write_num - 1; i++) {
        rte_prefetch0(mbuf_to_pbuf((void *)pbufs[i + 1]));
        pbufs[i] = init_mbuf_to_pbuf((struct rte_mbuf *)pbufs[i], PBUF_TRANSPORT, MBUF_MAX_DATA_LEN, PBUF_RAM);
        pbufs[i - 1]->next = pbufs[i];
    }
    if (write_num > 1) {
        pbufs[i] = init_mbuf_to_pbuf((struct rte_mbuf *)pbufs[i], PBUF_TRANSPORT, MBUF_MAX_DATA_LEN, PBUF_RAM);
        pbufs[i - 1]->next = pbufs[i];
    }

    ssize_t send_len = do_app_write(pbufs, buf, len, write_num);

    attach_pbuf->last->next = pbufs[0];
    attach_pbuf->last = pbufs[write_num - 1];

    free(pbufs);
    return send_len;
}

static inline ssize_t app_buff_write(struct lwip_sock *sock, void *buf, size_t len, uint32_t write_num)
{
    struct pbuf *pbufs[SOCK_SEND_RING_SIZE_MAX];

    (void)gazelle_ring_read(sock->send_ring, (void **)pbufs, write_num);

    ssize_t send_len = do_app_write(pbufs, buf, len, write_num);

    gazelle_ring_read_over(sock->send_ring);

    sock->remain_len = MBUF_MAX_DATA_LEN - pbufs[write_num - 1]->len;
    return send_len;
}

static inline struct pbuf *gazelle_ring_readlast(struct rte_ring *r)
{
    struct pbuf *last_pbuf = NULL;
    volatile uint32_t tail = __atomic_load_n(&r->cons.tail, __ATOMIC_ACQUIRE);
    uint32_t last = r->prod.tail - 1;
    if (last == tail || last - tail > r->capacity) {
        return NULL;
    }
    
    __rte_ring_dequeue_elems(r, last, (void **)&last_pbuf, sizeof(void *), 1);
    __atomic_store_n(&last_pbuf->in_write, 1, __ATOMIC_RELEASE);

    rte_mb();

    tail = __atomic_load_n(&r->cons.tail, __ATOMIC_ACQUIRE);
    if (last == tail || last - tail > r->capacity) {
        __atomic_store_n(&last_pbuf->in_write, 0, __ATOMIC_RELEASE);
        return NULL;
    }

    return last_pbuf;
}

static inline void gazelle_ring_lastover(struct pbuf *last_pbuf)
{
    __atomic_store_n(&last_pbuf->in_write, 0, __ATOMIC_RELEASE);
}

static inline size_t merge_data_lastpbuf(struct lwip_sock *sock, void *buf, size_t len)
{
    struct pbuf *last_pbuf = gazelle_ring_readlast(sock->send_ring);
    if (last_pbuf == NULL) {
        sock->remain_len = 0;
        return 0;
    }

    if (last_pbuf->next || last_pbuf->len >= MBUF_MAX_DATA_LEN) {
        sock->remain_len = 0;
        gazelle_ring_lastover(last_pbuf);
        return 0;
    }

    size_t send_len = MBUF_MAX_DATA_LEN - last_pbuf->len;
    if (send_len >= len) {
        sock->remain_len = send_len - len;
        send_len = len;
    } else {
        sock->remain_len = 0;
    }

    uint16_t offset = last_pbuf->len;
    last_pbuf->tot_len = last_pbuf->len = offset + send_len;
    pbuf_take_at(last_pbuf, buf, send_len, offset);

    gazelle_ring_lastover(last_pbuf);

    return send_len;
}

ssize_t write_stack_data(struct lwip_sock *sock, const void *buf, size_t len)
{
    if (sock->errevent > 0) {
        GAZELLE_RETURN(ENOTCONN);
    }

    struct protocol_stack *stack = sock->stack;
    if (!stack|| len == 0) {
        return 0;
    }

    ssize_t send_len = 0;

    /* merge data into last pbuf */
    if (sock->remain_len) {
        send_len = merge_data_lastpbuf(sock, (char *)buf, len);
        if (send_len >= len) {
            return len;
        }
    }

    uint32_t write_num = (len - send_len + MBUF_MAX_DATA_LEN - 1) / MBUF_MAX_DATA_LEN;
    uint32_t write_avail = gazelle_ring_readable_count(sock->send_ring);
    struct wakeup_poll *wakeup = sock->wakeup;

    /* send_ring is full, data attach last pbuf */
    if (write_avail == 0) {
        struct pbuf *last_pbuf = gazelle_ring_readlast(sock->send_ring);
        if (last_pbuf) {
            send_len += app_direct_attach(stack, last_pbuf, (char *)buf + send_len, len - send_len, write_num);
            gazelle_ring_lastover(last_pbuf);
            if (wakeup) {
                wakeup->stat.app_write_cnt += write_num;
            }
        } else {
            (void)rpc_call_replenish(stack, sock);
            if (wakeup) {
                wakeup->stat.app_write_rpc++;
            }
        }
        sock->remain_len = 0;
        return send_len;
    }

    /* send_ring have idle */
    send_len += (write_num <= write_avail) ? app_buff_write(sock, (char *)buf + send_len, len - send_len, write_num) :
        app_direct_write(stack, sock, (char *)buf + send_len, len - send_len, write_num);
    if (wakeup) {
        wakeup->stat.app_write_cnt += write_num;
    }

    if (wakeup && wakeup->type == WAKEUP_EPOLL && (sock->events & EPOLLOUT)) {
        del_data_out_event(sock);
    }

    return send_len;
}

static inline bool replenish_send_ring(struct protocol_stack *stack, struct lwip_sock *sock)
{
    bool replenish_again = false;

    replenish_again = replenish_send_idlembuf(stack, sock->send_ring);

    if ((sock->epoll_events & EPOLLOUT) && NETCONN_IS_OUTIDLE(sock)) {
        add_sock_event(sock, EPOLLOUT);
    }

    return replenish_again;
}

void rpc_replenish(struct rpc_msg *msg)
{
    struct protocol_stack *stack = (struct protocol_stack *)msg->args[MSG_ARG_0].p;
    struct lwip_sock *sock = (struct lwip_sock *)msg->args[MSG_ARG_1].p;

    msg->result = replenish_send_ring(stack, sock);
}

static inline bool do_lwip_send(struct protocol_stack *stack, int32_t fd, struct lwip_sock *sock, int32_t flags)
{
    /* send all send_ring, so len set lwip send max. */
    (void)lwip_send(fd, sock, UINT16_MAX, flags);

    return replenish_send_ring(stack, sock);
}

void stack_send(struct rpc_msg *msg)
{
    int32_t fd = msg->args[MSG_ARG_0].i;
    struct protocol_stack *stack = (struct protocol_stack *)msg->args[MSG_ARG_3].p;

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        msg->result = -1;
        return;
    }

    __atomic_store_n(&sock->in_send, 0, __ATOMIC_RELEASE);
    rte_mb();

    /* have remain data or replenish again add sendlist */
    if (sock->errevent == 0 && NETCONN_IS_DATAOUT(sock)) {
        if (list_is_null(&sock->send_list)) {
            list_add_node(&stack->send_list, &sock->send_list);
            __atomic_store_n(&sock->in_send, 1, __ATOMIC_RELEASE);
        }
    }
}

void send_stack_list(struct protocol_stack *stack, uint32_t send_max)
{
    struct list_node *node, *temp;
    struct lwip_sock *sock;
    uint32_t read_num = 0;
    bool replenish_again;

    list_for_each_safe(node, temp, &stack->send_list) {
        sock = container_of(node, struct lwip_sock, send_list);

        if (++read_num > send_max) {
            /* list head move to next send */
            list_del_node(&stack->send_list);
            list_add_node(&sock->send_list, &stack->send_list);
            break;
        }

        __atomic_store_n(&sock->in_send, 0, __ATOMIC_RELEASE);
        rte_mb();

        if (sock->conn == NULL || sock->errevent > 0) {
            list_del_node_null(&sock->send_list);
            continue;
        }

        replenish_again = do_lwip_send(stack, sock->conn->socket, sock, 0);

        if (!NETCONN_IS_DATAOUT(sock) && !replenish_again) {
            list_del_node_null(&sock->send_list);
        } else {
            __atomic_store_n(&sock->in_send, 1, __ATOMIC_RELEASE);
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

static inline struct pbuf *gazelle_ring_enqueuelast(struct rte_ring *r)
{
    struct pbuf *last_pbuf = NULL;
    volatile uint32_t head = __atomic_load_n(&r->prod.head, __ATOMIC_ACQUIRE);
    uint32_t last = r->cons.head - 1;
    if (last == head || last - head > r->capacity) {
        return NULL;
    }

    __rte_ring_dequeue_elems(r, last, (void **)&last_pbuf, sizeof(void *), 1);
    __atomic_store_n(&last_pbuf->in_write, 1, __ATOMIC_RELEASE);

    rte_mb();

    head = __atomic_load_n(&r->prod.head, __ATOMIC_ACQUIRE);
    if (last == head || last - head > r->capacity) {
        __atomic_store_n(&last_pbuf->in_write, 0, __ATOMIC_RELEASE);
        return NULL;
    }

    return last_pbuf;
}

static inline struct pbuf *pbuf_last(struct pbuf *pbuf)
{
    while (pbuf->next) {
        pbuf = pbuf->next;
    }
    return pbuf;
}

ssize_t read_lwip_data(struct lwip_sock *sock, int32_t flags, u8_t apiflags)
{
    if (sock->conn->recvmbox == NULL) {
        return 0;
    }

    free_recv_ring_readover(sock->recv_ring);

    uint32_t free_count = gazelle_ring_free_count(sock->recv_ring);
    if (free_count == 0) {
        GAZELLE_RETURN(EAGAIN);
    }

    uint32_t data_count = rte_ring_count(sock->conn->recvmbox->ring);
    uint32_t read_num = LWIP_MIN(free_count, data_count);
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

    uint32_t enqueue_num = gazelle_ring_sp_enqueue(sock->recv_ring, (void **)pbufs, read_count);
    for (uint32_t i = enqueue_num; i < read_count; i++) {
        /* update receive window */
        tcp_recved(sock->conn->pcb.tcp, pbufs[i]->tot_len);
        pbuf_free(pbufs[i]);
        sock->stack->stats.read_lwip_drop++;
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
            ((ssize_t)(buflen + (ssize_t)message->msg_iov[i].iov_len) < 0)) {
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
        if (message->msg_iov[i].iov_len == 0) {
            continue;
        }

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
    uint32_t tot_len = pbuf->tot_len - free_len;

    while (free_len && pbuf) {
        if (free_len >= pbuf->len) {
            free_len = free_len - pbuf->len;
            pbuf = pbuf->next;
        } else {
            pbuf_remove_header(pbuf, free_len);
            break;
        }
    }

    if (pbuf) {
        pbuf->tot_len = tot_len;
    }
    return pbuf;
}

ssize_t read_stack_data(int32_t fd, void *buf, size_t len, int32_t flags)
{
    size_t recv_left = len;
    struct pbuf *pbuf = NULL;
    ssize_t recvd = 0;
    uint32_t copy_len;
    struct lwip_sock *sock = get_socket_by_fd(fd);
    bool latency_enable = get_protocol_stack_group()->latency_start;

    if (sock->errevent > 0 && !NETCONN_IS_DATAIN(sock)) {
        return 0;
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

        copy_len = (recv_left > pbuf->tot_len) ? pbuf->tot_len : recv_left;
        if (copy_len > UINT16_MAX) {
            copy_len = UINT16_MAX;
        }
        pbuf_copy_partial(pbuf, (char *)buf + recvd, copy_len, 0);

        recvd += copy_len;
        recv_left -= copy_len;

        if (pbuf->tot_len > copy_len) {
            sock->recv_lastdata = pbuf_free_partial(pbuf, copy_len);
            break;
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

    list_for_each_safe(node, temp, list) {
        sock = container_of(node, struct lwip_sock, recv_list);

        if (++read_num > max_num) {
            /* list head move to next send */
            list_del_node(&stack->recv_list);
            list_add_node(&sock->recv_list, &stack->recv_list);
            break;
        }

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
    conn->cwn = pcb->cwnd;
    conn->rcv_wnd = pcb->rcv_wnd;
    conn->snd_wnd = pcb->snd_wnd;
    conn->snd_buf = pcb->snd_buf;
    conn->lastack = pcb->lastack;
    conn->snd_nxt = pcb->snd_nxt;
    conn->rcv_nxt = pcb->rcv_nxt;

    if (netconn != NULL && netconn->recvmbox != NULL) {
        conn->recv_cnt = rte_ring_count(netconn->recvmbox->ring);
        conn->fd = netconn->socket;

        struct lwip_sock *sock = get_socket(netconn->socket);
        if (netconn->socket > 0 && sock != NULL && sock->recv_ring != NULL && sock->send_ring != NULL) {
            conn->recv_ring_cnt = gazelle_ring_readable_count(sock->recv_ring);
            conn->recv_ring_cnt += (sock->recv_lastdata) ? 1 : 0;
            conn->send_ring_cnt = gazelle_ring_readover_count(sock->send_ring);
            conn->events = sock->events;
            conn->epoll_events = sock->epoll_events;
            conn->eventlist = !list_is_null(&sock->event_list);
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

void stack_mempool_size(struct rpc_msg *msg)
{
    struct protocol_stack *stack = (struct protocol_stack*)msg->args[MSG_ARG_0].p;

    msg->result = rte_mempool_avail_count(stack->rxtx_pktmbuf_pool);
}

void stack_sendlist_count(struct rpc_msg *msg)
{
    struct protocol_stack *stack = (struct protocol_stack*)msg->args[MSG_ARG_0].p;

    msg->result = get_list_count(&stack->send_list);
}

void stack_recvlist_count(struct rpc_msg *msg)
{
    struct protocol_stack *stack = (struct protocol_stack*)msg->args[MSG_ARG_0].p;

    msg->result = get_list_count(&stack->recv_list);
}
