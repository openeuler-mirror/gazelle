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
#include <lwip/udp.h>
#include <lwipsock.h>
#include <arch/sys_arch.h>
#include <lwip/pbuf.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/posix_api.h>
#include <lwip/api.h>
#include <lwip/tcp.h>
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
#include "lstack_cfg.h"
#include "lstack_lwip.h"

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
        gazelle_ring_free_fast(sock->recv_ring);
        sock->recv_ring = NULL;
    }

    if (sock->send_ring) {
        free_ring_pbuf(sock->send_ring);
        gazelle_ring_free_fast(sock->send_ring);
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
    sock->call_num = 0;
    sock->remain_len = 0;
    sock->already_bind_numa = 0;

    if (sock->recv_lastdata) {
        pbuf_free(sock->recv_lastdata);
    }
    sock->recv_lastdata = NULL;
}

static struct pbuf *init_mbuf_to_pbuf(struct rte_mbuf *mbuf, pbuf_layer layer, uint16_t length, pbuf_type type)
{
    struct pbuf_custom *pbuf_custom = mbuf_to_pbuf(mbuf);

    void *data = rte_pktmbuf_mtod(mbuf, void *);
    struct pbuf *pbuf = pbuf_alloced_custom(layer, length, type, pbuf_custom, data, MAX_PACKET_SZ);
    if (pbuf) {
        pbuf->ol_flags = 0;
        pbuf->l2_len = 0;
        pbuf->l3_len = 0;
        pbuf->l4_len = 0;
        pbuf->header_off = 0;
        pbuf->rexmit = 0;
        pbuf->allow_in = 1;
        pbuf->head = 0;
        pbuf->last = pbuf;
        pbuf->addr = *IP_ANY_TYPE;
        pbuf->port = 0;
        pthread_spin_init(&pbuf->pbuf_lock, PTHREAD_PROCESS_SHARED);
    }

    return pbuf;
}

/* true: need replenish again */
static bool replenish_send_idlembuf(struct protocol_stack *stack, struct lwip_sock *sock)
{
    void *pbuf[SOCK_SEND_RING_SIZE_MAX];

    struct rte_ring *ring = sock->send_ring;

    uint32_t replenish_cnt = gazelle_ring_free_count(ring);
    if (replenish_cnt == 0) {
        return false;
    }

    if (dpdk_alloc_pktmbuf(stack->rxtx_mbuf_pool, (struct rte_mbuf **)pbuf, replenish_cnt) != 0) {
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

    if (!get_global_cfg_params()->expand_send_ring) {
        sem_post(&sock->snd_ring_sem);
    }

    return false;
}

void do_lwip_init_sock(int32_t fd)
{
    struct protocol_stack *stack = get_protocol_stack();
    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL) {
        return;
    }

    reset_sock_data(sock);

    sock->recv_ring = gazelle_ring_create_fast("sock_recv", SOCK_RECV_RING_SIZE, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (sock->recv_ring == NULL) {
        LSTACK_LOG(ERR, LSTACK, "sock_recv create failed. errno: %d.\n", rte_errno);
        return;
    }

    sock->send_ring = gazelle_ring_create_fast("sock_send",
        get_global_cfg_params()->send_ring_size,
        RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (sock->send_ring == NULL) {
        gazelle_ring_free_fast(sock->recv_ring);
        LSTACK_LOG(ERR, LSTACK, "sock_send create failed. errno: %d.\n", rte_errno);
        return;
    }
    (void)replenish_send_idlembuf(stack, sock);

    sock->stack = stack;

    init_list_node_null(&sock->recv_list);
    init_list_node_null(&sock->event_list);
}

void do_lwip_clean_sock(int fd)
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
}

void do_lwip_free_pbuf(struct pbuf *pbuf)
{
    if (pbuf == NULL) {
        return;
    }

    struct rte_mbuf *mbuf = pbuf_to_mbuf(pbuf);

    rte_pktmbuf_free_seg(mbuf);
}

struct pbuf *do_lwip_alloc_pbuf(pbuf_layer layer, uint16_t length, pbuf_type type)
{
    struct rte_mbuf *mbuf;
    struct protocol_stack *stack = get_protocol_stack();

    if (dpdk_alloc_pktmbuf(stack->rxtx_mbuf_pool, &mbuf, 1) != 0) {
        stack->stats.tx_allocmbuf_fail++;
        return NULL;
    }

    return init_mbuf_to_pbuf(mbuf, layer, length, type);
}

struct pbuf *do_lwip_get_from_sendring(struct lwip_sock *sock, uint16_t remain_size, uint8_t *apiflags)
{
    struct pbuf *pbuf = NULL;

    if (unlikely(sock->send_pre_del)) {
        pbuf = sock->send_pre_del;
        pthread_spin_lock(&pbuf->pbuf_lock);
        if (pbuf->tot_len > remain_size) {
            pthread_spin_unlock(&pbuf->pbuf_lock);
            *apiflags &= ~TCP_WRITE_FLAG_MORE;
            return NULL;
        }
        if (pbuf->allow_in == 1) {
            __sync_fetch_and_sub(&pbuf->allow_in, 1);
        }
        pthread_spin_unlock(&pbuf->pbuf_lock);

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

    if (!gazelle_ring_readover_count(sock->send_ring)) {
        pthread_spin_lock(&pbuf->pbuf_lock);
        if (pbuf->tot_len > remain_size) {
            pthread_spin_unlock(&pbuf->pbuf_lock);
            *apiflags &= ~TCP_WRITE_FLAG_MORE;
            pbuf->head = 1;
            return NULL;
        }
        if (pbuf->allow_in == 1) {
            __sync_fetch_and_sub(&pbuf->allow_in, 1);
        }
        pthread_spin_unlock(&pbuf->pbuf_lock);
    } else {
        if (pbuf->tot_len > remain_size) {
            *apiflags &= ~TCP_WRITE_FLAG_MORE;
            pbuf->head = 1;
            return NULL;
        }
    }

    sock->send_lastdata = pbuf->next;
    pbuf->next = NULL;
    return pbuf;
}

void do_lwip_get_from_sendring_over(struct lwip_sock *sock)
{
    sock->send_pre_del = NULL;
    sock->stack->stats.write_lwip_cnt++;
}

static ssize_t do_app_write(struct pbuf *pbufs[], void *buf, size_t len, uint32_t write_num)
{
    ssize_t send_len = 0;
    uint32_t i = 0;
    uint32_t expand_send_ring = get_global_cfg_params()->expand_send_ring;

    for (i = 0; i < write_num - 1; i++) {
        rte_prefetch0(pbufs[i + 1]);
        rte_prefetch0(pbufs[i + 1]->payload);
        rte_prefetch0((char *)buf + send_len + MBUF_MAX_DATA_LEN);
        if (expand_send_ring) {
            pbuf_take(pbufs[i], (char *)buf + send_len, MBUF_MAX_DATA_LEN);
        } else {
            rte_memcpy((char *)pbufs[i]->payload, (char *)buf + send_len, MBUF_MAX_DATA_LEN);
        }
        pbufs[i]->tot_len = pbufs[i]->len = MBUF_MAX_DATA_LEN;
        send_len += MBUF_MAX_DATA_LEN;
    }

    /* reduce the branch in loop */
    uint16_t copy_len = len - send_len;
    if (expand_send_ring) {
        pbuf_take(pbufs[i], (char *)buf + send_len, copy_len);
    } else {
        rte_memcpy((char *)pbufs[i]->payload, (char *)buf + send_len, copy_len);
    }
    pbufs[i]->tot_len = pbufs[i]->len = copy_len;
    send_len += copy_len;

    return send_len;
}

static inline ssize_t app_direct_write(struct protocol_stack *stack, struct lwip_sock *sock, void *buf,
    size_t len, uint32_t write_num)
{
    if (write_num == 0) {
        return 0;
    }
    struct pbuf **pbufs = (struct pbuf **)malloc(write_num * sizeof(struct pbuf *));
    if (pbufs == NULL) {
        return 0;
    }

    /* first pbuf get from send_ring. and malloc pbufs attach to first pbuf */
    if (dpdk_alloc_pktmbuf(stack->rxtx_mbuf_pool, (struct rte_mbuf **)&pbufs[1], write_num - 1) != 0) {
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
    if (write_num == 0) {
        return 0;
    }
    struct pbuf **pbufs = (struct pbuf **)malloc(write_num * sizeof(struct pbuf *));
    if (pbufs == NULL) {
        return 0;
    }

    /* first pbuf get from send_ring. and malloc pbufs attach to first pbuf */
    if (dpdk_alloc_pktmbuf(stack->rxtx_mbuf_pool, (struct rte_mbuf **)pbufs, write_num) != 0) {
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

static inline ssize_t app_buff_write(struct lwip_sock *sock, void *buf, size_t len, uint32_t write_num,
                                     const struct sockaddr *addr, socklen_t addrlen)
{
    struct pbuf *pbufs[SOCK_SEND_RING_SIZE_MAX];

    (void)gazelle_ring_read(sock->send_ring, (void **)pbufs, write_num);

    ssize_t send_len = do_app_write(pbufs, buf, len, write_num);

    if (addr) {
        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
            for (int i = 0; i < write_num; i++) {
                pbufs[i]->addr.u_addr.ip4.addr = saddr->sin_addr.s_addr;
                pbufs[i]->port = lwip_ntohs((saddr)->sin_port);
                IP_SET_TYPE(&pbufs[i]->addr, IPADDR_TYPE_V4);
            }
        } else if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)addr;
            for (int i = 0; i < write_num; i++) {
                memcpy_s(pbufs[i]->addr.u_addr.ip6.addr, IPV6_ADDR_LEN, saddr->sin6_addr.s6_addr, IPV6_ADDR_LEN);
                pbufs[i]->port = lwip_ntohs((saddr)->sin6_port);
                IP_SET_TYPE(&pbufs[i]->addr, IPADDR_TYPE_V6);
            }
        } else {
            return 0;
        }
    }

    gazelle_ring_read_over(sock->send_ring);

    sock->remain_len = MBUF_MAX_DATA_LEN - pbufs[write_num - 1]->len;
    return send_len;
}

static inline struct pbuf *gazelle_ring_readlast(struct rte_ring *r)
{
    struct pbuf *last_pbuf = NULL;
    volatile uint32_t tail = __atomic_load_n(&r->cons.tail, __ATOMIC_ACQUIRE);
    uint32_t last = r->prod.tail - 1;
    if (last + 1 == tail || last + 1 - tail > r->capacity) {
        return NULL;
    }
    
    __rte_ring_dequeue_elems(r, last, (void **)&last_pbuf, sizeof(void *), 1);

    if (pthread_spin_trylock(&last_pbuf->pbuf_lock) != 0) {
        return NULL;
    }
    if (last_pbuf->allow_in != 1) {
        pthread_spin_unlock(&last_pbuf->pbuf_lock);
        return NULL;
    }

    return last_pbuf;
}

static inline void gazelle_ring_lastover(struct pbuf *last_pbuf)
{
    pthread_spin_unlock(&last_pbuf->pbuf_lock);
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
    if (get_global_cfg_params()->expand_send_ring) {
        pbuf_take_at(last_pbuf, buf, send_len, offset);
    } else {
        rte_memcpy((char *)last_pbuf->payload + offset, buf, send_len);
    }

    gazelle_ring_lastover(last_pbuf);

    return send_len;
}

int sem_timedwait_nsecs(sem_t *sem)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long long wait_nsec = ts.tv_nsec + SEND_TIME_WAIT_NS;
    ts.tv_nsec = wait_nsec % SECOND_NSECOND;
    long add = wait_nsec / SECOND_NSECOND;
    ts.tv_sec += add;
    return sem_timedwait(sem, &ts);
}

static ssize_t do_lwip_fill_sendring(struct lwip_sock *sock, const void *buf, size_t len,
                                     const struct sockaddr *addr, socklen_t addrlen)
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
            send_len = len;
            goto END;
        }
    }

    uint32_t write_num = (len - send_len + MBUF_MAX_DATA_LEN - 1) / MBUF_MAX_DATA_LEN;
    uint32_t write_avail = gazelle_ring_readable_count(sock->send_ring);
    struct wakeup_poll *wakeup = sock->wakeup;

    while (!netconn_is_nonblocking(sock->conn) && (write_avail < write_num)) {
        if (sock->errevent > 0) {
            GAZELLE_RETURN(ENOTCONN);
        }
        write_avail = gazelle_ring_readable_count(sock->send_ring);
    }

    /* send_ring is full, data attach last pbuf */
    if (write_avail == 0) {
        if (!get_global_cfg_params()->expand_send_ring) {
            sem_timedwait_nsecs(&sock->snd_ring_sem);
            if (likely(sock->send_ring != NULL)) {
                write_avail = gazelle_ring_readable_count(sock->send_ring);
            }
            goto END;
        }
        if (unlikely(sock->send_ring == NULL)) {
            goto END;
        }
        struct pbuf *last_pbuf = gazelle_ring_readlast(sock->send_ring);
        if (last_pbuf) {
            send_len += app_direct_attach(stack, last_pbuf, (char *)buf + send_len, len - send_len, write_num);
            gazelle_ring_lastover(last_pbuf);
            if (wakeup) {
                wakeup->stat.app_write_cnt += write_num;
            }
            if (addr->sa_family == AF_INET) {
                struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
                last_pbuf->addr.u_addr.ip4.addr = saddr->sin_addr.s_addr;
                last_pbuf->port = lwip_ntohs((saddr)->sin_port);
            } else if (addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)addr;
                memcpy_s(last_pbuf->addr.u_addr.ip6.addr, sizeof(last_pbuf->addr.u_addr.ip6.addr),
                    saddr->sin6_addr.s6_addr, sizeof(saddr->sin6_addr.s6_addr));
                last_pbuf->port = lwip_ntohs((saddr)->sin6_port);
            }
        } else {
            (void)rpc_call_replenish(stack, sock);
            if (wakeup) {
                wakeup->stat.app_write_rpc++;
            }
        }
        sock->remain_len = 0;
        goto END;
    }

    /* send_ring have idle */
    if (get_global_cfg_params()->expand_send_ring) {
        send_len += (write_num <= write_avail) ?
            app_buff_write(sock, (char *)buf + send_len, len - send_len, write_num, addr, addrlen) :
            app_direct_write(stack, sock, (char *)buf + send_len, len - send_len, write_num);
    } else {
        if (write_num > write_avail) {
            write_num = write_avail;
            len = write_num * MBUF_MAX_DATA_LEN;
        }
        send_len += app_buff_write(sock, (char *)buf + send_len, len - send_len, write_num, addr, addrlen);
    }

    if (wakeup) {
        wakeup->stat.app_write_cnt += write_num;
    }

    if (wakeup && wakeup->type == WAKEUP_EPOLL && (sock->events & EPOLLOUT)
        && !NETCONN_IS_OUTIDLE(sock)) {
        del_sock_event(sock, EPOLLOUT);
    }

END:
    if (send_len == 0) {
        errno = EAGAIN;
        return -1;
    }
    return send_len;
}

bool do_lwip_replenish_sendring(struct protocol_stack *stack, struct lwip_sock *sock)
{
    bool replenish_again = false;

    replenish_again = replenish_send_idlembuf(stack, sock);

    if (NETCONN_IS_OUTIDLE(sock)) {
        add_sock_event(sock, EPOLLOUT);
    }

    return replenish_again;
}

int do_lwip_send(struct protocol_stack *stack, int32_t fd, struct lwip_sock *sock,
                 size_t len, int32_t flags)
{
    ssize_t ret;
    /* send all send_ring, so len set lwip send max. */
    if (NETCONN_IS_UDP(sock)) {
        ret = lwip_send(fd, sock, len, flags);
    } else {
        ret = lwip_send(fd, sock, UINT16_MAX, flags);
    }
    if (ret < 0 && (errno == ENOTCONN || errno == ECONNRESET || errno == ECONNABORTED)) {
        return -1;
    }

    return do_lwip_replenish_sendring(stack, sock);
}

static inline void free_recv_ring_readover(struct rte_ring *ring)
{
    void *pbufs[SOCK_RECV_RING_SIZE];
    uint32_t num = gazelle_ring_sc_dequeue(ring, pbufs, RING_SIZE(SOCK_RECV_RING_SIZE));
    for (uint32_t i = 0; i < num; i++) {
        pbuf_free(pbufs[i]);
    }
}

static inline struct pbuf *pbuf_last(struct pbuf *pbuf)
{
    while (pbuf->next) {
        pbuf = pbuf->next;
    }
    return pbuf;
}

ssize_t do_lwip_read_from_lwip(struct lwip_sock *sock, int32_t flags, u8_t apiflags)
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

        err_t err = ERR_OK;
        if (NETCONN_IS_UDP(sock)) {
            err = netconn_recv_udp_raw_pbuf_flags(sock->conn, &pbufs[i], apiflags);
        } else {
            err = netconn_recv_tcp_pbuf_flags(sock->conn, &pbufs[i], apiflags);
        }
        if (err != ERR_OK) {
            if (recv_len > 0) {
                /* already received data, return that (this trusts in getting the same error from
                   netconn layer again next time netconn_recv is called) */
                break;
            }
            return (err == ERR_CLSD) ? 0 : -1;
        }

        recv_len += pbufs[i]->tot_len;
        lstack_calculate_aggregate(0, pbufs[i]->tot_len);
        read_count++;

        /* once we have some data to return, only add more if we don't need to wait */
        apiflags |= NETCONN_DONTBLOCK | NETCONN_NOFIN;
    }

    uint32_t enqueue_num = gazelle_ring_sp_enqueue(sock->recv_ring, (void **)pbufs, read_count);
    for (uint32_t i = enqueue_num; i < read_count; i++) {
        if (NETCONN_IS_UDP(sock)) {
            pbuf_free(pbufs[i]);
        } else {
            /* update receive window */
            tcp_recved(sock->conn->pcb.tcp, pbufs[i]->tot_len);
            pbuf_free(pbufs[i]);
        }
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

ssize_t do_lwip_recvmsg_from_stack(int32_t s, const struct msghdr *message, int32_t flags)
{
    ssize_t buflen = 0;

    if (check_msg_vaild(message)) {
        GAZELLE_RETURN(EINVAL);
    }

    for (int32_t i = 0; i < message->msg_iovlen; i++) {
        if (message->msg_iov[i].iov_len == 0) {
            continue;
        }

        ssize_t recvd_local = do_lwip_read_from_stack(s, message->msg_iov[i].iov_base, message->msg_iov[i].iov_len,
                                                      flags, NULL, NULL);
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
    // 2: call_num >= 2, don't need add new rpc send
    if (__atomic_load_n(&sock->call_num, __ATOMIC_ACQUIRE) < 2) {
        while (rpc_call_send(fd, NULL, len, flags) < 0) {
            usleep(1000); // 1000: wait 1ms to exec again
        }
        __sync_fetch_and_add(&sock->call_num, 1);
    }
}

/* process on same node use ring to recv data */
ssize_t gazelle_same_node_ring_recv(struct lwip_sock *sock, const void *buf, size_t len, int32_t flags)
{
    unsigned long long cur_begin = sock->same_node_rx_ring->sndbegin;
    unsigned long long cur_end;
    unsigned long long index = cur_begin + 1;
    size_t act_len = 0;

    cur_end = __atomic_load_n(&sock->same_node_rx_ring->sndend, __ATOMIC_ACQUIRE);
    if (cur_begin == cur_end) {
        errno = EAGAIN;
        act_len = -1;
        goto END;
    }
    act_len = cur_end - index + 1;
    act_len = RTE_MIN(act_len, len);
    if ((index & SAME_NODE_RING_MASK) + act_len > SAME_NODE_RING_LEN) {
        size_t act_len1 = SAME_NODE_RING_LEN - (index & SAME_NODE_RING_MASK);
        size_t act_len2 = act_len - act_len1;
        rte_memcpy((char *)buf, (char *)sock->same_node_rx_ring->mz->addr + (index & SAME_NODE_RING_MASK), act_len1);
        rte_memcpy((char *)buf + act_len1, (char *)sock->same_node_rx_ring->mz->addr, act_len2);
    } else {
        rte_memcpy((char *)buf, (char *)sock->same_node_rx_ring->mz->addr + (index & SAME_NODE_RING_MASK), act_len);
    }

    index += act_len;
    __atomic_store_n(&sock->same_node_rx_ring->sndbegin, index - 1, __ATOMIC_RELEASE);

END:
    /* rte_ring_count reduce lock */
    if (sock->wakeup && sock->wakeup->type == WAKEUP_EPOLL && (sock->events & EPOLLIN)
        && (!NETCONN_IS_DATAIN(sock))) {
        del_sock_event(sock, EPOLLIN);
    }
    return act_len;
}

/* processes on same node use ring to send data */
ssize_t gazelle_same_node_ring_send(struct lwip_sock *sock, const void *buf, size_t len, int32_t flags)
{
    unsigned long long cur_begin = __atomic_load_n(&sock->same_node_tx_ring->sndbegin, __ATOMIC_ACQUIRE);
    unsigned long long cur_end = sock->same_node_tx_ring->sndend;
    if (cur_end >= cur_begin + SAME_NODE_RING_LEN) {
        errno = EAGAIN;
        return -1;
    }

    unsigned long long index = cur_end + 1;
    size_t act_len = SAME_NODE_RING_LEN - (cur_end - cur_begin);
    act_len = RTE_MIN(act_len, len);

    if ((index & SAME_NODE_RING_MASK) + act_len > SAME_NODE_RING_LEN) {
        size_t act_len1 = SAME_NODE_RING_LEN - (index & SAME_NODE_RING_MASK);
        size_t act_len2 = act_len - act_len1;
        rte_memcpy((char *)sock->same_node_tx_ring->mz->addr + (index & SAME_NODE_RING_MASK), buf, act_len1);
        rte_memcpy((char *)sock->same_node_tx_ring->mz->addr, (char *)buf + act_len1, act_len2);
    } else {
        rte_memcpy((char *)sock->same_node_tx_ring->mz->addr + (index & SAME_NODE_RING_MASK), buf, act_len);
    }

    index  += act_len;
    __atomic_store_n(&sock->same_node_tx_ring->sndend, index - 1, __ATOMIC_RELEASE);
    if (act_len == 0) {
        errno = EAGAIN;
        return -1;
    }

    return act_len;
}

PER_THREAD uint16_t stack_sock_num[GAZELLE_MAX_STACK_NUM] = {0};
PER_THREAD uint16_t max_sock_stack = 0;

static inline void thread_bind_stack(struct lwip_sock *sock)
{
    if (likely(sock->already_bind_numa || !sock->stack)) {
        return;
    }
    sock->already_bind_numa = 1;

    if (get_global_cfg_params()->app_bind_numa == 0) {
        return;
    }

    stack_sock_num[sock->stack->stack_idx]++;
    if (stack_sock_num[sock->stack->stack_idx] > max_sock_stack) {
        max_sock_stack = stack_sock_num[sock->stack->stack_idx];
        bind_to_stack_numa(sock->stack);
    }
}

ssize_t do_lwip_send_to_stack(int32_t fd, const void *buf, size_t len, int32_t flags,
                              const struct sockaddr *addr, socklen_t addrlen)
{
    if (buf == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    if (len == 0) {
        return 0;
    }

    struct lwip_sock *sock = get_socket_by_fd(fd);

    thread_bind_stack(sock);

    if (sock->same_node_tx_ring != NULL) {
        return gazelle_same_node_ring_send(sock, buf, len, flags);
    }
    ssize_t send = do_lwip_fill_sendring(sock, buf, len, addr, addrlen);
    if (send <= 0) {
        return send;
    }

    notice_stack_send(sock, fd, send, flags);
    return send;
}

ssize_t do_lwip_sendmsg_to_stack(struct lwip_sock *sock, int32_t s, const struct msghdr *message, int32_t flags)
{
    int32_t ret;
    int32_t i;
    ssize_t buflen = 0;

    if (check_msg_vaild(message)) {
        GAZELLE_RETURN(EINVAL);
    }

    for (i = 0; i < message->msg_iovlen; i++) {
        if (message->msg_iov[i].iov_len == 0) {
            continue;
        }

        ret = do_lwip_fill_sendring(sock, message->msg_iov[i].iov_base, message->msg_iov[i].iov_len, NULL, 0);
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

ssize_t do_lwip_read_from_stack(int32_t fd, void *buf, size_t len, int32_t flags,
                                struct sockaddr *addr, socklen_t *addrlen)
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

    thread_bind_stack(sock);

    if (sock->same_node_rx_ring != NULL) {
        return gazelle_same_node_ring_recv(sock, buf, len, flags);
    }

    while (recv_left > 0) {
        if (sock->recv_lastdata) {
            pbuf = sock->recv_lastdata;
            sock->recv_lastdata = NULL;
        } else {
            if (netconn_is_nonblocking(sock->conn)) {
                if (gazelle_ring_read(sock->recv_ring, (void **)&pbuf, 1) != 1) {
                    break;
                }
            } else {
                while (gazelle_ring_read(sock->recv_ring, (void **)&pbuf, 1) != 1 && recvd == 0) {
                    /* if the connection is disconnected, recv return 0 */
                    if ((sock->errevent > 0 || (sock->conn->pcb.tcp->flags & TF_FIN)) && !NETCONN_IS_DATAIN(sock)) {
                        return 0;
                    }

                    lstack_block_wait(sock->wakeup);
                }
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
    if (sock->wakeup && sock->wakeup->type == WAKEUP_EPOLL && (sock->events & EPOLLIN)
        && (!NETCONN_IS_DATAIN(sock))) {
        del_sock_event(sock, EPOLLIN);
    }

    if (pbuf && addr && addrlen) {
        lwip_sock_make_addr(sock->conn, &(pbuf->addr), pbuf->port, addr, addrlen);
    }

    if (recvd == 0) {
        if (sock->wakeup) {
            sock->wakeup->stat.read_null++;
        }
        GAZELLE_RETURN(EAGAIN);
    }
    return recvd;
}

void do_lwip_add_recvlist(int32_t fd)
{
    struct lwip_sock *sock = get_socket_by_fd(fd);

    if (sock && sock->stack && list_is_null(&sock->recv_list)) {
        list_add_node(&sock->stack->recv_list, &sock->recv_list);
    }
}

void read_same_node_recv_list(struct protocol_stack *stack)
{
    struct list_node *list = &(stack->same_node_recv_list);
    struct list_node *node, *temp;
    struct lwip_sock *sock;

    list_for_each_safe(node, temp, list) {
        sock = container_of(node, struct lwip_sock, recv_list);

        if (sock->same_node_rx_ring != NULL && same_node_ring_count(sock)) {
            add_sock_event(sock, EPOLLIN);
        }
    }
}

void do_lwip_read_recvlist(struct protocol_stack *stack, uint32_t max_num)
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

        ssize_t len = 0;
        if (NETCONN_IS_UDP(sock)) {
            len = lwip_recv(sock->conn->socket, NULL, SSIZE_MAX, 0);
        } else {
            len = lwip_recv(sock->conn->socket, NULL, 0, 0);
        }
        if (len == 0) {
            sock->errevent = 1;
            add_sock_event(sock, EPOLLERR);
        } else if (len > 0) {
            add_sock_event(sock, EPOLLIN);
        }
    }
}

void do_lwip_connected_callback(struct netconn *conn)
{
    if (conn == NULL) {
        return;
    }

    int32_t fd = conn->socket;
    struct lwip_sock *sock = get_socket_by_fd(fd);
    if (sock == NULL || sock->conn == NULL) {
        return;
    }

    if (sock->wakeup != NULL && sock->wakeup->epollfd > 0) {
        posix_api->epoll_ctl_fn(sock->wakeup->epollfd, EPOLL_CTL_DEL, fd, NULL);
    }

    posix_api->shutdown_fn(fd, SHUT_RDWR);

    SET_CONN_TYPE_LIBOS(conn);

    add_sock_event(sock, EPOLLOUT);
}

static void copy_pcb_to_conn(struct gazelle_stat_lstack_conn_info *conn, const struct tcp_pcb *pcb)
{
    struct netconn *netconn = (struct netconn *)pcb->callback_arg;

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

    if (netconn != NULL) {
        conn->fd = netconn->socket;
        conn->recv_cnt = (netconn->recvmbox == NULL) ? 0 : rte_ring_count(netconn->recvmbox->ring);
        struct lwip_sock *sock = get_socket(netconn->socket);
        if (sock != NULL) {
            conn->recv_ring_cnt = (sock->recv_ring == NULL) ? 0 : gazelle_ring_readable_count(sock->recv_ring);
            conn->recv_ring_cnt += (sock->recv_lastdata) ? 1 : 0;
            conn->send_ring_cnt = (sock->send_ring == NULL) ? 0 : gazelle_ring_readover_count(sock->send_ring);
            conn->events = sock->events;
            conn->epoll_events = sock->epoll_events;
            conn->eventlist = !list_is_null(&sock->event_list);
        }
    }
}

void do_lwip_clone_sockopt(struct lwip_sock *dst_sock, struct lwip_sock *src_sock)
{
    dst_sock->conn->pcb.ip->so_options = src_sock->conn->pcb.ip->so_options;
    dst_sock->conn->pcb.ip->ttl = src_sock->conn->pcb.ip->ttl;
    dst_sock->conn->pcb.ip->tos = src_sock->conn->pcb.ip->tos;
    dst_sock->conn->flags = src_sock->conn->flags;
    if (NETCONN_IS_UDP(src_sock)) {
        dst_sock->conn->pcb.udp->flags = src_sock->conn->pcb.udp->flags;
        dst_sock->conn->pcb.udp->mcast_ifindex = src_sock->conn->pcb.udp->mcast_ifindex;
        dst_sock->conn->pcb.udp->mcast_ttl = src_sock->conn->pcb.udp->mcast_ttl;
    } else {
        dst_sock->conn->pcb.tcp->netif_idx = src_sock->conn->pcb.tcp->netif_idx;
        dst_sock->conn->pcb.tcp->flags = src_sock->conn->pcb.tcp->flags;
        dst_sock->conn->pcb.tcp->keep_idle = src_sock->conn->pcb.tcp->keep_idle;
        dst_sock->conn->pcb.tcp->keep_intvl = src_sock->conn->pcb.tcp->keep_intvl;
        dst_sock->conn->pcb.tcp->keep_cnt = src_sock->conn->pcb.tcp->keep_cnt;
    }
}

int do_lwip_close(int fd)
{
    int ret = lwip_close(fd);
    do_lwip_clean_sock(fd);
    posix_api->close_fn(fd);
    return ret;
}

int do_lwip_socket(int domain, int type, int protocol)
{
    int32_t fd = lwip_socket(domain, type, 0);
    if (fd < 0) {
        return fd;
    }

    do_lwip_init_sock(fd);

    struct lwip_sock *sock = get_socket(fd);
    if (sock == NULL || sock->stack == NULL) {
        do_lwip_close(fd);
        return -1;
    }

    return fd;
}

uint32_t do_lwip_get_conntable(struct gazelle_stat_lstack_conn_info *conn,
                               uint32_t max_num)
{
    struct tcp_pcb *pcb = NULL;
    uint32_t conn_num = 0;

    if (conn == NULL) {
        return -1;
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
        conn[conn_num].lip = *((gz_addr_t *)&pcbl->local_ip);
        conn[conn_num].l_port = pcbl->local_port;
        conn[conn_num].tcp_sub_state = pcbl->state;
        struct netconn *netconn = (struct netconn *)pcbl->callback_arg;
        conn[conn_num].fd = netconn != NULL ? netconn->socket : -1;
        if (netconn != NULL && netconn->acceptmbox != NULL) {
            conn[conn_num].recv_cnt = rte_ring_count(netconn->acceptmbox->ring);
        }
        conn_num++;
    }

    return conn_num;
}

uint32_t do_lwip_get_connnum(void)
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

void netif_poll(struct netif *netif)
{
    struct tcp_pcb *pcb = NULL;
    struct tcp_pcb_listen *pcbl = NULL;

    for (pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
#define NETIF_POLL_READ_COUNT 32
        struct pbuf *pbufs[NETIF_POLL_READ_COUNT];
        int ret;

        if (pcb->client_rx_ring != NULL) {
            ret = rte_ring_sc_dequeue_burst(pcb->client_rx_ring, (void **)pbufs, NETIF_POLL_READ_COUNT, NULL);
            for (int i = 0; i < ret; i++) {
                if (ip_input(pbufs[i], netif) != 0) {
                    LSTACK_LOG(INFO, LSTACK, "ip_input return err\n");
                    pbuf_free(pbufs[i]);
                }
            }
        }
    }
    for (pcbl = tcp_listen_pcbs.listen_pcbs; pcbl != NULL; pcbl = pcbl->next) {
        if (pcbl->listen_rx_ring != NULL) {
            struct pbuf *pbuf;
            if (rte_ring_sc_dequeue(pcbl->listen_rx_ring, (void **)&pbuf)  == 0) {
                if (ip_input(pbuf, netif) != ERR_OK) {
                    pbuf_free(pbuf);
                }
            }
        }
    }
}

/* processes on same node handshake packet use this function */
err_t netif_loop_output(struct netif *netif, struct pbuf *p)
{
    struct tcp_pcb *pcb = p->pcb;
    struct pbuf *head = NULL;

    if (pcb == NULL || pcb->client_tx_ring == NULL) {
        LSTACK_LOG(ERR, LSTACK, "pcb is null\n");
        return ERR_ARG;
    }

    if (p->next != NULL) {
        LSTACK_LOG(ERR, LSTACK, "netif_loop_output: not support chained pbuf\n");
        return ERR_ARG;
    }

    struct tcp_hdr *tcp_hdr = (struct tcp_hdr *)((char *)p->payload + sizeof(struct ip_hdr));
    uint8_t flags = TCPH_FLAGS(tcp_hdr);

    head = pbuf_alloc(0, p->len, PBUF_RAM);
    if (head == NULL) {
        LSTACK_LOG(ERR, LSTACK, "netif_loop_output: pbuf_alloc failed\n");
        return ERR_MEM;
    }
    head->ol_flags = p->ol_flags;
    memcpy_s(head->payload, head->len, p->payload, p->len);

    if ((flags & TCP_SYN) && !(flags & TCP_ACK)) {
        /* SYN packet, send to listen_ring */
        char ring_name[RING_NAME_LEN] = {0};
        snprintf_s(ring_name, sizeof(ring_name), sizeof(ring_name) - 1, "listen_rx_ring_%d", pcb->remote_port);
        struct rte_ring *ring = rte_ring_lookup(ring_name);
        if (ring == NULL) {
            LSTACK_LOG(INFO, LSTACK, "netif_loop_output: cant find listen_rx_ring %d\n", pcb->remote_port);
            pbuf_free(head);
        } else {
            if (rte_ring_mp_enqueue(ring, head) != 0) {
                LSTACK_LOG(INFO, LSTACK, "enqueue sync packet failed\n");
                pbuf_free(head);
            }
        }
    } else {
        /* send other type packet to tx_ring */
        if (rte_ring_sp_enqueue(pcb->client_tx_ring, head) != 0) {
            LSTACK_LOG(INFO, LSTACK, "client tx ring full\n");
            pbuf_free(head);
        }
    }

    return ERR_OK;
}

err_t find_same_node_memzone(struct tcp_pcb *pcb, struct lwip_sock *nsock)
{
    char name[RING_NAME_LEN];
    snprintf_s(name, sizeof(name), sizeof(name) - 1, "rte_mz_rx_%u", pcb->remote_port);
    if ((nsock->same_node_tx_ring_mz = rte_memzone_lookup(name)) == NULL) {
        LSTACK_LOG(INFO, LSTACK, "lwip_accept: can't find %s\n",name);
        return -1;
    } else {
        LSTACK_LOG(INFO, LSTACK, "lookup %s success\n", name);
    }
    nsock->same_node_tx_ring = (struct same_node_ring *)nsock->same_node_tx_ring_mz->addr;

    snprintf_s(name, sizeof(name), sizeof(name) - 1, "rte_mz_buf_rx_%u", pcb->remote_port);
    if ((nsock->same_node_tx_ring->mz = rte_memzone_lookup(name)) == NULL) {
        LSTACK_LOG(INFO, LSTACK, "lwip_accept: can't find %s\n",name);
        return -1;
    }

    snprintf_s(name, sizeof(name), sizeof(name) - 1, "rte_mz_tx_%u", pcb->remote_port);
    if ((nsock->same_node_rx_ring_mz = rte_memzone_lookup(name)) == NULL) {
        LSTACK_LOG(INFO, LSTACK, "lwip_accept: can't find %s\n",name);
        return -1;
    } else {
        LSTACK_LOG(INFO, LSTACK, "lookup %s success\n", name);
    }
    nsock->same_node_rx_ring = (struct same_node_ring *)nsock->same_node_rx_ring_mz->addr;

    snprintf_s(name, sizeof(name), sizeof(name) - 1,"rte_mz_buf_tx_%u", pcb->remote_port);
    if ((nsock->same_node_rx_ring->mz = rte_memzone_lookup(name)) == NULL) {
        LSTACK_LOG(INFO, LSTACK, "lwip_accept: can't find %s\n",name);
        return -1;
    }

    /* rcvlink init in alloc_socket() */
    /* remove from g_rcv_process_list in free_socket */
    list_add_node(&nsock->stack->same_node_recv_list, &nsock->recv_list);
    return 0;
}

err_t same_node_memzone_create(const struct rte_memzone **zone, int size, int port, char *name, char *rx)
{
    char mem_name[RING_NAME_LEN] = {0};
    snprintf_s(mem_name, sizeof(mem_name), sizeof(mem_name) - 1, "%s_%s_%d", name, rx, port);

    *zone = rte_memzone_reserve_aligned(mem_name, size, rte_socket_id(), 0, RTE_CACHE_LINE_SIZE);
    if (*zone == NULL) {
        LSTACK_LOG(ERR, LSTACK, "cannot reserve memzone:%s, errno is %d\n", mem_name, rte_errno);
        return ERR_MEM;
    }

    LSTACK_LOG(INFO, LSTACK, "lstack id %d, reserve %s(%p) success, addr is %p, size is %u\n",
        rte_socket_id(), mem_name, *zone, (*zone)->addr, size);

    return ERR_OK;
}

err_t same_node_ring_create(struct rte_ring **ring, int size, int port, char *name, char *rx)
{
    if (!get_global_cfg_params()->use_sockmap) {
        *ring = NULL;
        return -1;
    }

    unsigned flags;
    char ring_name[RING_NAME_LEN] = {0};
    if (strcmp(name, "listen") == 0) {
        flags = RING_F_SC_DEQ;
    } else {
        flags = RING_F_SP_ENQ | RING_F_SC_DEQ;
    }

    snprintf_s(ring_name, sizeof(ring_name), sizeof(ring_name) - 1, "%s_%s_ring_%d", name, rx, port);
    *ring = rte_ring_create(ring_name, size, rte_socket_id(), flags);
    if (*ring == NULL) {
        LSTACK_LOG(ERR, LSTACK, "cannot create rte_ring %s, errno is %d\n", ring_name, rte_errno);
        return ERR_MEM;
    }
    LSTACK_LOG(INFO, LSTACK, "lstack socket id:%d, create %s(%p) success\n", rte_socket_id(), ring_name, *ring);
    return ERR_OK;
}

static void init_same_node_ring(struct tcp_pcb *pcb)
{
    struct netconn *netconn = (struct netconn *)pcb->callback_arg;
    struct lwip_sock *sock = get_socket(netconn->socket);

    pcb->client_rx_ring = NULL;
    pcb->client_tx_ring = NULL;
    pcb->free_ring = 0;
    sock->same_node_rx_ring = NULL;
    sock->same_node_rx_ring_mz = NULL;
    sock->same_node_tx_ring = NULL;
    sock->same_node_tx_ring_mz = NULL;
}

#define CLIENT_RING_SIZE 512
err_t create_same_node_ring(struct tcp_pcb *pcb)
{
    struct netconn *netconn = (struct netconn *)pcb->callback_arg;
    struct lwip_sock *sock = get_socket(netconn->socket);

    if (same_node_ring_create(&pcb->client_rx_ring, CLIENT_RING_SIZE, pcb->local_port, "client", "rx") != 0) {
        goto END;
    }
    if (same_node_ring_create(&pcb->client_tx_ring, CLIENT_RING_SIZE, pcb->local_port, "client", "tx") != 0) {
        goto END;
    }
    pcb->free_ring = 1;

    if (same_node_memzone_create(&sock->same_node_rx_ring_mz, sizeof(struct same_node_ring),
        pcb->local_port, "rte_mz", "rx") != 0) {
        goto END;
    }
    sock->same_node_rx_ring = (struct same_node_ring*)sock->same_node_rx_ring_mz->addr;

    if (same_node_memzone_create(&sock->same_node_rx_ring->mz, SAME_NODE_RING_LEN,
        pcb->local_port, "rte_mz_buf", "rx") != 0) {
        goto END;
    }

    sock->same_node_rx_ring->sndbegin = 0;
    sock->same_node_rx_ring->sndend = 0;

    if (same_node_memzone_create(&sock->same_node_tx_ring_mz, sizeof(struct same_node_ring),
        pcb->local_port, "rte_mz", "tx") != 0) {
        goto END;
    }
    sock->same_node_tx_ring = (struct same_node_ring*)sock->same_node_tx_ring_mz->addr;

    if (same_node_memzone_create(&sock->same_node_tx_ring->mz, SAME_NODE_RING_LEN,
        pcb->local_port, "rte_mz_buf", "tx") != 0) {
        goto END;
    }

    sock->same_node_tx_ring->sndbegin = 0;
    sock->same_node_tx_ring->sndend = 0;

    return 0;
END:
    rte_ring_free(pcb->client_rx_ring);
    rte_ring_free(pcb->client_tx_ring);
    rte_memzone_free(sock->same_node_rx_ring->mz);
    rte_memzone_free(sock->same_node_rx_ring_mz);
    rte_memzone_free(sock->same_node_tx_ring->mz);
    rte_memzone_free(sock->same_node_tx_ring_mz);
    init_same_node_ring(pcb);
    return ERR_BUF;
}

err_t find_same_node_ring(struct tcp_pcb *npcb)
{
    char name[RING_NAME_LEN] = {0};
    snprintf_s(name, sizeof(name), sizeof(name) - 1, "client_tx_ring_%u", npcb->remote_port);
    npcb->client_rx_ring = rte_ring_lookup(name);
    memset_s(name, sizeof(name), 0, sizeof(name));
    snprintf_s(name, sizeof(name), sizeof(name) - 1, "client_rx_ring_%u", npcb->remote_port);
    npcb->client_tx_ring = rte_ring_lookup(name);
    npcb->free_ring = 0;
    if (npcb->client_tx_ring == NULL ||
        npcb->client_rx_ring == NULL) {
        LSTACK_LOG(INFO, LSTACK, "lookup client rxtx ring failed, port is %d\n", npcb->remote_port);
        tcp_abandon(npcb, 0);
        return ERR_CONN;
    } else {
        LSTACK_LOG(INFO, LSTACK, "find client_tx_ring_%u and client_rx_ring_%u\n",
            npcb->remote_port, npcb->remote_port);
    }
    return 0;
}
