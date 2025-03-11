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
#include <rte_errno.h>

#include <lwip/priv/tcp_priv.h>

#include "lstack_log.h"
#include "lstack_cfg.h"
#include "lstack_protocol_stack.h"
#include "lstack_stack_stat.h"
#include "same_node.h"
#include "lstack_epoll.h"
#include "lstack_lwip.h"

#if GAZELLE_SAME_NODE
void read_same_node_recv_list(struct protocol_stack *stack)
{
    struct list_node *list = &(stack->same_node_recv_list);
    struct list_node *node, *temp;
    struct lwip_sock *sock;

    list_for_each_node(node, temp, list) {
        sock = list_entry(node, struct lwip_sock, recv_list);

        if (sock->same_node_rx_ring != NULL && same_node_ring_count(sock)) {
            add_sock_event(sock, EPOLLIN);
        }
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
    if (!p) {
        return ERR_ARG;
    }
    const struct ip_hdr *iphdr;
    iphdr = (const struct ip_hdr *)p->payload;
    if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
        return udp_netif_loop_output(netif, p);
    }

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
    list_add_node(&nsock->recv_list, &nsock->stack->same_node_recv_list);
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
    struct lwip_sock *sock = lwip_get_socket(netconn->callback_arg.socket);

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
    struct lwip_sock *sock = lwip_get_socket(netconn->callback_arg.socket);

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

unsigned same_node_ring_count(const struct lwip_sock *sock)
{
  const unsigned long long cur_begin = __atomic_load_n(&sock->same_node_rx_ring->sndbegin, __ATOMIC_RELAXED);
  const unsigned long long cur_end = __atomic_load_n(&sock->same_node_rx_ring->sndend, __ATOMIC_RELAXED);

  return cur_end - cur_begin;
}
#endif /* GAZELLE_SAME_NODE */
