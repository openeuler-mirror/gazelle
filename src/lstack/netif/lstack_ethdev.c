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

#ifdef USE_LIBOS_MEM
#include <rte_ethdev.h>
#include <rte_malloc.h>
#else
/* in dpdk 19.11 there is the following inclusion relationship
 * >> rte_ethdev.h
 * >> rte_eth_ctrl.h
 * >> rte_flow.h
 * >> rte_ip.h
 * >> netinet/ip.h
 * avoid conflicts with netinet/ip.h
 */
#include <lwip/inet.h>
#endif

#include <lwip/debug.h>
#include <lwip/etharp.h>
#include <netif/ethernet.h>

#include <securec.h>

#include "lstack_cfg.h"
#include "lstack_vdev.h"
#include "lstack_stack_stat.h"
#include "lstack_log.h"
#include "lstack_dpdk.h"
#include "lstack_ethdev.h"

#define PKTMBUF_MALLOC_FLAG     NULL

static inline void eth_mbuf_reclaim(struct rte_mbuf *mbuf)
{
    if (mbuf->pool != PKTMBUF_MALLOC_FLAG) {
        rte_pktmbuf_free(mbuf);
    } else {
        rte_free(mbuf);
    }
}

static void eth_pbuf_reclaim(struct pbuf *pbuf)
{
    if (get_protocol_stack_group()->latency_start) {
        calculate_lstack_latency(&get_protocol_stack()->latency, pbuf, GAZELLE_LATENCY_READ);
    }

    if (pbuf != NULL) {
        struct rte_mbuf *mbuf = pbuf_to_mbuf(pbuf);
        eth_mbuf_reclaim(mbuf);
    }
}

int32_t eth_mbuf_claim(struct rte_mempool *mp, struct rte_mbuf **mbufs, unsigned count)
{
    struct rte_mbuf *m = NULL;
    uint32_t i;

    // try alloc mbuf from mbufpoll
    if (rte_pktmbuf_alloc_bulk(mp, mbufs, count) == 0) {
        return 0;
    }

    // try alloc mbuf from system
    for (i = 0; i < count; i++) {
        // elt_size == sizeof(struct pbuf_custom) + GAZELLE_MBUFF_PRIV_SIZE + MBUF_SZ
        m = (struct rte_mbuf *)rte_malloc(NULL, mp->elt_size, sizeof(uint64_t));
        if (m == NULL) {
            LSTACK_LOG(ERR, LSTACK, "vdev failed to malloc mbuf\n");
            break;
        }
        // init mbuf
        mbufs[i] = m;
        rte_pktmbuf_init(mp, NULL, m, 0);
        rte_pktmbuf_reset(m);
        m->pool = PKTMBUF_MALLOC_FLAG;
    }

    if (unlikely(i != count)) {
        for (uint32_t j = 0; j < i; j++) {
            rte_free(mbufs[j]);
            mbufs[j] = NULL;
        }
        return -1;
    }

    return 0;
}

void eth_dev_recv(struct rte_mbuf *mbuf)
{
    int32_t ret;
    void *payload = NULL;
    struct pbuf *next = NULL, *prev = NULL, *head = NULL;
    struct pbuf_custom *pc = NULL;
    struct protocol_stack *stack = get_protocol_stack();
    struct rte_mbuf *m = mbuf;
    uint16_t len;

    while (m != NULL) {
        len = (uint16_t)rte_pktmbuf_pkt_len(m);
        payload = rte_pktmbuf_mtod(m, void *);

        pc = mbuf_to_pbuf(m);
        pc->custom_free_function = eth_pbuf_reclaim;

        next = pbuf_alloced_custom(PBUF_RAW, (uint16_t)len, PBUF_RAM, pc, payload, (uint16_t)len);
        if (next == NULL) {
            stack->stats.rx_drop++;
            LSTACK_LOG(ERR, LSTACK, "eth_dev_recv: failed to allocate pbuf!\n");
            break;
        }

        if (head == NULL) {
            head = next;
        }
        if (prev != NULL) {
            prev->next = next;
        }
        prev = next;

        m = m->next;
    }

    if (head != NULL) {
        ret = stack->netif.input(head, &stack->netif);
        if (ret != ERR_OK) {
            LSTACK_LOG(ERR, LSTACK, "eth_dev_recv: failed to handle rx pbuf ret=%d\n", ret);
            stack->stats.rx_drop++;
            pbuf_free(head);
        }
    }
}

int32_t eth_dev_poll(void)
{
    uint32_t nr_pkts;
    struct rte_mbuf *pkts[DPDK_PKT_BURST_SIZE];
    struct protocol_stack *stack = get_protocol_stack();

    nr_pkts = stack->dev_ops->rx_poll(stack, pkts, DPDK_PKT_BURST_SIZE);
    if (nr_pkts == 0) {
        return nr_pkts;
    }

    for (uint32_t i = 0; i < nr_pkts; i++) {
        /* copy arp into other stack */
        if (!use_ltran()) {
            struct rte_ether_hdr *ethh = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
            if (unlikely(RTE_BE16(RTE_ETHER_TYPE_ARP) == ethh->ether_type)) {
                stack_broadcast_arp(pkts[i], stack);
            }
        }

        eth_dev_recv(pkts[i]);
    }

    stack->stats.rx += nr_pkts;

    return nr_pkts;
}

uint32_t eth_get_flow_cnt(void)
{
    if (use_ltran()) {
        return rte_ring_count(get_protocol_stack()->rx_ring) + rte_ring_count(get_protocol_stack()->tx_ring);
    } else {
        /* can't get flow cnt, lstack_low_power_idling don't use this params */
        return LSTACK_LPM_RX_PKTS + 1;
    }
}

static err_t eth_dev_output(struct netif *netif, struct pbuf *pbuf)
{
    uint8_t *data = NULL;
    int32_t ret;
    uint32_t sent_pkts;
    struct rte_mbuf *mbufs[DPDK_PKT_BURST_SIZE];
    uint16_t total_len = pbuf->tot_len;
    struct pbuf *head = pbuf;
    struct protocol_stack *stack = get_protocol_stack();

    ret = rte_pktmbuf_alloc_bulk(stack->tx_pktmbuf_pool, &mbufs[0], 1);
    if (ret != 0) {
        stack->stats.tx_drop++;
        stack->stats.tx_allocmbuf_fail++;
        LSTACK_LOG(ERR, LSTACK, "cannot alloc mbuf for output ret=%d\n", ret);
        return ERR_MEM;
    }

    data = (uint8_t *)rte_pktmbuf_append(mbufs[0], total_len);
    if (data == NULL) {
        stack->stats.tx_drop++;
        stack->stats.tx_allocmbuf_fail++;
        LSTACK_LOG(ERR, LSTACK, "eth_dev_output: append mbuf failed!\n");
        rte_pktmbuf_free(mbufs[0]);
        return ERR_MEM;
    }

    for (; head != NULL; head = head->next) {
        rte_memcpy(data, head->payload, head->len);
        data += head->len;
    }

    sent_pkts = stack->dev_ops->tx_xmit(stack, mbufs, 1);
    stack->stats.tx += sent_pkts;
    if (sent_pkts < 1) {
        stack->stats.tx_drop++;
        rte_pktmbuf_free(mbufs[0]);
        mbufs[0] = NULL;
        return ERR_MEM;
    }

    return ERR_OK;
}

static err_t eth_dev_input(struct pbuf *p, struct netif *netif)
{
    err_t ret = ethernet_input(p, netif);
    if (ret != ERR_OK) {
        return ret;
    }

    if (get_protocol_stack_group()->latency_start) {
        calculate_lstack_latency(&get_protocol_stack()->latency, p, GAZELLE_LATENCY_LWIP);
    }
    return ret;
}

static err_t eth_dev_init(struct netif *netif)
{
    struct cfg_params *cfg = get_global_cfg_params();

    netif->name[0] = 'e';
    netif->name[1] = 't';
    netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;
    netif->mtu = FRAME_MTU;
    netif->output = etharp_output;
    netif->linkoutput = eth_dev_output;

    int32_t ret;
    ret = memcpy_s(netif->hwaddr, sizeof(netif->hwaddr), cfg->ethdev.addr_bytes, RTE_ETHER_ADDR_LEN);
    if (ret != EOK) {
        LSTACK_LOG(ERR, LSTACK, "memcpy_s fail ret=%d\n", ret);
        return ERR_MEM;
    }

    netif->hwaddr_len = RTE_ETHER_ADDR_LEN;

    return ERR_OK;
}

int32_t ethdev_init(struct protocol_stack *stack)
{
    struct cfg_params *cfg = get_global_cfg_params();

    vdev_dev_ops_init(&stack->dev_ops);

    if (use_ltran()) {
        stack->rx_ring_used = 0;
        int32_t ret = fill_mbuf_to_ring(stack->rx_pktmbuf_pool, stack->rx_ring, VDEV_RX_QUEUE_SZ - 1);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "fill mbuf to rx_ring failed ret=%d\n", ret);
            return ret;
        }
    }

    netif_set_default(&stack->netif);

    struct netif *netif = netif_add(&stack->netif, &cfg->host_addr, &cfg->netmask, &cfg->gateway_addr, NULL,
        eth_dev_init, eth_dev_input);
    if (netif == NULL) {
        LSTACK_LOG(ERR, LSTACK, "netif_add failed\n");
        return ERR_IF;
    }

    netif_set_link_up(&stack->netif);

    netif_set_up(&stack->netif);

    return 0;
}
