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

#include <rte_ethdev.h>
#include <rte_malloc.h>

#include <lwip/debug.h>
#include <lwip/etharp.h>
#include <netif/ethernet.h>

#include <securec.h>

#include "lstack_cfg.h"
#include "lstack_vdev.h"
#include "lstack_stack_stat.h"
#include "lstack_log.h"
#include "lstack_dpdk.h"
#include "lstack_lwip.h"
#include "lstack_ethdev.h"

#define PKTMBUF_MALLOC_FLAG     NULL

void eth_dev_recv(struct rte_mbuf *mbuf)
{
    int32_t ret;
    void *payload = NULL;
    struct pbuf *next = NULL;
    struct pbuf *prev = NULL;
    struct pbuf *head = NULL;
    struct pbuf_custom *pc = NULL;
    struct protocol_stack *stack = get_protocol_stack();
    struct rte_mbuf *m = mbuf;
    uint16_t len;

    while (m != NULL) {
        len = (uint16_t)rte_pktmbuf_pkt_len(m);
        payload = rte_pktmbuf_mtod(m, void *);
        pc = mbuf_to_pbuf(m);
        pc->custom_free_function = gazelle_free_pbuf;
        next = pbuf_alloced_custom(PBUF_RAW, (uint16_t)len, PBUF_RAM, pc, payload, (uint16_t)len);
        if (next == NULL) {
            stack->stats.rx_allocmbuf_fail++;
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

    if (get_protocol_stack_group()->latency_start) {
        uint64_t time_stamp = get_current_time();
        time_stamp_into_mbuf(nr_pkts, pkts, time_stamp);
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
    struct protocol_stack *stack = get_protocol_stack();
    struct rte_mbuf *mbuf = pbuf_to_mbuf(pbuf);

    if (mbuf->buf_addr == 0) {
        stack->stats.tx_drop++;
        return ERR_BUF;
    }

    mbuf->data_len = pbuf->len;
    mbuf->pkt_len = pbuf->tot_len;
    rte_mbuf_refcnt_update(mbuf, 1);
#if CHECKSUM_GEN_IP_HW || CHECKSUM_GEN_TCP_HW
    mbuf->ol_flags = pbuf->ol_flags;
    mbuf->l2_len = pbuf->l2_len;
    mbuf->l3_len = pbuf->l3_len;
#endif

    uint32_t sent_pkts = stack->dev_ops->tx_xmit(stack, &mbuf, 1);
    stack->stats.tx += sent_pkts;
    if (sent_pkts < 1) {
        stack->stats.tx_drop++;
        rte_pktmbuf_free(mbuf);
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
