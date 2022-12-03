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
#include "dpdk_common.h"
#include "lstack_protocol_stack.h"
#include "lstack_ethdev.h"

/* FRAME_MTU + 14byte header */
#define MBUF_MAX_LEN    1514

void eth_dev_recv(struct rte_mbuf *mbuf, struct protocol_stack *stack)
{
    int32_t ret;
    void *payload = NULL;
    struct pbuf *next = NULL;
    struct pbuf *prev = NULL;
    struct pbuf *head = NULL;
    struct pbuf_custom *pc = NULL;
    struct rte_mbuf *m = mbuf;
    uint16_t len, pkt_len;
    struct rte_mbuf *next_m = NULL;

    pkt_len = (uint16_t)rte_pktmbuf_pkt_len(m);
    while (m != NULL) {
        len = (uint16_t)rte_pktmbuf_data_len(m);
        payload = rte_pktmbuf_mtod(m, void *);
        pc = mbuf_to_pbuf(m);
        pc->custom_free_function = gazelle_free_pbuf;
        next = pbuf_alloced_custom(PBUF_RAW, (uint16_t)len, PBUF_RAM, pc, payload, (uint16_t)len);
        if (next == NULL) {
            stack->stats.rx_allocmbuf_fail++;
            break;
        }
        next->tot_len = pkt_len;
#if CHECKSUM_CHECK_IP_HW || CHECKSUM_CHECK_TCP_HW
        next->ol_flags = m->ol_flags;
#endif

        if (head == NULL) {
            head = next;
        }
        if (prev != NULL) {
            prev->next = next;
        }
        prev = next;

        next_m = m->next;
        m->next = NULL;
        m = next_m;
    }

    if (head != NULL) {
        ret = stack->netif.input(head, &stack->netif);
        if (ret != ERR_OK) {
            LSTACK_LOG(ERR, LSTACK, "eth_dev_recv: failed to handle rx pbuf ret=%d\n", ret);
            stack->stats.rx_drop++;
        }
    }
}

#define READ_PKTS_MAX   32
int32_t eth_dev_poll(void)
{
    uint32_t nr_pkts;
    struct rte_mbuf *pkts[READ_PKTS_MAX];
    struct protocol_stack *stack = get_protocol_stack();

    nr_pkts = stack->dev_ops.rx_poll(stack, pkts, READ_PKTS_MAX);
    if (nr_pkts == 0) {
        return 0;
    }

    if (!use_ltran() && get_protocol_stack_group()->latency_start) {
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

        eth_dev_recv(pkts[i], stack);
    }

    stack->stats.rx += nr_pkts;

    return nr_pkts;
}

/* optimized eth_dev_poll() in lstack */
int32_t gazelle_eth_dev_poll(struct protocol_stack *stack, bool use_ltran_flag)
{
    uint32_t nr_pkts;
    struct rte_mbuf *pkts[READ_PKTS_MAX];

    nr_pkts = stack->dev_ops.rx_poll(stack, pkts, READ_PKTS_MAX);
    if (nr_pkts == 0) {
        return 0;
    }

    if (!use_ltran_flag && get_protocol_stack_group()->latency_start) {
        uint64_t time_stamp = get_current_time();
        time_stamp_into_mbuf(nr_pkts, pkts, time_stamp);
    }

    for (uint32_t i = 0; i < nr_pkts; i++) {
        /* copy arp into other stack */
        if (!use_ltran_flag) {
            struct rte_ether_hdr *ethh = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
            if (unlikely(RTE_BE16(RTE_ETHER_TYPE_ARP) == ethh->ether_type)) {
                stack_broadcast_arp(pkts[i], stack);
            }
        }

        eth_dev_recv(pkts[i], stack);
    }

    stack->stats.rx += nr_pkts;

    return nr_pkts;
}

static err_t eth_dev_output(struct netif *netif, struct pbuf *pbuf)
{
    struct protocol_stack *stack = get_protocol_stack();
    struct rte_mbuf *pre_mbuf = NULL;
    struct rte_mbuf *first_mbuf = NULL;
    struct pbuf *first_pbuf = NULL;

    while (likely(pbuf != NULL)) {
        struct rte_mbuf *mbuf = pbuf_to_mbuf(pbuf);

        mbuf->data_len = pbuf->len;
        mbuf->pkt_len = pbuf->tot_len;
        mbuf->ol_flags = pbuf->ol_flags;

        if (first_mbuf == NULL) {
            first_mbuf = mbuf;
            first_pbuf = pbuf;
            first_mbuf->nb_segs = 1;
            if (pbuf->header_off > 0) {
                mbuf->data_off -= first_pbuf->l2_len + first_pbuf->l3_len + first_pbuf->l4_len;
                pbuf->header_off = 0;
            }
        } else {
            first_mbuf->nb_segs++;
            pre_mbuf->next = mbuf;
            if (pbuf->header_off == 0) {
                uint16_t header_len = first_pbuf->l2_len + first_pbuf->l3_len + first_pbuf->l4_len;
                mbuf->data_off += header_len;
                pbuf->header_off = header_len;
            }
        }

        if (likely(first_mbuf->pkt_len > MBUF_MAX_LEN)) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
            mbuf->tso_segsz = TCP_MSS;
        }
        mbuf->l2_len = first_pbuf->l2_len;
        mbuf->l3_len = first_pbuf->l3_len;
        mbuf->l4_len = first_pbuf->l4_len;

        pre_mbuf = mbuf;
        rte_mbuf_refcnt_update(mbuf, 1);
        if (pbuf->rexmit) {
            mbuf->next = NULL;
            break;
        }
        pbuf->rexmit = 1;
        pbuf = pbuf->next;
    }

    uint32_t sent_pkts = stack->dev_ops.tx_xmit(stack, &first_mbuf, 1);
    stack->stats.tx += sent_pkts;
    if (sent_pkts < 1) {
        stack->stats.tx_drop++;
        rte_pktmbuf_free(first_mbuf);
        return ERR_MEM;
    }

    return ERR_OK;
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
    ret = memcpy_s(netif->hwaddr, sizeof(netif->hwaddr), cfg->mac_addr, ETHER_ADDR_LEN);
    if (ret != EOK) {
        LSTACK_LOG(ERR, LSTACK, "memcpy_s fail ret=%d\n", ret);
        return ERR_MEM;
    }

    netif->hwaddr_len = ETHER_ADDR_LEN;

    return ERR_OK;
}

int32_t ethdev_init(struct protocol_stack *stack)
{
    struct cfg_params *cfg = get_global_cfg_params();

    vdev_dev_ops_init(&stack->dev_ops);

    if (use_ltran()) {
        stack->rx_ring_used = 0;
        int32_t ret = fill_mbuf_to_ring(stack->rxtx_pktmbuf_pool, stack->rx_ring, RING_SIZE(VDEV_RX_QUEUE_SZ));
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "fill mbuf to rx_ring failed ret=%d\n", ret);
            return ret;
        }
    }

    netif_set_default(&stack->netif);

    struct netif *netif = netif_add(&stack->netif, &cfg->host_addr, &cfg->netmask, &cfg->gateway_addr, NULL,
        eth_dev_init, ethernet_input);
    if (netif == NULL) {
        LSTACK_LOG(ERR, LSTACK, "netif_add failed\n");
        return ERR_IF;
    }

    netif_set_link_up(&stack->netif);

    netif_set_up(&stack->netif);

    return 0;
}
