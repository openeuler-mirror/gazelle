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

#include <rte_eal.h>
#include <rte_version.h>
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
#include <rte_kni.h>
#endif
#include <rte_ethdev.h>

#include <lwip/etharp.h>
#include <lwip/ethip6.h>
#include <lwip/posix_api.h>
#include <netif/ethernet.h>

#include <securec.h>

#include "dpdk_common.h"
#include "lstack_cfg.h"
#include "lstack_vdev.h"
#include "lstack_stack_stat.h"
#include "lstack_log.h"
#include "lstack_dpdk.h"
#include "lstack_lwip.h"
#include "lstack_protocol_stack.h"
#include "lstack_thread_rpc.h"
#include "lstack_flow.h"
#include "lstack_ethdev.h"

/* FRAME_MTU + 14byte header */
#define MBUF_MAX_LEN                            1514
#define PACKET_READ_SIZE                        32

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
        next = pbuf_alloced_custom(PBUF_RAW, (uint16_t)len, PBUF_RAM, pc, payload, (uint16_t)len);
        if (next == NULL) {
            stack->stats.rx_allocmbuf_fail++;
            break;
        }
        next->tot_len = pkt_len;
        pkt_len -= len;

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

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
void kni_handle_rx(uint16_t port_id)
{
    struct rte_mbuf *pkts_burst[PACKET_READ_SIZE];
    struct rte_kni* kni = get_gazelle_kni();
    uint32_t nb_kni_rx = 0;
    if (kni) {
        nb_kni_rx = rte_kni_rx_burst(kni, pkts_burst, PACKET_READ_SIZE);
    }
    if (nb_kni_rx > 0) {
        uint16_t nb_rx = rte_eth_tx_burst(port_id, 0, pkts_burst, nb_kni_rx);
        for (uint16_t i = nb_rx; i < nb_kni_rx; ++i) {
            rte_pktmbuf_free(pkts_burst[i]);
        }
    }
    return;
}

void kni_handle_tx(struct rte_mbuf *mbuf)
{
    if (!get_global_cfg_params()->kni_switch ||
        !get_kni_started()) {
        rte_pktmbuf_free(mbuf);
        return;
    }
    struct rte_ipv4_hdr *ipv4_hdr;
    uint16_t l3_offset = mbuf->l2_len;

    ipv4_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(mbuf, char*) +
                l3_offset);
    if (mbuf->nb_segs > 1) {
        ipv4_hdr->hdr_checksum = 0;
        ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
    }

    if (!rte_kni_tx_burst(get_gazelle_kni(), &mbuf, 1)) {
        rte_pktmbuf_free(mbuf);
    }
}
#endif

int32_t eth_dev_poll(void)
{
    uint32_t nr_pkts;
    struct cfg_params *cfg = get_global_cfg_params();
    struct protocol_stack *stack = get_protocol_stack();

    nr_pkts = stack->dev_ops.rx_poll(stack, stack->pkts, cfg->nic_read_number);
    if (nr_pkts == 0) {
        return 0;
    }

    if (!use_ltran() && get_protocol_stack_group()->latency_start) {
        uint64_t time_stamp = get_current_time();
        time_stamp_into_mbuf(nr_pkts, stack->pkts, time_stamp);
    }

    for (uint32_t i = 0; i < nr_pkts; i++) {
        /* 1 current thread recv; 0 other thread recv; -1 kni recv; */
        int transfer_type = TRANSFER_CURRENT_THREAD;
        /* copy arp into other stack */
        if (!use_ltran()) {
            struct rte_ether_hdr *ethh = rte_pktmbuf_mtod(stack->pkts[i], struct rte_ether_hdr *);
            u16_t type;
            type = ethh->ether_type;
            if (type == PP_HTONS(ETHTYPE_VLAN)) {
                struct eth_vlan_hdr *vlan = (struct eth_vlan_hdr *)(((char *)ethh) + SIZEOF_ETH_HDR);
                type = vlan->tpid;
            }
            if (unlikely(RTE_BE16(RTE_ETHER_TYPE_ARP) == type)) {
                stack_broadcast_arp(stack->pkts[i], stack);
                /* copy arp into other process */
                transfer_arp_to_other_process(stack->pkts[i]);
            } else {
                if (get_global_cfg_params()->tuple_filter && stack->queue_id == 0) {
                    transfer_type = distribute_pakages(stack->pkts[i]);
                }
            }
        }

        if (likely(transfer_type == TRANSFER_CURRENT_THREAD)) {
            eth_dev_recv(stack->pkts[i], stack);
        } else if (transfer_type == TRANSFER_KERNEL) {
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
            kni_handle_tx(stack->pkts[i]);
#endif
        } else {
            /* transfer to other thread */
        }
    }

    stack->stats.rx += nr_pkts;

    return nr_pkts;
}

static err_t eth_dev_output(struct netif *netif, struct pbuf *pbuf)
{
    struct protocol_stack *stack = get_protocol_stack();
    struct rte_mbuf *pre_mbuf = NULL;
    struct rte_mbuf *first_mbuf = NULL;
    void *buf_addr;

    while (likely(pbuf != NULL)) {
        struct rte_mbuf *mbuf = pbuf_to_mbuf(pbuf);

        mbuf->data_len = pbuf->len;
        mbuf->pkt_len = pbuf->tot_len;
        mbuf->next = NULL;
        buf_addr = rte_pktmbuf_mtod(mbuf, void *);

        /*
         * |rte_mbuf | mbuf_private | data_off | data |
         *                          ^          ^
         *                       buf_addr    payload
         * m->buf_addr pointer pbuf->payload
         */
        mbuf->data_off += (uint8_t *)pbuf->payload - (uint8_t *)buf_addr;

        if (first_mbuf == NULL) {
            first_mbuf = mbuf;
            first_mbuf->nb_segs = 1;
        } else {
            first_mbuf->nb_segs++;
            pre_mbuf->next = mbuf;
        }

        if (likely(first_mbuf->pkt_len > MBUF_MAX_LEN)) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
            mbuf->tso_segsz = MBUF_MAX_DATA_LEN;
        }

        pre_mbuf = mbuf;
        rte_mbuf_refcnt_update(mbuf, 1);
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
    netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP | NETIF_FLAG_MLD6;
    netif->mtu = FRAME_MTU;
    netif->output = etharp_output;
    netif->linkoutput = eth_dev_output;
    netif->output_ip6 = ethip6_output;

    int32_t ret;
    ret = memcpy_s(netif->hwaddr, sizeof(netif->hwaddr), cfg->mac_addr, ETHER_ADDR_LEN);
    if (ret != EOK) {
        LSTACK_LOG(ERR, LSTACK, "memcpy_s fail ret=%d\n", ret);
        return ERR_MEM;
    }

    netif->hwaddr_len = ETHER_ADDR_LEN;

    netif_set_rxol_flags(netif, get_protocol_stack_group()->rx_offload);
    netif_set_txol_flags(netif, get_protocol_stack_group()->tx_offload);
    if (get_global_cfg_params()->stack_mode_rtc) {
        netif_set_rtc_mode(netif);
    }

    return ERR_OK;
}

int32_t ethdev_init(struct protocol_stack *stack)
{
    struct cfg_params *cfg = get_global_cfg_params();

    vdev_dev_ops_init(&stack->dev_ops);

    if (use_ltran()) {
        stack->rx_ring_used = 0;
        int32_t ret = fill_mbuf_to_ring(stack->rxtx_mbuf_pool, stack->rx_ring, RING_SIZE(VDEV_RX_QUEUE_SZ));
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "fill mbuf to rx_ring failed ret=%d\n", ret);
            return ret;
        }
    } else {
        if (cfg->tuple_filter && stack->queue_id == 0) {
            flow_init();
        }
    }

    netif_set_default(&stack->netif);

    struct netif *netif;
    if (!ip4_addr_isany(&cfg->host_addr)) {
        netif = netif_add(&stack->netif, &cfg->host_addr, &cfg->netmask,
            &cfg->gateway_addr, NULL, eth_dev_init, ethernet_input);
    } else {
        netif = netif_add(&stack->netif, NULL, NULL, NULL, NULL, eth_dev_init, ethernet_input);
    }
    if (netif == NULL) {
        LSTACK_LOG(ERR, LSTACK, "netif_add failed\n");
        return ERR_IF;
    }
    if (!ip6_addr_isany(&cfg->host_addr6)) {
        netif_ip6_addr_set(&stack->netif, 0, &cfg->host_addr6);
        netif_ip6_addr_set_state(&stack->netif, 0, IP6_ADDR_VALID);
    }
    
    /* 0-4094: The vlaue range for VLAN IDs is 0 to 4094. */
    if (get_global_cfg_params()->nic.vlan_mode >= 0 && get_global_cfg_params()->nic.vlan_mode <= 4094) {
        netif_set_vlan_tci(&stack->netif, (u16_t)get_global_cfg_params()->nic.vlan_mode);
    }

    netif_set_link_up(&stack->netif);

    netif_set_up(&stack->netif);

    return 0;
}
