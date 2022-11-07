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
#include <lwip/memp.h>
#include <lwip/lwipopts.h>
#include <lwip/sys.h>
#include <lwip/reg_sock.h>
#include <rte_ring.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_gro.h>
#include <rte_net.h>

#include "lstack_cfg.h"
#include "lstack_dpdk.h"
#include "lstack_ethdev.h"
#include "lstack_control_plane.h"
#include "lstack_log.h"
#include "dpdk_common.h"
#include "lstack_protocol_stack.h"
#include "gazelle_reg_msg.h"
#include "lstack_lwip.h"
#include "lstack_vdev.h"

/* INUSE_TX_PKTS_WATERMARK < VDEV_RX_QUEUE_SZ;
 * USE_RX_PKTS_WATERMARK < FREE_RX_QUEUE_SZ.
 * less, means more available mbuf.
 * more, means less available mbuf.
 */
#define INUSE_TX_PKTS_WATERMARK         (VDEV_TX_QUEUE_SZ >> 2)
#define USED_RX_PKTS_WATERMARK          (FREE_RX_QUEUE_SZ >> 2)

static uint32_t ltran_rx_poll(struct protocol_stack *stack, struct rte_mbuf **pkts, uint32_t max_mbuf)
{
    uint32_t rcvd_pkts;
    uint32_t nr_pkts;
    struct rte_mbuf *free_buf[DPDK_PKT_BURST_SIZE];

    rcvd_pkts = gazelle_ring_sc_dequeue(stack->rx_ring, (void **)pkts, max_mbuf);

    stack->rx_ring_used += rcvd_pkts;
    if (unlikely(stack->rx_ring_used >= USED_RX_PKTS_WATERMARK)) {
        uint32_t free_cnt = LWIP_MIN(stack->rx_ring_used, RING_SIZE(DPDK_PKT_BURST_SIZE));
        int32_t ret = gazelle_alloc_pktmbuf(stack->rx_pktmbuf_pool, (struct rte_mbuf **)free_buf, free_cnt);
        if (likely(ret == 0)) {
            nr_pkts = gazelle_ring_sp_enqueue(stack->rx_ring, (void **)free_buf, free_cnt);
            stack->rx_ring_used -= nr_pkts;
        } else {
            stack->stats.rx_allocmbuf_fail++;
        }
    }

    return rcvd_pkts;
}

static uint32_t vdev_rx_poll(struct protocol_stack *stack, struct rte_mbuf **pkts, uint32_t max_mbuf)
{
    struct rte_gro_param gro_param = {
        .gro_types = RTE_GRO_TCP_IPV4,
        /* 8*16=128(max) */
        .max_flow_num = 8,
        .max_item_per_flow = 16,
    };

    uint32_t pkt_num = rte_eth_rx_burst(stack->port_id, stack->queue_id, pkts, max_mbuf);
    if (pkt_num <= 1) {
        return pkt_num;
    }

    for (uint32_t i = 0; i < pkt_num; i++) {
        struct rte_net_hdr_lens hdr_lens;
        pkts[i]->packet_type = rte_net_get_ptype(pkts[i], &hdr_lens, RTE_PTYPE_ALL_MASK);
        pkts[i]->l2_len = hdr_lens.l2_len;
        pkts[i]->l3_len = hdr_lens.l3_len;
        pkts[i]->l4_len = hdr_lens.l4_len;
    }
    return rte_gro_reassemble_burst(pkts, pkt_num, &gro_param);
}

static uint32_t ltran_tx_xmit(struct protocol_stack *stack, struct rte_mbuf **pkts, uint32_t nr_pkts)
{
    uint32_t sent_pkts = 0;
    struct rte_mbuf *free_buf[DPDK_PKT_BURST_SIZE];
    const uint32_t tbegin = sys_now();

    do {
        if (unlikely(stack->tx_ring_used >= INUSE_TX_PKTS_WATERMARK)) {
            uint32_t free_pkts = gazelle_ring_sc_dequeue(stack->tx_ring, (void **)free_buf, stack->tx_ring_used);
            for (uint32_t i = 0; i < free_pkts; i++) {
                rte_pktmbuf_free(free_buf[i]);
            }
            stack->tx_ring_used -= free_pkts;
        }

        sent_pkts += gazelle_ring_sp_enqueue(stack->tx_ring, (void **)(&pkts[sent_pkts]), nr_pkts - sent_pkts);
    } while ((sent_pkts < nr_pkts) && (ENQUEUE_RING_RETRY_TIMEOUT > sys_now() - tbegin) && get_register_state());

    stack->tx_ring_used += sent_pkts;
    return sent_pkts;
}

static uint32_t vdev_tx_xmit(struct protocol_stack *stack, struct rte_mbuf **pkts, uint32_t nr_pkts)
{
    uint32_t sent_pkts = 0;

    do {
        sent_pkts += rte_eth_tx_burst(stack->port_id, stack->queue_id, &pkts[sent_pkts], nr_pkts - sent_pkts);
    } while (sent_pkts < nr_pkts);

    return sent_pkts;
}

int32_t vdev_reg_xmit(enum reg_ring_type type, struct gazelle_quintuple *qtuple)
{
    if (!use_ltran()) {
        return 0;
    }

    if (qtuple == NULL) {
        return -1;
    }

    int32_t ret;
    uint32_t sent_pkts = 0;
    void *free_buf[VDEV_REG_QUEUE_SZ];
    struct reg_ring_msg *tmp_buf = NULL;
    const uint32_t tbegin = sys_now();
    struct protocol_stack *stack = get_protocol_stack();

    if (type == REG_RING_TCP_LISTEN || type == REG_RING_TCP_LISTEN_CLOSE) {
        if (!match_host_addr(qtuple->src_ip)) {
            LSTACK_LOG(INFO, LSTACK, "lstack ip not match in conf.\n");
            return 0;
        }
    }

    uint32_t reg_index = stack->reg_head++ & DEFAULT_RING_MASK;
    do {
        (void)gazelle_ring_sc_dequeue(stack->reg_ring, free_buf, VDEV_REG_QUEUE_SZ);

        if (gazelle_ring_free_count(stack->reg_ring) == 0) {
            continue;
        }

        tmp_buf = &stack->reg_buf[reg_index];
        tmp_buf->type = type;
        tmp_buf->tid = get_stack_tid();
        ret = memcpy_s(&tmp_buf->qtuple, sizeof(*qtuple), qtuple, sizeof(struct gazelle_quintuple));
        if (ret != EOK) {
            LSTACK_LOG(ERR, LSTACK, "memcpy_s failed ret=%d.\n", ret);
            return -1;
        }

        free_buf[0] = tmp_buf;
        sent_pkts = gazelle_ring_sp_enqueue(stack->reg_ring, free_buf, 1);
    } while ((sent_pkts < 1) && (ENQUEUE_RING_RETRY_TIMEOUT > sys_now() - tbegin) && get_register_state());

    return (int32_t)sent_pkts;
}

void vdev_dev_ops_init(struct lstack_dev_ops *dev_ops)
{
    if (use_ltran()) {
        dev_ops->rx_poll = ltran_rx_poll;
        dev_ops->tx_xmit = ltran_tx_xmit;
    } else {
        dev_ops->rx_poll = vdev_rx_poll;
        dev_ops->tx_xmit = vdev_tx_xmit;
    }
}
