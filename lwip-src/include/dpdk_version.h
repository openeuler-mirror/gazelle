/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Huawei Technologies
 *
 */

#ifndef __DPDK_VERSION_H__
#define __DPDK_VERSION_H__

#include <rte_version.h>

#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
#define __rte_ring_enqueue_elems(r, prod_head, obj_table, esize, n) \
    ENQUEUE_PTRS(r, &r[1], prod_head, (obj_table), n, void *)

#define __rte_ring_dequeue_elems(r, cons_head, obj_table, esize, n) \
    DEQUEUE_PTRS(r, &r[1], cons_head, (obj_table), n, void *)

#define RTE_MBUF_F_RX_IP_CKSUM_BAD          PKT_RX_IP_CKSUM_BAD
#define RTE_MBUF_F_RX_L4_CKSUM_BAD          PKT_RX_L4_CKSUM_BAD
#define RTE_MBUF_F_TX_IPV4                  PKT_TX_IPV4
#define RTE_MBUF_F_TX_IPV6                  PKT_TX_IPV6
#define RTE_MBUF_F_TX_IP_CKSUM              PKT_TX_IP_CKSUM
#define RTE_MBUF_F_TX_TCP_CKSUM             PKT_TX_TCP_CKSUM
#define RTE_MBUF_F_TX_TCP_SEG               PKT_TX_TCP_SEG
#define RTE_MBUF_F_TX_UDP_CKSUM             PKT_TX_UDP_CKSUM
#define RTE_MBUF_F_TX_VLAN                  PKT_TX_VLAN_PKT

#define RTE_ETH_RX_OFFLOAD_TCP_CKSUM        DEV_RX_OFFLOAD_TCP_CKSUM
#define RTE_ETH_RX_OFFLOAD_UDP_CKSUM        DEV_RX_OFFLOAD_UDP_CKSUM
#define RTE_ETH_RX_OFFLOAD_IPV4_CKSUM       DEV_RX_OFFLOAD_IPV4_CKSUM
#define RTE_ETH_RX_OFFLOAD_VLAN_STRIP       DEV_RX_OFFLOAD_VLAN_STRIP
#define RTE_ETH_RX_OFFLOAD_VLAN_FILTER      DEV_RX_OFFLOAD_VLAN_FILTER

#define RTE_ETH_TX_OFFLOAD_IPV4_CKSUM       DEV_TX_OFFLOAD_IPV4_CKSUM
#define RTE_ETH_TX_OFFLOAD_VLAN_INSERT      DEV_TX_OFFLOAD_VLAN_INSERT
#define RTE_ETH_TX_OFFLOAD_TCP_TSO          DEV_TX_OFFLOAD_TCP_TSO
#define RTE_ETH_TX_OFFLOAD_TCP_CKSUM        DEV_TX_OFFLOAD_TCP_CKSUM
#define RTE_ETH_TX_OFFLOAD_UDP_CKSUM        DEV_TX_OFFLOAD_UDP_CKSUM
#define RTE_ETH_TX_OFFLOAD_MULTI_SEGS       DEV_TX_OFFLOAD_MULTI_SEGS

#define RTE_ETH_LINK_SPEED_AUTONEG          ETH_LINK_SPEED_AUTONEG

#define RTE_ETH_MQ_TX_NONE                  ETH_MQ_TX_NONE
#define RTE_ETH_MQ_RX_NONE                  ETH_MQ_RX_NONE
#define RTE_ETH_RSS_IP                      ETH_RSS_IP
#define RTE_ETH_RSS_TCP                     ETH_RSS_TCP
#define RTE_ETH_RSS_UDP                     ETH_RSS_UDP
#define RTE_ETH_MQ_RX_RSS                   ETH_MQ_RX_RSS
#define RTE_ETH_RETA_GROUP_SIZE             RTE_RETA_GROUP_SIZE

#endif /* RTE_VERSION */

#endif /* __DPDK_VERSION_H__ */
