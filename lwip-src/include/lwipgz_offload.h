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

#ifndef __LWIPGZ_OFFLOAD_H__
#define __LWIPGZ_OFFLOAD_H__

#include "lwipopts.h"

#if GAZELLE_ENABLE
#include <stdbool.h>
#include <rte_ethdev.h>
#include <rte_mbuf_core.h>
#include <rte_ip.h>

#include "dpdk_version.h"
#include "lwip/pbuf.h"

#define PBUF_TO_MBUF(p)  ((struct rte_mbuf *)RTE_PTR_SUB(p, sizeof(struct rte_mbuf)))

static inline void pbuf_offload_copy(struct pbuf *to, const struct pbuf *from)
{
    PBUF_TO_MBUF(to)->l4_len   = PBUF_TO_MBUF(from)->l4_len;
    PBUF_TO_MBUF(to)->l3_len   = PBUF_TO_MBUF(from)->l3_len;
    PBUF_TO_MBUF(to)->l2_len   = PBUF_TO_MBUF(from)->l2_len;
    PBUF_TO_MBUF(to)->ol_flags = PBUF_TO_MBUF(from)->ol_flags;
}

static inline void pbuf_set_vlan(struct pbuf *p, u16_t vlan_tci)
{
    PBUF_TO_MBUF(p)->ol_flags |= RTE_MBUF_F_TX_VLAN;
    PBUF_TO_MBUF(p)->vlan_tci = vlan_tci;
}

#if OFFLOAD_CHECKSUM_CHECK_IP
// replaces inet_chksum() for ip4_input
static inline u64_t ol_chksum_check_ip(struct pbuf *p)
{
    return PBUF_TO_MBUF(p)->ol_flags & (RTE_MBUF_F_RX_IP_CKSUM_BAD);
}
#endif /* OFFLOAD_CHECKSUM_CHECK_IP */

#if OFFLOAD_CHECKSUM_GEN_IP
static inline void ol_chksum_gen_eth(struct pbuf *p, u16_t len)
{
    PBUF_TO_MBUF(p)->l2_len = len;
}

// replaces inet_chksum() for ip4_output
static inline void ol_chksum_gen_ip(struct pbuf *p, u16_t len, bool do_ipcksum)
{
    PBUF_TO_MBUF(p)->ol_flags |= ((len == IP_HLEN) ? RTE_MBUF_F_TX_IPV4 : RTE_MBUF_F_TX_IPV6);
    if (do_ipcksum) {
        PBUF_TO_MBUF(p)->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
    }
    PBUF_TO_MBUF(p)->l3_len = len;
}
#endif /* OFFLOAD_CHECKSUM_GEN_IP */

#if OFFLOAD_CHECKSUM_CHECK_TCP || OFFLOAD_CHECKSUM_CHECK_UDP
// replace ip_chksum_pseudo() for tcp_input
static inline u64_t ol_chksum_check_l4(struct pbuf *p)
{
    return PBUF_TO_MBUF(p)->ol_flags & (RTE_MBUF_F_RX_L4_CKSUM_BAD);
}
#define ol_chksum_check_tcp ol_chksum_check_l4
#define ol_chksum_check_udp ol_chksum_check_l4
#endif

#if OFFLOAD_CHECKSUM_GEN_TCP
// replace ip_chksum_pseudo() for tcp_output
static inline void ol_chksum_gen_tcp(struct pbuf *p, u16_t len)
{
    PBUF_TO_MBUF(p)->l4_len = len;
    PBUF_TO_MBUF(p)->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
}
#endif /* OFFLOAD_CHECKSUM_GEN_TCP */

#if OFFLOAD_CHECKSUM_GEN_UDP
static inline void ol_chksum_gen_udp(struct pbuf *p, u16_t len)
{
    PBUF_TO_MBUF(p)->l4_len = len;
    PBUF_TO_MBUF(p)->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
}
#endif /* OFFLOAD_CHECKSUM_GEN_UDP */

#endif /* GAZELLE_ENABLE */
#endif /* __LWIPGZ_OFFLOAD_H__ */
