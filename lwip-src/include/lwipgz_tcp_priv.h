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
 
#ifndef __GAZELLE_TCP_PRIV_H__
#define __GAZELLE_TCP_PRIV_H__

#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwipgz_hlist.h"

#define __TCP_REG(pcbs, npcb)                      \
  do {                                             \
    if (*pcbs)                                     \
      (*pcbs)->prev = npcb;                        \
    (npcb)->prev = NULL;                           \
    (npcb)->next = *pcbs;                          \
    *(pcbs) = (npcb);                              \
    tcp_timer_needed();                            \
  } while (0)

#define __TCP_RMV(pcbs, npcb)                      \
  do {                                             \
    if(*(pcbs) == (npcb)) {                        \
      *(pcbs) = (*pcbs)->next;                     \
      if (*pcbs)                                   \
        (*pcbs)->prev = NULL;                      \
    } else {                                       \
      struct tcp_pcb *prev, *next;                 \
      prev = npcb->prev;                           \
      next = npcb->next;                           \
      if (prev)                                    \
        prev->next = next;                         \
      if (next)                                    \
        next->prev = prev;                         \
    }                                              \
    (npcb)->prev = NULL;                           \
    (npcb)->next = NULL;                           \
  } while(0)

#if TCP_DEBUG_PCB_LISTS
#define TCP_REG(pcbs, npcb) do {\
                            struct tcp_pcb *tcp_tmp_pcb; \
                            LWIP_DEBUGF(TCP_DEBUG, ("TCP_REG %p local port %"U16_F"\n", (void *)(npcb), (npcb)->local_port)); \
                            for (tcp_tmp_pcb = *(pcbs); \
                              tcp_tmp_pcb != NULL; \
                              tcp_tmp_pcb = tcp_tmp_pcb->next) { \
                              LWIP_ASSERT("TCP_REG: already registered\n", tcp_tmp_pcb != (npcb)); \
                            } \
                            LWIP_ASSERT("TCP_REG: pcb->state != CLOSED", ((pcbs) == &tcp_bound_pcbs) || ((npcb)->state != CLOSED)); \
                            __TCP_REG(pcbs, npcb); \
                            LWIP_ASSERT("TCP_REG: tcp_pcbs sane", tcp_pcbs_sane()); \
                            } while(0)
#define TCP_RMV(pcbs, npcb) do { \
                            struct tcp_pcb *tcp_tmp_pcb; \
                            LWIP_ASSERT("TCP_RMV: pcbs != NULL", *(pcbs) != NULL); \
                            LWIP_DEBUGF(TCP_DEBUG, ("TCP_RMV: removing %p from %p\n", (void *)(npcb), (void *)(*(pcbs)))); \
                            __TCP_RMV(pcbs, npcb); \
                            LWIP_ASSERT("TCP_RMV: tcp_pcbs sane", tcp_pcbs_sane()); \
                            LWIP_DEBUGF(TCP_DEBUG, ("TCP_RMV: removed %p from %p\n", (void *)(npcb), (void *)(*(pcbs)))); \
                            } while(0)

#else /* LWIP_DEBUG */

#define TCP_REG(pcbs, npcb) __TCP_REG(pcbs, npcb)
#define TCP_RMV(pcbs, npcb) __TCP_RMV(pcbs, npcb)

#endif /* LWIP_DEBUG */

#if GAZELLE_TCP_PCB_HASH
struct tcp_hashbucket {
  sys_mutex_t mutex;
  struct hlist_head chain;
};
struct tcp_hash_table {
  u32_t size;
  struct tcp_hashbucket array[GAZELLE_TCP_ACTIVE_HTABLE_SIZE];
};
extern PER_THREAD struct tcp_hash_table *tcp_active_htable;

#include <rte_jhash.h>
static inline u32_t tcp_pcb_hash(ip_addr_t *local_ip, u16_t lport, ip_addr_t *remote_ip, u16_t rport)
{
  u32_t c = lport | (rport << 16);

#if LWIP_IPV6
  if (IP_IS_V6(local_ip)) {
    ip6_addr_t *lip6 = ip_2_ip6(local_ip);
    ip6_addr_t *rip6 = ip_2_ip6(remote_ip);
    for (int i = 0; i < 4; ++i) {
      c = rte_jhash_3words(lip6->addr[i], rip6->addr[i], c, 0);
    }
  } else
#endif /* LWIP_IPV6 */
  {
    ip4_addr_t *lip4 = ip_2_ip4(local_ip);
    ip4_addr_t *rip4 = ip_2_ip4(remote_ip);
    c = rte_jhash_3words(lip4->addr, rip4->addr, c, 0);
  }

  return c;
}

#define TCP_REG_HASH(pcbs, npcb)                   \
  do {                                             \
    struct hlist_head *head;                       \
    struct tcp_hash_table *htb = pcbs;             \
    u32_t idx = tcp_pcb_hash(&((npcb)->local_ip), (npcb)->local_port, &((npcb)->remote_ip), (npcb)->remote_port); \
    idx &= (htb->size - 1);                        \
    head = &htb->array[idx].chain;                 \
    hlist_add_head(&(npcb)->tcp_node, head);       \
    tcp_timer_needed();                            \
  } while (0)

#define TCP_RMV_HASH(npcb)                         \
  do {                                             \
    hlist_del_node(&(npcb)->tcp_node);             \
  } while (0)

#define TCP_REG_ACTIVE_HASH(npcb)                  \
  do {                                             \
    TCP_REG_HASH(tcp_active_htable, npcb);         \
    tcp_active_pcbs_changed = 1;                   \
  } while (0)

#define TCP_RMV_ACTIVE_HASH(npcb)                  \
  do {                                             \
    TCP_RMV_HASH(npcb);                            \
    tcp_active_pcbs_changed = 1;                   \
  } while (0)

#endif /* GAZELLE_TCP_PCB_HASH */

#if GAZELLE_TCP_REUSE_IPPORT
#define TCP_REG_SAMEPORT(first_pcb, lpcb)          \
  do {                                             \
    struct tcp_pcb_listen *tmp_pcb = first_pcb;    \
    while (tmp_pcb->next_same_port_pcb != NULL) {  \
      tmp_pcb = tmp_pcb->next_same_port_pcb;       \
    };                                             \
    tmp_pcb->next_same_port_pcb = lpcb;            \
    tcp_timer_needed();                            \
  } while (0)
#endif /* GAZELLE_TCP_REUSE_IPPORT */

#if GAZELLE_ENABLE
#include "lwipgz_flow.h"
static inline int vdev_reg_done(enum reg_ring_type reg_type, const struct tcp_pcb *pcb)
{
  LWIP_ASSERT("Invalid parameter", pcb != NULL);

  struct gazelle_quintuple qtuple = {0};

  qtuple.protocol   = IP_IS_V4_VAL(pcb->local_ip) ? GZ_ADDR_TYPE_V4 : GZ_ADDR_TYPE_V6;
  qtuple.src_ip     = *((gz_addr_t *)&pcb->local_ip);
  qtuple.src_port   = lwip_htons(pcb->local_port);
  qtuple.dst_ip     = *((gz_addr_t *)&pcb->remote_ip);
  qtuple.dst_port   = lwip_htons(pcb->remote_port);

#if GAZELLE_TCP_REUSE_IPPORT
  if (reg_type == REG_RING_TCP_CONNECT_CLOSE) {
    struct tcp_pcb_listen* lpcb = pcb->listener;
    if (lpcb != NULL) {
      lpcb->connect_num--;
    }
  }
#endif

  return vdev_reg_xmit(reg_type, &qtuple);
}
static inline void vdev_unreg_done(const struct tcp_pcb *pcb)
{
  if (pcb->local_port == 0) {
    return;
  }
  if (pcb->state == LISTEN) {
    vdev_reg_done(REG_RING_TCP_LISTEN_CLOSE, pcb);
  } else {
    vdev_reg_done(REG_RING_TCP_CONNECT_CLOSE, pcb);
  }
}

#if GAZELLE_TCP_PINGPONG_MODE
static inline bool tcp_in_pingpong(const struct tcp_pcb *pcb)
{
  return (pcb->pingpong >= TCP_PINGPONG_THRESH);
}
static inline void tcp_enter_pingpong(struct tcp_pcb *pcb)
{
  if (pcb->pingpong < TCP_PINGPONG_THRESH) {
    pcb->pingpong++;
  }
}
static inline void tcp_exit_pingpong(struct tcp_pcb *pcb)
{
  pcb->pingpong = 0;
}
#endif /* GAZELLE_TCP_PINGPONG_MODE */
#endif /* GAZELLE_ENABLE */

#endif /* __GAZELLE_TCP_PRIV_H__ */
