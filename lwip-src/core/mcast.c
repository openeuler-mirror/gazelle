/**
 * @file
 * Multicast filter module\n
 */

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
 * Author: Kylinos Technologies
 *
 */

#include "lwip/opt.h"

#if LWIP_UDP || LWIP_RAW /* don't build if not configured for use in lwipopts.h */

#include "lwip/err.h"
#include "lwip/udp.h"
#include "lwip/raw.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/netif.h"
#include "lwip/errno.h"
#include "lwip/ip_addr.h"
#include "lwip/sockets.h"
#include "lwip/mcast.h"

#include <stddef.h> /* We need offsetof() */

#if LWIP_IPV4 && LWIP_IGMP
/**
 * ipv4 multicast filter find
 */
struct ip4_mc *
mcast_ip4_mc_find(struct ip_mc *ipmc, struct netif *netif, const ip4_addr_t *multi_addr, struct ip4_mc **mc_prev)
{
  struct ip4_mc *prev = NULL;
  struct ip4_mc *mc;

  IP4_MC_FOREACH(ipmc, mc) {
    if (ip4_addr_cmp(&mc->if_addr, netif_ip4_addr(netif)) && 
        ip4_addr_cmp(&mc->multi_addr, multi_addr)) { /* check interface and multicast address */
      if (mc_prev) {
        *mc_prev = prev;
      }
      return mc; /* found! */
    }
    prev = mc;
  }

  return NULL; /* not found! */
}

/**
 * ipv4 multicast filter find source
 */
static struct igmp_src *
mcast_ip4_mc_src_find(struct ip4_mc *mc, const ip4_addr_t *src_addr, struct igmp_src **src_prev)
{
  struct igmp_src *prev = NULL;
  struct igmp_src *src;

  IP4_MC_SRC_FOREACH(mc, src) {
    if (ip4_addr_cmp(&src->src_addr, src_addr)) { /* check source address */
      if (src_prev) {
        *src_prev = prev;
      }
      return src; /* found! */
    }
    prev = src;
  }

  return NULL; /* not found! */
}

/**
 * ipv4 multicast filter remove all source
 */
void
mcast_ip4_mc_src_remove(struct igmp_src *src)
{
  struct igmp_src *next;

  while (src) {
    next = src->next;
    mem_free(src);
    src = next;
  }
}

#if LWIP_IGMP_V3
/**
 * ipv4 multicast filter group source infomation (use ip4_addr_p_t for IGMPv3 speedup)
 */
u16_t
mcast_ip4_filter_info(struct netif *netif, const ip4_addr_t *multi_addr, ip4_addr_p_t addr_array[], u16_t arr_cnt, u8_t *fmode)
{
  static ip4_addr_p_t in_tbl[LWIP_MCAST_SRC_TBL_SIZE];
  static ip4_addr_p_t ex_tbl[LWIP_MCAST_SRC_TBL_SIZE];

  struct ip4_mc *mc;
  struct igmp_src *src;
  ip4_addr_t addr; /* for compare speed */
  u16_t i, j;
  u16_t cnt, in_cnt = 0, ex_cnt = 0;
  u16_t max_cnt = (u16_t)((arr_cnt > LWIP_MCAST_SRC_TBL_SIZE) ? LWIP_MCAST_SRC_TBL_SIZE : arr_cnt);
  u8_t match = 0;

#define LWIP_IP4_MC_GET(pcb, pcbs, type, tbl, c) \
  for ((pcb) = (pcbs); (pcb) != NULL; (pcb) = (pcb)->next) { \
    mc = mcast_ip4_mc_find(&(pcb)->ipmc, netif, multi_addr, NULL); \
    if ((mc == NULL) || (mc->fmode != (type))) { \
      continue; \
    } \
    match = 1; /* group matched */ \
    IP4_MC_SRC_FOREACH(mc, src) { \
      if ((c) < max_cnt) { \
        ip4_addr_set(&(tbl)[(c)], &src->src_addr); /* save a source */ \
        (c)++; \
      } else { \
        *fmode = MCAST_EXCLUDE; /* table overflow, we need all this group packet */ \
        return (0); \
      } \
    } \
  }

#if LWIP_UDP
  {
    struct udp_pcb *pcb;
    LWIP_IP4_MC_GET(pcb, udp_pcbs, MCAST_INCLUDE, in_tbl, in_cnt); /* copy all udp include source address to in_tbl[] */
  }
#endif /* LWIP_UDP */

#if LWIP_RAW
  {
    struct raw_pcb *pcb;
    LWIP_IP4_MC_GET(pcb, raw_pcbs, MCAST_INCLUDE, in_tbl, in_cnt); /* copy all raw include source address to in_tbl[] */
  }
#endif /* LWIP_UDP */

#if LWIP_UDP
  {
    struct udp_pcb *pcb;
    LWIP_IP4_MC_GET(pcb, udp_pcbs, MCAST_EXCLUDE, ex_tbl, ex_cnt); /* copy all udp exclude source address to ex_tbl[] */
  }
#endif /* LWIP_UDP */

#if LWIP_RAW
  {
    struct raw_pcb *pcb;
    LWIP_IP4_MC_GET(pcb, raw_pcbs, MCAST_EXCLUDE, ex_tbl, ex_cnt); /* copy all raw exclude source address to ex_tbl[] */
  }
#endif /* LWIP_UDP */

  if (ex_cnt) { /* at least have one exclude source address */
    *fmode = MCAST_EXCLUDE;
    for (i = 0; i < ex_cnt; i++) {
      ip4_addr_set(&addr, &ex_tbl[i]);
      for (j = 0; j < in_cnt; j++) {
        if (ip4_addr_cmp(&addr, &in_tbl[j])) { /* check exclude conflict with include table */
          ip4_addr_set_any(&ex_tbl[i]); /* remove from exclude table */
          break;
        }
      }
    }

    for (i = 0, cnt = 0; i < ex_cnt; i++) {
      if (!ip4_addr_isany(&ex_tbl[i])) {
        ip4_addr_set(&addr_array[cnt], &ex_tbl[i]);
        cnt++;
      }
    }

  } else if (in_cnt) { /* at least have one include source address */
    *fmode = MCAST_INCLUDE;
    for (i = 0; i < in_cnt; i++) {
      ip4_addr_set(&addr_array[i], &in_tbl[i]);
    }
    cnt = i;

  } else {
    if (match) { /* at least have one pcb matched */
      *fmode = MCAST_EXCLUDE;
    } else { /* no match! */
      *fmode = MCAST_INCLUDE;
    }
    cnt = 0;
  }

  return (cnt);
}

/**
 * ipv4 multicast filter source address interest (use ip4_addr_p_t for IGMPv3 speedup)
 */
u8_t
mcast_ip4_filter_interest(struct netif *netif, const ip4_addr_t *multi_addr, const ip4_addr_p_t src_addr[], u16_t arr_cnt)
{
  static ip4_addr_p_t ip_tbl[LWIP_MCAST_SRC_TBL_SIZE];
  u16_t i, j, cnt;
  u8_t fmode;

  cnt = mcast_ip4_filter_info(netif, multi_addr, ip_tbl, LWIP_MCAST_SRC_TBL_SIZE, &fmode);
  if (fmode == MCAST_EXCLUDE) {
    for (i = 0; i < cnt; i++) {
      for (j = 0; j < arr_cnt; j++) {
        if (ip4_addr_cmp(&src_addr[j], &ip_tbl[i])) {
          return 0;
        }
      }
    }
    return 1;

  } else {
    for (i = 0; i < cnt; i++) {
      for (j = 0; j < arr_cnt; j++) {
        if (ip4_addr_cmp(&src_addr[j], &ip_tbl[i])) {
          return 1;
        }
      }
    }
    return 0;
  }
}
#endif /* LWIP_IGMP_V3 */
#endif /* LWIP_IPV4 && LWIP_IGMP */

#if LWIP_IPV6 && LWIP_IPV6_MLD
/**
 * ipv6 multicast filter find
 */
struct ip6_mc *
mcast_ip6_mc_find(struct ip_mc *ipmc, struct netif *netif, const ip6_addr_t *multi_addr, struct ip6_mc **mc_prev)
{
  struct ip6_mc *prev = NULL;
  struct ip6_mc *mc;

  IP6_MC_FOREACH(ipmc, mc) {
    if (((mc->if_idx == NETIF_NO_INDEX) || (mc->if_idx == netif_get_index(netif))) && 
        ip6_addr_cmp_zoneless(&mc->multi_addr, multi_addr)) { /* check interface and multicast address */
      if (mc_prev) {
        *mc_prev = prev;
      }
      return mc; /* found! */
    }
    prev = mc;
  }

  return NULL; /* not found! */
}

/**
 * ipv6 multicast filter find source
 */
static struct mld6_src *
mcast_ip6_mc_src_find(struct ip6_mc *mc, const ip6_addr_t *src_addr, struct mld6_src **src_prev)
{
  struct mld6_src *prev = NULL;
  struct mld6_src *src;

  IP6_MC_SRC_FOREACH(mc, src) {
    if (ip6_addr_cmp_zoneless(&src->src_addr, src_addr)) { /* check source address */
      if (src_prev) {
        *src_prev = prev;
      }
      return src; /* found! */
    }
    prev = src;
  }

  return NULL; /* not found! */
}

/**
 * ipv6 multicast filter remove all source
 */
void
mcast_ip6_mc_src_remove(struct mld6_src *src)
{
  struct mld6_src *next;

  while (src) {
    next = src->next;
    mem_free(src);
    src = next;
  }
}

#if LWIP_IPV6_MLD_V2
/**
 * ipv6 multicast filter group source infomation (use ip6_addr_p_t for MLDv2 speedup)
 */
u16_t
mcast_ip6_filter_info(struct netif *netif, const ip6_addr_t *multi_addr, ip6_addr_p_t addr_array[], u16_t arr_cnt, u8_t *fmode)
{
  static ip6_addr_p_t in_tbl[LWIP_MCAST_SRC_TBL_SIZE];
  static ip6_addr_p_t ex_tbl[LWIP_MCAST_SRC_TBL_SIZE];

  struct ip6_mc *mc;
  struct mld6_src *src;
  ip6_addr_t addr; /* for compare speed */
  u16_t i, j;
  u16_t cnt, in_cnt = 0, ex_cnt = 0;
  u16_t max_cnt = (u16_t)((arr_cnt > LWIP_MCAST_SRC_TBL_SIZE) ? LWIP_MCAST_SRC_TBL_SIZE : arr_cnt);
  u8_t match = 0;

#define LWIP_IP6_MC_GET(pcb, pcbs, type, tbl, c) \
  for ((pcb) = (pcbs); (pcb) != NULL; (pcb) = (pcb)->next) { \
    mc = mcast_ip6_mc_find(&(pcb)->ipmc, netif, multi_addr, NULL); \
    if ((mc == NULL) || (mc->fmode != (type))) { \
      continue; \
    } \
    match = 1; \
    IP6_MC_SRC_FOREACH(mc, src) { \
      if ((c) < max_cnt) { \
        ip6_addr_copy_to_packed((tbl)[(c)], src->src_addr); /* save a source */ \
        (c)++; \
      } else { \
        *fmode = MCAST_EXCLUDE; /* table overflow, we need all this group packet */ \
        return (0); \
      } \
    } \
  }

#if LWIP_UDP
  {
    struct udp_pcb *pcb;
    LWIP_IP6_MC_GET(pcb, udp_pcbs, MCAST_INCLUDE, in_tbl, in_cnt); /* copy all udp include source address to in_tbl[] */
  }
#endif /* LWIP_UDP */

#if LWIP_RAW
  {
    struct raw_pcb *pcb;
    LWIP_IP6_MC_GET(pcb, raw_pcbs, MCAST_INCLUDE, in_tbl, in_cnt); /* copy all raw include source address to in_tbl[] */
  }
#endif /* LWIP_UDP */

#if LWIP_UDP
  {
    struct udp_pcb *pcb;
    LWIP_IP6_MC_GET(pcb, udp_pcbs, MCAST_EXCLUDE, ex_tbl, ex_cnt); /* copy all udp exclude source address to ex_tbl[] */
  }
#endif /* LWIP_UDP */

#if LWIP_RAW
  {
    struct raw_pcb *pcb;
    LWIP_IP6_MC_GET(pcb, raw_pcbs, MCAST_EXCLUDE, ex_tbl, ex_cnt); /* copy all raw exclude source address to ex_tbl[] */
  }
#endif /* LWIP_UDP */

  if (ex_cnt) { /* at least have one exclude source address */
    *fmode = MCAST_EXCLUDE;
    for (i = 0; i < ex_cnt; i++) {
      ip6_addr_copy_from_packed(addr, ex_tbl[i]);
      for (j = 0; j < in_cnt; j++) {
        if (ip6_addr_cmp_zoneless(&addr, &in_tbl[j])) { /* check exclude conflict with include table */
          ip6_addr_copy_to_packed(ex_tbl[i], *IP6_ADDR_ANY6); /* remove from exclude table */
          break;
        }
      }
    }

    for (i = 0, cnt = 0; i < ex_cnt; i++) {
      if (!ip6_addr_isany(&ex_tbl[i])) {
        ip6_addr_copy_to_packed(addr_array[cnt], ex_tbl[i]);
        cnt++;
      }
    }

  } else if (in_cnt) { /* at least have one include source address */
    *fmode = MCAST_INCLUDE;
    for (i = 0; i < in_cnt; i++) {
      ip6_addr_copy_to_packed(addr_array[i], in_tbl[i]);
    }
    cnt = i;

  } else {
    if (match) { /* at least have one pcb matched */
      *fmode = MCAST_EXCLUDE;
    } else { /* no match! */
      *fmode = MCAST_INCLUDE;
    }
    cnt = 0;
  }

  return (cnt);
}

/**
 * ipv6 multicast filter source address interest (use ip6_addr_p_t for MLDv2 speedup)
 */
u8_t
mcast_ip6_filter_interest(struct netif *netif, const ip6_addr_t *multi_addr, const ip6_addr_p_t src_addr[], u16_t arr_cnt)
{
  static ip6_addr_p_t ip_tbl[LWIP_MCAST_SRC_TBL_SIZE];
  u16_t i, j, cnt;
  u8_t fmode;

  cnt = mcast_ip6_filter_info(netif, multi_addr, ip_tbl, LWIP_MCAST_SRC_TBL_SIZE, &fmode);
  if (fmode == MCAST_EXCLUDE) {
    for (i = 0; i < cnt; i++) {
      for (j = 0; j < arr_cnt; j++) {
        if (ip6_addr_cmp_zoneless(&src_addr[j], &ip_tbl[i])) {
          return 0;
        }
      }
    }
    return 1;

  } else {
    for (i = 0; i < cnt; i++) {
      for (j = 0; j < arr_cnt; j++) {
        if (ip6_addr_cmp_zoneless(&src_addr[j], &ip_tbl[i])) {
          return 1;
        }
      }
    }
    return 0;
  }
}
#endif /* LWIP_IPV6_MLD_V2 */
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */

#if (LWIP_IPV4 && LWIP_IGMP) || (LWIP_IPV6 && LWIP_IPV6_MLD)

#if (LWIP_IPV4 && LWIP_IGMP) 
err_t
mcast_mc_new_src(struct ip4_mc *mc, const ip_addr_t *src_addr)
{
  struct igmp_src *src;
  if (mc->num_src >= LWIP_MCAST_SRC_TBL_SIZE) {
    return ERR_MEM;
  }
  src = (struct igmp_src *)mem_malloc(sizeof(struct igmp_src));
  if (src == NULL) {
    return ERR_MEM; /* no memory */
  }
  ip4_addr_set(&src->src_addr, ip_2_ip4(src_addr));
  src->next = mc->src;
  mc->src = src;
  mc->num_src++;
  return ERR_OK;
}

err_t
mcast_mc_free_src(struct ip4_mc *mc, struct igmp_src *src, struct igmp_src *src_prev)
{
  if (src == NULL) {
    return ERR_OK;
  }
  if (src_prev) {
    src_prev->next = src->next;
  } else {
    mc->src = src->next;
  }
  mem_free(src);
  if (mc->num_src > 0)
    mc->num_src--;
  return ERR_OK;
}
#endif

#if (LWIP_IPV6 && LWIP_IPV6_MLD)
err_t
mcast_mc_new_ipv6_src(struct ip6_mc *mc, const ip_addr_t *src_addr)
{
  struct mld6_src *src;
  if (mc->num_src >= LWIP_MCAST_SRC_TBL_SIZE) {
    return ERR_MEM;
  }
  src = (struct mld6_src *)mem_malloc(sizeof(struct mld6_src));
  if (src == NULL) {
    return ERR_MEM; /* no memory */
  }
  ip6_addr_set(&src->src_addr, ip_2_ip6(src_addr));
  src->next = mc->src;
  mc->src = src;
  mc->num_src++;
  return ERR_OK;
}

err_t
mcast_mc_free_ipv6_src(struct ip6_mc *mc, struct mld6_src *src, struct mld6_src *src_prev)
{
  if (src == NULL) {
    return ERR_OK;
  }
  if (src_prev) {
    src_prev->next = src->next;
  } else {
    mc->src = src->next;
  }
  mem_free(src);
  if (mc->num_src > 0)
    mc->num_src--;
  return ERR_OK;
}
#endif

/** Join a multicast group (Can with a source specified)
 *
 * @param ipmc multicast filter control block
 * @param netif the network interface which should join a new group.
 * @param multi_addr the ipv6 address of the group to join
 * @param src_addr multicast source address (can be NULL)
 * @return lwIP error definitions
 */
err_t
mcast_join_netif(struct ip_mc *ipmc, struct netif *netif, const ip_addr_t *multi_addr, const ip_addr_t *src_addr)
{
#if LWIP_UDP
  if (ipmc->proto == IPPROTO_UDP) {
    err_t err;
    struct udp_pcb *pcb;
    /* prepare UDP pcb to udp_pcbs list */
    pcb = (struct udp_pcb *)((u8_t *)ipmc - offsetof(struct udp_pcb, ipmc));
    if (pcb->local_port == 0) {
      err = udp_bind(pcb, &pcb->local_ip, pcb->local_port);
      if (err != ERR_OK) {
        LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("mcast_join_netif: forced port bind failed\n"));
        return err;
      }
    }
  }
#endif /* LWIP_UDP */

#if LWIP_IPV4 && LWIP_IGMP
  if (IP_IS_V4(multi_addr)) {
    struct ip4_mc *mc;
    struct igmp_src *src;
    err_t err;

    mc = mcast_ip4_mc_find(ipmc, netif, ip_2_ip4(multi_addr), NULL);
    if (mc) {
      if (src_addr) {
        if ((mc->fmode == MCAST_EXCLUDE) && (mc->src)) {
          return ERR_VAL; /* filter mode not include mode */
        }
        src = mcast_ip4_mc_src_find(mc, ip_2_ip4(src_addr), NULL);
        if (src) {
          return ERR_ALREADY; /* already in source list */
        }

        if (mcast_mc_new_src(mc, src_addr) != ERR_OK) {
          return ERR_MEM; /* no memory */
        }
        mc->fmode = MCAST_INCLUDE; /* change to include mode */
        IP4_MC_TRIGGER_CALL(netif, ip_2_ip4(multi_addr)); /* trigger a report */
        return ERR_OK;
      }
      return EADDRINUSE;
    }

    mc = (struct ip4_mc *)mem_malloc(sizeof(struct ip4_mc)); /* Make a new mc */
    if (mc == NULL) {
      igmp_leavegroup_netif(netif, ip_2_ip4(multi_addr));
      return ERR_MEM; /* no memory */
    }
    mc->num_src = 0;
    mc->src = NULL;
    mc->if_idx = netif_get_index(netif);
    ip4_addr_set(&mc->if_addr, netif_ip4_addr(netif));
    ip4_addr_set(&mc->multi_addr, ip_2_ip4(multi_addr));

    if (src_addr) { /* have a source specified */
      mc->fmode = MCAST_INCLUDE;
      if (mcast_mc_new_src(mc, src_addr) != ERR_OK) {
        igmp_leavegroup_netif(netif, ip_2_ip4(multi_addr));
        mem_free(mc);
        return ERR_MEM; /* no memory */
      }
    } else {
      mc->fmode = MCAST_EXCLUDE; /* no source specified */
      mc->src = NULL;
    }

    mc->next = ipmc->mc4;
    ipmc->mc4 = mc;
    err = igmp_joingroup_netif(netif, ip_2_ip4(multi_addr));
    if (err != ERR_OK) {
      ipmc->mc4 = mc->next;
      mem_free(mc);
    }
    return err;
  } else
#endif /* LWIP_IPV4 && LWIP_IGMP */
  {
#if LWIP_IPV6 && LWIP_IPV6_MLD
    struct ip6_mc *mc;
    struct mld6_src *src;
    err_t err;

    mc = mcast_ip6_mc_find(ipmc, netif, ip_2_ip6(multi_addr), NULL);
    if (mc) {
      if (src_addr) {
        if ((mc->fmode == MCAST_EXCLUDE) && (mc->src)) {
          return ERR_VAL; /* filter mode not include mode */
        }
        src = mcast_ip6_mc_src_find(mc, ip_2_ip6(src_addr), NULL);
        if (src) {
          return ERR_ALREADY; /* already in source list */
        }

        if (mcast_mc_new_ipv6_src(mc, src_addr) != ERR_OK) {
          return ERR_MEM; /* no memory */
        }
        mc->fmode = MCAST_INCLUDE; /* change to include mode */
        IP6_MC_TRIGGER_CALL(netif, ip_2_ip6(multi_addr)); /* trigger a report */
        return ERR_OK;
      }
      return EADDRINUSE;
    }

    mc = (struct ip6_mc *)mem_malloc(sizeof(struct ip6_mc)); /* Make a new mc */
    if (mc == NULL) {
      mld6_leavegroup_netif(netif, ip_2_ip6(multi_addr));
      return ERR_MEM; /* no memory */
    }
    mc->num_src = 0;
    mc->src = NULL;
    mc->if_idx = netif_get_index(netif);
    ip6_addr_set(&mc->multi_addr, ip_2_ip6(multi_addr));

    if (src_addr) {
      mc->fmode = MCAST_INCLUDE;
      if (mcast_mc_new_ipv6_src(mc, src_addr) != ERR_OK) {
        mld6_leavegroup_netif(netif, ip_2_ip6(multi_addr));
        mem_free(mc);
        return ERR_MEM; /* no memory */
      }
    } else {
      mc->fmode = MCAST_EXCLUDE; /* no source specified */
      mc->src = NULL;
    }

    mc->next = ipmc->mc6;
    ipmc->mc6 = mc;
    err = mld6_joingroup_netif(netif, ip_2_ip6(multi_addr));
    if (err != ERR_OK) {
      ipmc->mc6 = mc->next;
      mem_free(mc);
    }
    return err;
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */
  }
  return ERR_OK;
}

/** Join a multicast group (Can with a source specified)
 *
 * @param ipmc multicast filter control block
 * @param if_addr the network interface address.
 * @param multi_addr the ipv6 address of the group to join
 * @param src_addr multicast source address (can be NULL)
 * @return lwIP error definitions
 */
err_t
mcast_join_group(struct ip_mc *ipmc, const ip_addr_t *if_addr, const ip_addr_t *multi_addr, const ip_addr_t *src_addr)
{
  err_t err = ERR_VAL; /* no matching interface */

#if LWIP_IPV4 && LWIP_IGMP
  if (IP_IS_V4(multi_addr)) {
    struct netif *netif;

    NETIF_FOREACH(netif) {
      if ((netif->flags & NETIF_FLAG_IGMP) && ((ip4_addr_isany(ip_2_ip4(if_addr)) || ip4_addr_cmp(netif_ip4_addr(netif), ip_2_ip4(if_addr))))) {
        err = mcast_join_netif(ipmc, netif, multi_addr, src_addr);
        if (err != ERR_OK) {
          return (err);
        }
      }
    }
  } else
#endif /* LWIP_IPV4 && LWIP_IGMP */
  {
#if LWIP_IPV6 && LWIP_IPV6_MLD
    struct netif *netif;

    NETIF_FOREACH(netif) {
      if (ip6_addr_isany(ip_2_ip6(if_addr)) ||
          netif_get_ip6_addr_match(netif, ip_2_ip6(if_addr)) >= 0) {
        err = mcast_join_netif(ipmc, netif, multi_addr, src_addr);
        if (err != ERR_OK) {
          return (err);
        }
      }
    }
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */
  }
  return err;
}

/** Leave or drop a source from group on a network interface.
 *
 * @param ipmc multicast filter control block
 * @param netif the network interface which should leave group.
 * @param multi_addr the address of the group to leave
 * @param src_addr multicast source address
 * @return lwIP error definitions
 */
err_t
mcast_leave_netif(struct ip_mc *ipmc, struct netif *netif, const ip_addr_t *multi_addr, const ip_addr_t *src_addr)
{
#if LWIP_IPV4 && LWIP_IGMP
  if (IP_IS_V4(multi_addr)) {
    struct ip4_mc *mc_prev;
    struct ip4_mc *mc;
    struct igmp_src *src_prev;
    struct igmp_src *src;

    mc = mcast_ip4_mc_find(ipmc, netif, ip_2_ip4(multi_addr), &mc_prev);
    if (mc == NULL) {
      return ERR_VAL;
    }

    if (src_addr) {
      if ((mc->fmode == MCAST_EXCLUDE) && (mc->src)) {
        return ERR_VAL; /* drop source membership must in include mode */
      }

      src = mcast_ip4_mc_src_find(mc, ip_2_ip4(src_addr), &src_prev);
      if (src) {
        mcast_mc_free_src(mc, src, src_prev);
      } else {
        return ERR_VAL;
      }
      if (mc->src) {
        IP4_MC_TRIGGER_CALL(netif, ip_2_ip4(multi_addr)); /* trigger a report */
        return ERR_OK;
      }
    } else { /* we want drop this group */
      mcast_ip4_mc_src_remove(mc->src);
      mc->num_src = 0;
    }

    igmp_leavegroup_netif(netif, ip_2_ip4(multi_addr));
    if (mc_prev) {
      mc_prev->next = mc->next;
    } else {
      ipmc->mc4 = mc->next;
    }
    mem_free(mc);
  } else
#endif /* LWIP_IPV4 && LWIP_IGMP */
  {
#if LWIP_IPV6 && LWIP_IPV6_MLD
    struct ip6_mc *mc_prev;
    struct ip6_mc *mc;
    struct mld6_src *src_prev;
    struct mld6_src *src;

    mc = mcast_ip6_mc_find(ipmc, netif, ip_2_ip6(multi_addr), &mc_prev);
    if (mc == NULL) {
      return ERR_VAL;
    }

    if (src_addr) {
      if ((mc->fmode == MCAST_EXCLUDE) && (mc->src)) {
        return ERR_VAL; /* drop source membership must in include mode */
      }

      src = mcast_ip6_mc_src_find(mc, ip_2_ip6(src_addr), &src_prev);
      if (src) {
        mcast_mc_free_ipv6_src(mc, src, src_prev);
      } else {
        return ERR_VAL;
      }
      if (mc->src) {
        IP6_MC_TRIGGER_CALL(netif, ip_2_ip6(multi_addr)); /* trigger a report */
        return ERR_OK;
      }
    } else { /* we want drop this group */
      mcast_ip6_mc_src_remove(mc->src);
      mc->num_src = 0;
    }

    mld6_leavegroup_netif(netif, ip_2_ip6(multi_addr));
    if (mc_prev) {
      mc_prev->next = mc->next;
    } else {
      ipmc->mc6 = mc->next;
    }
    mem_free(mc);
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */
  }
  return ERR_OK;
}

/** Leave or drop a source from group on a network interface.
 *
 * @param ipmc multicast filter control block
 * @param if_addr the network interface address.
 * @param multi_addr the address of the group to leave
 * @param src_addr multicast source address
 * @return lwIP error definitions
 */
err_t
mcast_leave_group(struct ip_mc *ipmc, const ip_addr_t *if_addr, const ip_addr_t *multi_addr, const ip_addr_t *src_addr)
{
  err_t res, err = ERR_VAL; /* no matching interface */

#if LWIP_IPV4 && LWIP_IGMP
  if (IP_IS_V4(multi_addr)) {
    struct netif *netif;

    NETIF_FOREACH(netif) {
      if ((netif->flags & NETIF_FLAG_IGMP) && ((ip4_addr_isany(ip_2_ip4(if_addr)) || ip4_addr_cmp(netif_ip4_addr(netif), ip_2_ip4(if_addr))))) {
        res = mcast_leave_netif(ipmc, netif, multi_addr, src_addr);
        if (err != ERR_OK) {
          err = res;
        }
      }
    }
  } else
#endif /* LWIP_IPV4 && LWIP_IGMP */
  {
#if LWIP_IPV6 && LWIP_IPV6_MLD
    struct netif *netif;

    NETIF_FOREACH(netif) {
      if (ip6_addr_isany(ip_2_ip6(if_addr)) ||
          netif_get_ip6_addr_match(netif, ip_2_ip6(if_addr)) >= 0) {
        res = mcast_leave_netif(ipmc, netif, multi_addr, src_addr);
        if (err != ERR_OK) {
          err = res;
        }
      }
    }
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */
  }
  return err;
}

/** Add a block source address to a multicast group
 *
 * @param ipmc multicast filter control block
 * @param netif the network interface which group we already join.
 * @param multi_addr the address of the group to add source
 * @param blk_addr block multicast source address
 * @return lwIP error definitions
 */
err_t
mcast_block_netif(struct ip_mc *ipmc, struct netif *netif, const ip_addr_t *multi_addr, const ip_addr_t *blk_addr)
{
#if LWIP_IPV4 && LWIP_IGMP
  if (IP_IS_V4(multi_addr)) {
    struct ip4_mc *mc;
    struct igmp_src *src;

    mc = mcast_ip4_mc_find(ipmc, netif, ip_2_ip4(multi_addr), NULL);
    if (mc == NULL) {
      return ERR_VAL;
    }
    if (mc->fmode != MCAST_EXCLUDE) { /* we must in exclude mode */
      return ERR_VAL;
    }

    src = mcast_ip4_mc_src_find(mc, ip_2_ip4(blk_addr), NULL);
    if (src == NULL) {
      if (mcast_mc_new_src(mc, blk_addr) != ERR_OK) {
        return ERR_MEM;
      }
      IP4_MC_TRIGGER_CALL(netif, ip_2_ip4(multi_addr)); /* trigger a report */
    }
  } else
#endif /* LWIP_IPV4 && LWIP_IGMP */
  {
#if LWIP_IPV6 && LWIP_IPV6_MLD
    struct ip6_mc *mc;
    struct mld6_src *src;

    mc = mcast_ip6_mc_find(ipmc, netif, ip_2_ip6(multi_addr), NULL);
    if (mc == NULL) {
      return ERR_VAL;
    }
    if (mc->fmode != MCAST_EXCLUDE) { /* we must in exclude mode */
      return ERR_VAL;
    }

    src = mcast_ip6_mc_src_find(mc, ip_2_ip6(blk_addr), NULL);
    if (src == NULL) {
      if (mcast_mc_new_ipv6_src(mc, blk_addr) != ERR_OK) {
        return ERR_MEM;
      }
      IP6_MC_TRIGGER_CALL(netif, ip_2_ip6(multi_addr)); /* trigger a report */
    }
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */
  }
  return ERR_OK;
}

/** Add a block source address to a multicast group
 *
 * @param ipmc multicast filter control block
 * @param if_addr the network interface address.
 * @param multi_addr the address of the group to add source
 * @param blk_addr block multicast source address
 * @return lwIP error definitions
 */
err_t
mcast_block_group(struct ip_mc *ipmc, const ip_addr_t *if_addr, const ip_addr_t *multi_addr, const ip_addr_t *blk_addr)
{
  err_t err = ERR_VAL; /* no matching interface */
  
#if LWIP_IPV4 && LWIP_IGMP
  if (IP_IS_V4(multi_addr)) {
    struct netif *netif;

    NETIF_FOREACH(netif) {
      if ((netif->flags & NETIF_FLAG_IGMP) && ((ip4_addr_isany(ip_2_ip4(if_addr)) || ip4_addr_cmp(netif_ip4_addr(netif), ip_2_ip4(if_addr))))) {
        err = mcast_block_netif(ipmc, netif, multi_addr, blk_addr);
        if (err != ERR_OK) {
          return (err);
        }
      }
    }
  } else
#endif /* LWIP_IPV4 && LWIP_IGMP */
  {
#if LWIP_IPV6 && LWIP_IPV6_MLD
    struct netif *netif;

    NETIF_FOREACH(netif) {
      if (ip6_addr_isany(ip_2_ip6(if_addr)) ||
          netif_get_ip6_addr_match(netif, ip_2_ip6(if_addr)) >= 0) {
        err = mcast_block_netif(ipmc, netif, multi_addr, blk_addr);
        if (err != ERR_OK) {
          return (err);
        }
      }
    }
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */
  }
  return err;
}

/** Remove a block source address from a multicast group
 *
 * @param ipmc multicast filter control block
 * @param netif the network interface which group we already join.
 * @param multi_addr the address of the group to add source
 * @param unblk_addr unblock multicast source address
 * @return lwIP error definitions
 */
err_t
mcast_unblock_netif(struct ip_mc *ipmc, struct netif *netif, const ip_addr_t *multi_addr, const ip_addr_t *unblk_addr)
{
#if LWIP_IPV4 && LWIP_IGMP
  if (IP_IS_V4(multi_addr)) {
    struct ip4_mc *mc;
    struct igmp_src *src_prev;
    struct igmp_src *src;

    mc = mcast_ip4_mc_find(ipmc, netif, ip_2_ip4(multi_addr), NULL);
    if (mc == NULL) {
      return ERR_VAL;
    }
    if (mc->fmode != MCAST_EXCLUDE) { /* we must in exclude mode */
      return ERR_VAL;
    }

    src = mcast_ip4_mc_src_find(mc, ip_2_ip4(unblk_addr), &src_prev);
    if (src == NULL) {
      return ERR_VAL;
    }
    mcast_mc_free_src(mc, src, src_prev);
    IP4_MC_TRIGGER_CALL(netif, ip_2_ip4(multi_addr)); /* trigger a report */
  } else
#endif /* LWIP_IPV4 && LWIP_IGMP */
  {
#if LWIP_IPV6 && LWIP_IPV6_MLD
    struct ip6_mc *mc;
    struct mld6_src *src_prev;
    struct mld6_src *src;

    mc = mcast_ip6_mc_find(ipmc, netif, ip_2_ip6(multi_addr), NULL);
    if (mc == NULL) {
      return ERR_VAL;
    }
    if (mc->fmode != MCAST_EXCLUDE) { /* we must in exclude mode */
      return ERR_VAL;
    }

    src = mcast_ip6_mc_src_find(mc, ip_2_ip6(unblk_addr), &src_prev);
    if (src == NULL) {
      return ERR_VAL;
    }
    mcast_mc_free_ipv6_src(mc, src, src_prev);
    IP6_MC_TRIGGER_CALL(netif, ip_2_ip6(multi_addr)); /* trigger a report */
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */
  }
  return ERR_OK;
}

/** Remove a block source address from a multicast group
 *
 * @param ipmc multicast filter control block
 * @param if_addr the network interface address.
 * @param multi_addr the address of the group to add source
 * @param unblk_addr unblock multicast source address
 * @return lwIP error definitions
 */
err_t
mcast_unblock_group(struct ip_mc *ipmc, const ip_addr_t *if_addr, const ip_addr_t *multi_addr, const ip_addr_t *unblk_addr)
{
  err_t res, err = ERR_VAL; /* no matching interface */

#if LWIP_IPV4 && LWIP_IGMP
  if (IP_IS_V4(multi_addr)) {
    struct netif *netif;

    NETIF_FOREACH(netif) {
      if ((netif->flags & NETIF_FLAG_IGMP) && ((ip4_addr_isany(ip_2_ip4(if_addr)) || ip4_addr_cmp(netif_ip4_addr(netif), ip_2_ip4(if_addr))))) {
        res = mcast_unblock_netif(ipmc, netif, multi_addr, unblk_addr);
        if (err != ERR_OK) {
          err = res;
        }
      }
    }
  } else
#endif /* LWIP_IPV4 && LWIP_IGMP */
  {
#if LWIP_IPV6 && LWIP_IPV6_MLD
    struct netif *netif;

    NETIF_FOREACH(netif) {
      if (ip6_addr_isany(ip_2_ip6(if_addr)) ||
          netif_get_ip6_addr_match(netif, ip_2_ip6(if_addr)) >= 0) {
        res = mcast_unblock_netif(ipmc, netif, multi_addr, unblk_addr);
        if (err != ERR_OK) {
          err = res;
        }
      }
    }
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */
  }
  return err;
}

#endif /* (LWIP_IPV4 && LWIP_IGMP) || (LWIP_IPV6 && LWIP_IPV6_MLD) */

#endif /* LWIP_UDP || LWIP_RAW */
