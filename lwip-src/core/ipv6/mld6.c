/**
 * @file
 * Multicast listener discovery
 *
 * @defgroup mld6 MLD6
 * @ingroup ip6
 * Multicast listener discovery for IPv6. Aims to be compliant with RFC 2710.
 * No support for MLDv2.<br>
 * Note: The allnodes (ff01::1, ff02::1) group is assumed be received by your
 * netif since it must always be received for correct IPv6 operation (e.g. SLAAC).
 * Ensure the netif filters are configured accordingly!<br>
 * The netif flags also need NETIF_FLAG_MLD6 flag set to enable MLD6 on a
 * netif ("netif->flags |= NETIF_FLAG_MLD6;").<br>
 * To be called from TCPIP thread.
 */

/*
 * Copyright (c) 2010 Inico Technologies Ltd.
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
 * Author: Ivan Delamer <delamer@inicotech.com>
 *
 *
 * Please coordinate changes and requests with Ivan Delamer
 * <delamer@inicotech.com>
 */

/* Based on igmp.c implementation of igmp v2 protocol */

#include "lwip/opt.h"

#if LWIP_IPV6 && LWIP_IPV6_MLD  /* don't build if not configured for use in lwipopts.h */

#include "lwip/mld6.h"
#include "lwip/prot/mld6.h"
#include "lwip/icmp6.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/ip.h"
#include "lwip/inet_chksum.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/memp.h"
#include "lwip/stats.h"
#include "lwip/sockets.h"

#include <string.h>


/*
 * MLD constants
 */
#define MLD6_HL                           1
#define MLD6_JOIN_DELAYING_MEMBER_TMR_MS  (500)

#define MLD6_GROUP_NON_MEMBER             0
#define MLD6_GROUP_DELAYING_MEMBER        1
#define MLD6_GROUP_IDLE_MEMBER            2

#define MLD6_MINLEN                    12
#define MLD6_V2_MINLEN                  16

/* Forward declarations. */
static struct mld_group *mld6_new_group(struct netif *ifp, const ip6_addr_t *addr);
static err_t mld6_remove_group(struct netif *netif, struct mld_group *group);
static void mld6_delayed_report(struct mld_group *group, u16_t maxresp);
static void mld6_send(struct netif *netif, struct mld_group *group, u8_t type);
static void mld6_timeout(struct netif *netif, struct mld_group *group);


#if LWIP_IPV6_MLD_V2
static void mld6_v2_timeout(struct netif *netif, struct mld_group *group);
static void mld6_v2_delayed_report(struct mld_group *group, u16_t maxresp_in);
static void mld6_v2_send(struct netif *netif, struct mld_group *group, u8_t type);
#endif

/**
 * Stop MLD processing on interface
 *
 * @param netif network interface on which stop MLD processing
 */
err_t
mld6_stop(struct netif *netif)
{
  struct mld_group *group = netif_mld6_data(netif);

  netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6, NULL);

  while (group != NULL) {
    struct mld_group *next = group->next; /* avoid use-after-free below */

    /* disable the group at the MAC level */
    if (netif->mld_mac_filter != NULL) {
      netif->mld_mac_filter(netif, &(group->group_address), NETIF_DEL_MAC_FILTER);
    }

    /* free group */
    memp_free(MEMP_MLD6_GROUP, group);

    /* move to "next" */
    group = next;
  }
  return ERR_OK;
}

/**
 * Report MLD memberships for this interface
 *
 * @param netif network interface on which report MLD memberships
 */
void
mld6_report_groups(struct netif *netif)
{
  struct mld_group *group = netif_mld6_data(netif);

  while (group != NULL) {
    mld6_delayed_report(group, MLD6_JOIN_DELAYING_MEMBER_TMR_MS);
#if LWIP_IPV6_MLD_V2
    mld6_v2_delayed_report(group, MLD6_JOIN_DELAYING_MEMBER_TMR_MS);
#endif
    group = group->next;
  }
}

/**
 * Search for a group that is joined on a netif
 *
 * @param ifp the network interface for which to look
 * @param addr the group ipv6 address to search for
 * @return a struct mld_group* if the group has been found,
 *         NULL if the group wasn't found.
 */
struct mld_group *
mld6_lookfor_group(struct netif *ifp, const ip6_addr_t *addr)
{
  struct mld_group *group = netif_mld6_data(ifp);

  while (group != NULL) {
    if (ip6_addr_eq(&(group->group_address), addr)) {
      return group;
    }
    group = group->next;
  }

  return NULL;
}


/**
 * create a new group
 *
 * @param ifp the network interface for which to create
 * @param addr the new group ipv6
 * @return a struct mld_group*,
 *         NULL on memory error.
 */
static struct mld_group *
mld6_new_group(struct netif *ifp, const ip6_addr_t *addr)
{
  struct mld_group *group;

  group = (struct mld_group *)memp_malloc(MEMP_MLD6_GROUP);
  if (group != NULL) {
    ip6_addr_set(&(group->group_address), addr);
    group->timer              = 0; /* Not running */
    group->group_state        = MLD6_GROUP_IDLE_MEMBER;
    group->last_reporter_flag = 0;
    group->use                = 0;
    group->next               = netif_mld6_data(ifp);
#if LWIP_IPV6_MLD_V2
    group->v2_fmode = MLD6_FMODE_INIT;
    group->v2_last_reporter_flag = 0;
    group->v2_group_state = MLD6_GROUP_IDLE_MEMBER;
    group->v2_timer = 0;
#endif

    netif_set_client_data(ifp, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6, group);
  }

  return group;
}

/**
 * Remove a group from the mld_group_list, but do not free it yet
 *
 * @param group the group to remove
 * @return ERR_OK if group was removed from the list, an err_t otherwise
 */
static err_t
mld6_remove_group(struct netif *netif, struct mld_group *group)
{
  err_t err = ERR_OK;

  /* Is it the first group? */
  if (netif_mld6_data(netif) == group) {
    netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_MLD6, group->next);
  } else {
    /* look for group further down the list */
    struct mld_group *tmpGroup;
    for (tmpGroup = netif_mld6_data(netif); tmpGroup != NULL; tmpGroup = tmpGroup->next) {
      if (tmpGroup->next == group) {
        tmpGroup->next = group->next;
        break;
      }
    }
    /* Group not find group */
    if (tmpGroup == NULL) {
      err = ERR_ARG;
    }
  }

  return err;
}


/**
 * Process an input MLD message. Called by icmp6_input.
 *
 * @param p the mld packet, p->payload pointing to the icmpv6 header
 * @param inp the netif on which this packet was received
 */
void
mld6_input(struct pbuf *p, struct netif *inp)
{
  struct mld_header *mld_hdr;
  struct mld_group *group;

  MLD6_STATS_INC(mld6.recv);

  /* Check that mld header fits in packet. */
  if (p->len < sizeof(struct mld_header)) {
    /* @todo debug message */
    pbuf_free(p);
    MLD6_STATS_INC(mld6.lenerr);
    MLD6_STATS_INC(mld6.drop);
    return;
  }

  mld_hdr = (struct mld_header *)p->payload;

  switch (mld_hdr->type) {
  case ICMP6_TYPE_MLQ: /* Multicast listener query. */
#if LWIP_IPV6_MLD_V2
    if (p->len >= MLD6_V2_MINLEN) {
      struct mld_v2_query *mld_v2_hdr = (struct mld_v2_query *)p->payload;

      /* Is it a general query? */
      if (ip6_addr_isallnodes_linklocal(ip6_current_dest_addr()) &&
          ip6_addr_isany(&(mld_v2_hdr->multicast_address))) {
        MLD6_STATS_INC(mld6.rx_general);
        /* Report all groups, except all nodes group, and if-local groups. */
        group = netif_mld6_data(inp);
        while (group != NULL) {
          if ((!(ip6_addr_ismulticast_iflocal(&(group->group_address)))) &&
              (!(ip6_addr_isallnodes_linklocal(&(group->group_address))))) {
            mld6_v2_delayed_report(group, lwip_ntohs(mld_hdr->max_resp_delay));
          }
          group = group->next;
        }
      } else { /* query to a specific group ? */
        if (!ip6_addr_isany(&(mld_v2_hdr->multicast_address))) {
          u16_t src_num = PP_NTOHS(mld_v2_hdr->src_num);
          ip6_addr_p_t *src_buf;
          u16_t src_buf_size = src_num << 4;
          ip6_addr_t group_addr;

          MLD6_STATS_INC(mld6.rx_group);
          ip6_addr_copy(group_addr, mld_v2_hdr->multicast_address);
          group = mld6_lookfor_group(inp, &group_addr);

          if (0 == src_num) {
            if (group != NULL) {
              /* Schedule a report. */
              mld6_v2_delayed_report(group, lwip_ntohs(mld_v2_hdr->max_resp_delay));
            }
          } else {
            src_buf = (ip6_addr_p_t *)mem_malloc(src_buf_size);
            if (src_buf == NULL) {
              pbuf_free(p);
              MLD6_STATS_INC(mld6.memerr);
              LWIP_DEBUGF(MLD6_DEBUG, ("mld6_input: not enough memory for mld6_input\n"));
              return;
            }
            pbuf_copy_partial(p, src_buf, src_buf_size, MLD_V2_QUERY_HLEN);
            if (mcast_ip6_filter_interest(inp, (const ip6_addr_t *)&group_addr, src_buf, src_num)) {
              /* We interest! */
              mld6_v2_delayed_report(group, lwip_ntohs(mld_v2_hdr->max_resp_delay));
            }
          }
        }
      }
      break;
    }
#endif
    /* Is it a general query? */
    if (ip6_addr_isallnodes_linklocal(ip6_current_dest_addr()) &&
        ip6_addr_isany(&(mld_hdr->multicast_address))) {
      MLD6_STATS_INC(mld6.rx_general);
      /* Report all groups, except all nodes group, and if-local groups. */
      group = netif_mld6_data(inp);
      while (group != NULL) {
        if ((!(ip6_addr_ismulticast_iflocal(&(group->group_address)))) &&
            (!(ip6_addr_isallnodes_linklocal(&(group->group_address))))) {
          mld6_delayed_report(group, lwip_ntohs(mld_hdr->max_resp_delay));
        }
        group = group->next;
      }
    } else {
      /* Have we joined this group?
       * We use IP6 destination address to have a memory aligned copy.
       * mld_hdr->multicast_address should be the same. */
      MLD6_STATS_INC(mld6.rx_group);
      group = mld6_lookfor_group(inp, ip6_current_dest_addr());
      if (group != NULL) {
        /* Schedule a report. */
        mld6_delayed_report(group, lwip_ntohs(mld_hdr->max_resp_delay));
      }
    }
    break; /* ICMP6_TYPE_MLQ */
  case ICMP6_TYPE_MLR: /* Multicast listener report. */
    /* Have we joined this group?
     * We use IP6 destination address to have a memory aligned copy.
     * mld_hdr->multicast_address should be the same. */
    MLD6_STATS_INC(mld6.rx_report);
    group = mld6_lookfor_group(inp, ip6_current_dest_addr());
    if (group != NULL) {
      /* If we are waiting to report, cancel it. */
      if (group->group_state == MLD6_GROUP_DELAYING_MEMBER) {
        group->timer = 0; /* stopped */
        group->group_state = MLD6_GROUP_IDLE_MEMBER;
        group->last_reporter_flag = 0;
      }
    }
    break; /* ICMP6_TYPE_MLR */
  case ICMP6_TYPE_MLD: /* Multicast listener done. */
    /* Do nothing, router will query us. */
    break; /* ICMP6_TYPE_MLD */
  default:
    MLD6_STATS_INC(mld6.proterr);
    MLD6_STATS_INC(mld6.drop);
    break;
  }

  pbuf_free(p);
}

/**
 * @ingroup mld6
 * Join a group on one or all network interfaces.
 *
 * If the group is to be joined on all interfaces, the given group address must
 * not have a zone set (i.e., it must have its zone index set to IP6_NO_ZONE).
 * If the group is to be joined on one particular interface, the given group
 * address may or may not have a zone set.
 *
 * @param srcaddr ipv6 address (zoned) of the network interface which should
 *                join a new group. If IP6_ADDR_ANY6, join on all netifs
 * @param groupaddr the ipv6 address of the group to join (possibly but not
 *                  necessarily zoned)
 * @return ERR_OK if group was joined on the netif(s), an err_t otherwise
 */
err_t
mld6_joingroup(const ip6_addr_t *srcaddr, const ip6_addr_t *groupaddr)
{
  err_t         err = ERR_VAL; /* no matching interface */
  struct netif *netif;

  LWIP_ASSERT_CORE_LOCKED();

  /* loop through netif's */
  NETIF_FOREACH(netif) {
    /* Should we join this interface ? */
    if (ip6_addr_isany(srcaddr) ||
        netif_get_ip6_addr_match(netif, srcaddr) >= 0) {
      err = mld6_joingroup_netif(netif, groupaddr);
      if (err != ERR_OK) {
        return err;
      }
    }
  }

  return err;
}

/**
 * @ingroup mld6
 * Join a group on a network interface.
 *
 * @param netif the network interface which should join a new group.
 * @param groupaddr the ipv6 address of the group to join (possibly but not
 *                  necessarily zoned)
 * @return ERR_OK if group was joined on the netif, an err_t otherwise
 */
err_t
mld6_joingroup_netif(struct netif *netif, const ip6_addr_t *groupaddr)
{
  struct mld_group *group;
#if LWIP_IPV6_SCOPES
  ip6_addr_t ip6addr;

  /* If the address has a particular scope but no zone set, use the netif to
   * set one now. Within the mld6 module, all addresses are properly zoned. */
  if (ip6_addr_lacks_zone(groupaddr, IP6_MULTICAST)) {
    ip6_addr_set(&ip6addr, groupaddr);
    ip6_addr_assign_zone(&ip6addr, IP6_MULTICAST, netif);
    groupaddr = &ip6addr;
  }
  IP6_ADDR_ZONECHECK_NETIF(groupaddr, netif);
#endif /* LWIP_IPV6_SCOPES */

  LWIP_ASSERT_CORE_LOCKED();

  /* find group or create a new one if not found */
  group = mld6_lookfor_group(netif, groupaddr);

  if (group == NULL) {
    /* Joining a new group. Create a new group entry. */
    group = mld6_new_group(netif, groupaddr);
    if (group == NULL) {
      return ERR_MEM;
    }

    /* Activate this address on the MAC layer. */
    if (netif->mld_mac_filter != NULL) {
      netif->mld_mac_filter(netif, groupaddr, NETIF_ADD_MAC_FILTER);
    }

    /* Report our membership. */
    MLD6_STATS_INC(mld6.tx_report);
#if !LWIP_IPV6_MLD_V2
    mld6_send(netif, group, ICMP6_TYPE_MLR);
    mld6_delayed_report(group, MLD6_JOIN_DELAYING_MEMBER_TMR_MS);
#endif
#if LWIP_IPV6_MLD_V2
    mld6_v2_send(netif, group, ICMP6_TYPE_MLR2);
    mld6_v2_delayed_report(group, MLD6_JOIN_DELAYING_MEMBER_TMR_MS);
#endif
  }

  /* Increment group use */
  group->use++;
  return ERR_OK;
}

/**
 * @ingroup mld6
 * Leave a group on a network interface.
 *
 * Zoning of address follows the same rules as @ref mld6_joingroup.
 *
 * @param srcaddr ipv6 address (zoned) of the network interface which should
 *                leave the group. If IP6_ADDR_ANY6, leave on all netifs
 * @param groupaddr the ipv6 address of the group to leave (possibly, but not
 *                  necessarily zoned)
 * @return ERR_OK if group was left on the netif(s), an err_t otherwise
 */
err_t
mld6_leavegroup(const ip6_addr_t *srcaddr, const ip6_addr_t *groupaddr)
{
  err_t         err = ERR_VAL; /* no matching interface */
  struct netif *netif;

  LWIP_ASSERT_CORE_LOCKED();

  /* loop through netif's */
  NETIF_FOREACH(netif) {
    /* Should we leave this interface ? */
    if (ip6_addr_isany(srcaddr) ||
        netif_get_ip6_addr_match(netif, srcaddr) >= 0) {
      err_t res = mld6_leavegroup_netif(netif, groupaddr);
      if (err != ERR_OK) {
        /* Store this result if we have not yet gotten a success */
        err = res;
      }
    }
  }

  return err;
}

/**
 * @ingroup mld6
 * Leave a group on a network interface.
 *
 * @param netif the network interface which should leave the group.
 * @param groupaddr the ipv6 address of the group to leave (possibly, but not
 *                  necessarily zoned)
 * @return ERR_OK if group was left on the netif, an err_t otherwise
 */
err_t
mld6_leavegroup_netif(struct netif *netif, const ip6_addr_t *groupaddr)
{
  struct mld_group *group;
#if LWIP_IPV6_SCOPES
  ip6_addr_t ip6addr;

  if (ip6_addr_lacks_zone(groupaddr, IP6_MULTICAST)) {
    ip6_addr_set(&ip6addr, groupaddr);
    ip6_addr_assign_zone(&ip6addr, IP6_MULTICAST, netif);
    groupaddr = &ip6addr;
  }
  IP6_ADDR_ZONECHECK_NETIF(groupaddr, netif);
#endif /* LWIP_IPV6_SCOPES */

  LWIP_ASSERT_CORE_LOCKED();

  /* find group */
  group = mld6_lookfor_group(netif, groupaddr);

  if (group != NULL) {
    /* Leave if there is no other use of the group */
    if (group->use <= 1) {
      /* Remove the group from the list */
      mld6_remove_group(netif, group);

      /* If we are the last reporter for this group */
#if !LWIP_IPV6_MLD_V2
      if (group->last_reporter_flag) {
        MLD6_STATS_INC(mld6.tx_leave);
        mld6_send(netif, group, ICMP6_TYPE_MLD);
      }
#endif
#if LWIP_IPV6_MLD_V2
      /* If we are the last reporter for this group */
      if (group->v2_last_reporter_flag) {
        MLD6_STATS_INC(mld6.tx_leave);
        mld6_v2_send(netif, group, ICMP6_TYPE_MLD);
      }
#endif

      /* Disable the group at the MAC level */
      if (netif->mld_mac_filter != NULL) {
        netif->mld_mac_filter(netif, groupaddr, NETIF_DEL_MAC_FILTER);
      }

      /* free group struct */
      memp_free(MEMP_MLD6_GROUP, group);
    } else {
      /* Decrement group use */
      group->use--;
    }

    /* Left group */
    return ERR_OK;
  }

  /* Group not found */
  return ERR_VAL;
}

/**
 * Called if a timeout for one group is reached.
 * Sends a report for this group.
 *
 * @param group an mld_group for which a timeout is reached
 */
static void
mld6_timeout(struct netif *netif, struct mld_group *group)
{
  /* If the state is MLD6_GROUP_DELAYING_MEMBER then we send a report for this group */
  if (group->group_state == MLD6_GROUP_DELAYING_MEMBER) {
    LWIP_DEBUGF(MLD6_DEBUG, ("mld6_timeout: report membership for group with address "));
    ip6_addr_debug_print_val(MLD6_DEBUG, group->group_address);
    LWIP_DEBUGF(MLD6_DEBUG, (" on if %p\n", (void *)netif));

    group->group_state = MLD6_GROUP_IDLE_MEMBER;

    MLD6_STATS_INC(mld6.tx_report);
    mld6_send(netif, group, ICMP6_TYPE_MLR);
  }
}

#if LWIP_IPV6_MLD_V2
/**
 * Called if a timeout for one group is reached.
 * Sends a report for this group.
 *
 * @param group an mld_group for which a timeout is reached
 */
static void
mld6_v2_timeout(struct netif *netif, struct mld_group *group)
{
  /* If the state is MLD6_GROUP_DELAYING_MEMBER then we send a report for this group */
  if (group->v2_group_state == MLD6_GROUP_DELAYING_MEMBER) {
    LWIP_DEBUGF(MLD6_DEBUG, ("mld6_v2_timeout: report membership for group with address "));
    ip6_addr_debug_print_val(MLD6_DEBUG, group->group_address);
    LWIP_DEBUGF(MLD6_DEBUG, (" on if %p\n", (void *)netif));

    group->v2_group_state = MLD6_GROUP_IDLE_MEMBER;

    MLD6_STATS_INC(mld6.tx_report);
    mld6_v2_send(netif, group, ICMP6_TYPE_MLR2);
  }
}
#endif /* LWIP_IPV6_MLD_V2 */

/**
 * Periodic timer for mld processing. Must be called every
 * MLD6_TMR_INTERVAL milliseconds (100).
 *
 * When a delaying member expires, a membership report is sent.
 */
void
mld6_tmr(void)
{
  struct netif *netif;

  NETIF_FOREACH(netif) {
    struct mld_group *group = netif_mld6_data(netif);

    while (group != NULL) {
      if (group->timer > 0) {
        group->timer--;
        if (group->timer == 0) {
          mld6_timeout(netif, group);
        }
      }
#if LWIP_IPV6_MLD_V2
      if (group->v2_timer > 0) {
        group->v2_timer--;
        if (group->v2_timer == 0) {
          mld6_v2_timeout(netif, group);
        }
      }
#endif
      group = group->next;
    }
  }
}

/**
 * Schedule a delayed membership report for a group
 *
 * @param group the mld_group for which "delaying" membership report
 *              should be sent
 * @param maxresp_in the max resp delay provided in the query
 */
static void
mld6_delayed_report(struct mld_group *group, u16_t maxresp_in)
{
  /* Convert maxresp from milliseconds to tmr ticks */
  u16_t maxresp = maxresp_in / MLD6_TMR_INTERVAL;
  if (maxresp == 0) {
    maxresp = 1;
  }

#ifdef LWIP_RAND
  /* Randomize maxresp. (if LWIP_RAND is supported) */
  maxresp = (u16_t)(LWIP_RAND() % maxresp);
  if (maxresp == 0) {
    maxresp = 1;
  }
#endif /* LWIP_RAND */

  /* Apply timer value if no report has been scheduled already. */
  if ((group->group_state == MLD6_GROUP_IDLE_MEMBER) ||
     ((group->group_state == MLD6_GROUP_DELAYING_MEMBER) &&
      ((group->timer == 0) || (maxresp < group->timer)))) {
    group->timer = maxresp;
    group->group_state = MLD6_GROUP_DELAYING_MEMBER;
  }
}

#if LWIP_IPV6_MLD_V2
/**
 * Schedule a delayed membership report for a group
 *
 * @param group the mld_group for which "delaying" membership report
 *              should be sent
 * @param maxresp_in the max resp delay provided in the query
 */
static void
mld6_v2_delayed_report(struct mld_group *group, u16_t maxresp_in)
{
  /* Convert maxresp from milliseconds to tmr ticks */
  u16_t maxresp = maxresp_in / MLD6_TMR_INTERVAL;
  if (maxresp >= 32768) {
    maxresp = ((maxresp & 0x0fff) | 0x1000) << (((maxresp >> 12) & 7) + 3);;
  }
  if (maxresp == 0) {
    maxresp = 1;
  }

#ifdef LWIP_RAND
  /* Randomize maxresp. (if LWIP_RAND is supported) */
  maxresp = (u16_t)(LWIP_RAND() % maxresp);
  if (maxresp == 0) {
    maxresp = 1;
  }
#endif /* LWIP_RAND */

  /* Apply timer value if no report has been scheduled already. */
  if ((group->v2_group_state == MLD6_GROUP_IDLE_MEMBER) ||
     ((group->v2_group_state == MLD6_GROUP_DELAYING_MEMBER) &&
      ((group->v2_timer == 0) || (maxresp < group->v2_timer)))) {
    group->v2_timer = maxresp;
    group->v2_group_state = MLD6_GROUP_DELAYING_MEMBER;
  }
}

#endif


/**
 * Send a MLD message (report or done).
 *
 * An IPv6 hop-by-hop options header with a router alert option
 * is prepended.
 *
 * @param group the group to report or quit
 * @param type ICMP6_TYPE_MLR (report) or ICMP6_TYPE_MLD (done)
 */
static void
mld6_send(struct netif *netif, struct mld_group *group, u8_t type)
{
  struct mld_header *mld_hdr;
  struct pbuf *p;
  const ip6_addr_t *src_addr;

  /* Allocate a packet. Size is MLD header + IPv6 Hop-by-hop options header. */
  p = pbuf_alloc(PBUF_IP, sizeof(struct mld_header) + MLD6_HBH_HLEN, PBUF_RAM);
  if (p == NULL) {
    MLD6_STATS_INC(mld6.memerr);
    return;
  }

  /* Move to make room for Hop-by-hop options header. */
  if (pbuf_remove_header(p, MLD6_HBH_HLEN)) {
    pbuf_free(p);
    MLD6_STATS_INC(mld6.lenerr);
    return;
  }

  /* Select our source address. */
  if (!ip6_addr_isvalid(netif_ip6_addr_state(netif, 0))) {
    /* This is a special case, when we are performing duplicate address detection.
     * We must join the multicast group, but we don't have a valid address yet. */
    src_addr = IP6_ADDR_ANY6;
  } else {
    /* Use link-local address as source address. */
    src_addr = netif_ip6_addr(netif, 0);
  }

  /* MLD message header pointer. */
  mld_hdr = (struct mld_header *)p->payload;

  /* Set fields. */
  mld_hdr->type = type;
  mld_hdr->code = 0;
  mld_hdr->chksum = 0;
  mld_hdr->max_resp_delay = 0;
  mld_hdr->reserved = 0;
  ip6_addr_copy_to_packed(mld_hdr->multicast_address, group->group_address);

#if CHECKSUM_GEN_ICMP6
  IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_ICMP6) {
    mld_hdr->chksum = ip6_chksum_pseudo(p, IP6_NEXTH_ICMP6, p->len,
      src_addr, &(group->group_address));
  }
#endif /* CHECKSUM_GEN_ICMP6 */

  /* Add hop-by-hop headers options: router alert with MLD value. */
  ip6_options_add_hbh_ra(p, IP6_NEXTH_ICMP6, IP6_ROUTER_ALERT_VALUE_MLD);

  if (type == ICMP6_TYPE_MLR) {
    /* Remember we were the last to report */
    group->last_reporter_flag = 1;
  }

  /* Send the packet out. */
  MLD6_STATS_INC(mld6.xmit);
  ip6_output_if(p, (ip6_addr_isany(src_addr)) ? NULL : src_addr, &(group->group_address),
      MLD6_HL, 0, IP6_NEXTH_HOPBYHOP, netif);
  pbuf_free(p);
}

#if LWIP_IPV6_MLD_V2
/**
 * Build a mld v2 record to a specific group.
 *
 * @param rec record to build
 * @param group the group to which to send the packet
 * @param fmode filter mode
 * @param src_array source addr array
 * @param src_cnt source addr cnt
 */
static void
mld_v2_build_record(struct mld_v2_record *rec, struct mld_group *group, u8_t fmode, ip6_addr_p_t *src_array, u32_t src_cnt)
{
  ip6_addr_p_t *src_copy;

  if (fmode == MCAST_EXCLUDE) {
    if (group->v2_fmode != MCAST_EXCLUDE) {
      group->v2_fmode = MCAST_EXCLUDE;
      rec->type = MLD2_CHANGE_TO_EXCLUDE;
    } else {
      rec->type = MLD2_MODE_IS_EXCLUDE;
    }

  } else {
    if (group->v2_fmode != MCAST_INCLUDE) {
      group->v2_fmode = MCAST_INCLUDE;
      rec->type = MLD2_CHANGE_TO_INCLUDE;
    } else {
      rec->type = MLD2_MODE_IS_INCLUDE;
    }
  }

  rec->aux_len = 0;
  rec->src_num = PP_HTONS(src_cnt);
  ip6_addr_copy_to_packed(rec->multicast_address, group->group_address);

  if (src_cnt) {
    src_copy = (ip6_addr_p_t *)(rec + 1);
    MEMCPY(src_copy, src_array, (src_cnt << 4));
  }
}

/**
 * Send a MLD message (report).
 *
 * An IPv6 hop-by-hop options header with a router alert option
 * is prepended.
 *
 * @param group the group to report or quit
 * @param type ICMP6_TYPE_MLR (report) or ICMP6_TYPE_MLD (done)
 */
static void
mld6_v2_send(struct netif *netif, struct mld_group *group, u8_t type)
{
  struct mld_v2_report *mld_hdr;
  struct mld_v2_record *rec;
  struct pbuf *p;
  const ip6_addr_t *src_addr;

  /* Select our source address. */
  if (!ip6_addr_isvalid(netif_ip6_addr_state(netif, 0))) {
    /* This is a special case, when we are performing duplicate address detection.
     * We must join the multicast group, but we don't have a valid address yet. */
    src_addr = IP6_ADDR_ANY6;
  } else {
    /* Use link-local address as source address. */
    src_addr = netif_ip6_addr(netif, 0);
  }

  if (ICMP6_TYPE_MLD == type) {
    p = pbuf_alloc(PBUF_IP, MLD_V2_REPORT_HLEN + MLD_V2_RECORD_LEN(0) + MLD6_HBH_HLEN, PBUF_RAM);
    if (p == NULL) {
      LWIP_DEBUGF(MLD6_DEBUG, ("mld6_v2_send: not enough memory for mld6_v2_send\n"));
      IGMP_STATS_INC(mld6.memerr);
      return;
    }

    /* Move to make room for Hop-by-hop options header. */
    if (pbuf_remove_header(p, MLD6_HBH_HLEN)) {
      pbuf_free(p);
      MLD6_STATS_INC(mld6.lenerr);
      return;
    }

    mld_hdr = (struct mld_v2_report *)p->payload;
    mld_hdr->type  = ICMP6_TYPE_MLR2;
    mld_hdr->reserved1 = 0;
    mld_hdr->chksum = 0;
    mld_hdr->reserved2 = 0;
    mld_hdr->mrec_num   = PP_HTONS(1);

    rec = (struct mld_v2_record *)(mld_hdr + 1);
    if (group->v2_fmode == MCAST_EXCLUDE) {
      rec->type = MLD2_CHANGE_TO_INCLUDE;
    } else {
      rec->type = MLD2_MODE_IS_INCLUDE;
    }
    rec->aux_len = 0;
    rec->src_num = 0; /* IS_IN (NULL) mean drop group */
    ip6_addr_copy_to_packed(rec->multicast_address, group->group_address);
  } else {/* Report a group */
    ip6_addr_p_t src_array[LWIP_MCAST_SRC_TBL_SIZE];
    u16_t src_cnt;
    u8_t fmode;

    src_cnt = mcast_ip6_filter_info(netif, &group->group_address, src_array, LWIP_MCAST_SRC_TBL_SIZE, &fmode);
    LWIP_ASSERT("mld6_v2_send: multicast filter error!", !(!src_cnt && (fmode == MCAST_INCLUDE)));

    p = pbuf_alloc(PBUF_IP, MLD_V2_REPORT_HLEN + MLD_V2_RECORD_LEN(src_cnt) + MLD6_HBH_HLEN, PBUF_RAM);
    if (p == NULL) {
      LWIP_DEBUGF(MLD6_DEBUG, ("mld6_v2_send: not enough memory for mld6_v2_send\n"));
      IGMP_STATS_INC(mld6.memerr);
      return;
    }

    mld_hdr = (struct mld_v2_report *)p->payload;
    mld_hdr->type  = ICMP6_TYPE_MLR2;
    mld_hdr->reserved1 = 0;
    mld_hdr->chksum = 0;
    mld_hdr->reserved2 = 0;
    mld_hdr->mrec_num   = PP_HTONS(1);

    rec = (struct mld_v2_record *)(mld_hdr + 1);
    mld_v2_build_record(rec, group, fmode, src_array, src_cnt);
    group->v2_last_reporter_flag = 1;/* Remember we were the last to report */
  }

 #if CHECKSUM_GEN_ICMP6
  IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_ICMP6) {
    mld_hdr->chksum = ip6_chksum_pseudo(p, IP6_NEXTH_ICMP6, p->len,
      src_addr, &(group->group_address));
  }
#endif /* CHECKSUM_GEN_ICMP6 */

  /* Add hop-by-hop headers options: router alert with MLD value. */
  ip6_options_add_hbh_ra(p, IP6_NEXTH_ICMP6, IP6_ROUTER_ALERT_VALUE_MLD);

  /* Send the packet out. */
  MLD6_STATS_INC(mld6.xmit);
  ip6_output_if(p, (ip6_addr_isany(src_addr)) ? NULL : src_addr, &(group->group_address),
      MLD6_HL, 0, IP6_NEXTH_HOPBYHOP, netif);
  pbuf_free(p);
}

/**
 * mld v2 report trigger.
 */
void
mld6_v2_trigger(struct netif *netif, const ip6_addr_t *groupaddr)
{
  struct mld_group *group;
#if LWIP_IPV6_SCOPES
    ip6_addr_t ip6addr;

    /* If the address has a particular scope but no zone set, use the netif to
     * set one now. Within the mld6 module, all addresses are properly zoned. */
    if (ip6_addr_lacks_zone(groupaddr, IP6_MULTICAST)) {
      ip6_addr_set(&ip6addr, groupaddr);
      ip6_addr_assign_zone(&ip6addr, IP6_MULTICAST, netif);
      groupaddr = &ip6addr;
    }
    IP6_ADDR_ZONECHECK_NETIF(groupaddr, netif);
#endif /* LWIP_IPV6_SCOPES */

  /* find group */
  group = mld6_lookfor_group(netif, groupaddr);
  if (group) {
    mld6_v2_send(netif, group, ICMP6_TYPE_MLR2);

    mld6_v2_delayed_report(group, MLD6_JOIN_DELAYING_MEMBER_TMR_MS);

    /* Need to work out where this timer comes from */
    group->v2_group_state = MLD6_GROUP_DELAYING_MEMBER;
  }
}
#endif

#endif /* LWIP_IPV6 */
