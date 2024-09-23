/**
 * @file
 * MLD6 protocol definitions
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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#ifndef LWIP_HDR_PROT_MLD6_H
#define LWIP_HDR_PROT_MLD6_H

#include "lwip/arch.h"
#include "lwip/prot/ip6.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MLD6_HBH_HLEN 8
/** Multicast listener report/query/done message header. */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct mld_header {
  PACK_STRUCT_FLD_8(u8_t type);
  PACK_STRUCT_FLD_8(u8_t code);
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u16_t max_resp_delay);
  PACK_STRUCT_FIELD(u16_t reserved);
  PACK_STRUCT_FLD_S(ip6_addr_p_t multicast_address);
  /* Options follow. */
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

#if LWIP_IPV6_MLD_V2 /* RFC 3810 */
/**
 * MLDv2 query packet format.
 */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
  PACK_STRUCT_BEGIN
  struct mld_v2_query {
    PACK_STRUCT_FLD_8(u8_t         type);
    PACK_STRUCT_FLD_8(u8_t code);
    PACK_STRUCT_FIELD(u16_t chksum);
    PACK_STRUCT_FIELD(u16_t max_resp_delay);
    PACK_STRUCT_FIELD(u16_t reserved);
    PACK_STRUCT_FLD_S(ip6_addr_t multicast_address);
    PACK_STRUCT_FLD_8(u8_t         resv_s_qrv);
    PACK_STRUCT_FLD_8(u8_t         qqic);
    PACK_STRUCT_FIELD(u16_t        src_num);
  } PACK_STRUCT_STRUCT;
  PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

#define MLD_V2_QUERY_HLEN  sizeof(struct mld_v2_query)

/**
 * MLDv2 report packet header format.
 */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
  PACK_STRUCT_BEGIN
  struct mld_v2_report {
    PACK_STRUCT_FLD_8(u8_t         type);
    PACK_STRUCT_FLD_8(u8_t         reserved1);
    PACK_STRUCT_FIELD(u16_t        chksum);
    PACK_STRUCT_FIELD(u16_t        reserved2);
    PACK_STRUCT_FIELD(u16_t        mrec_num);
  } PACK_STRUCT_STRUCT;
  PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

#define MLD_V2_REPORT_HLEN  sizeof(struct mld_v2_report)

/*
 * Definitions for MLDv2
 */
#define MLD2_MODE_IS_INCLUDE    1
#define MLD2_MODE_IS_EXCLUDE    2
#define MLD2_CHANGE_TO_INCLUDE  3
#define MLD2_CHANGE_TO_EXCLUDE  4
#define MLD2_ALLOW_NEW_SOURCES  5
#define MLD2_BLOCK_OLD_SOURCES  6

/**
 * MLDv2 report packet group record format.
 */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
  PACK_STRUCT_BEGIN
  struct mld_v2_record {
    PACK_STRUCT_FLD_8(u8_t         type);
    PACK_STRUCT_FLD_8(u8_t         aux_len);
    PACK_STRUCT_FIELD(u16_t        src_num);
    PACK_STRUCT_FLD_S(ip6_addr_p_t multicast_address);
  } PACK_STRUCT_STRUCT;
  PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

#define MLD_V2_RECORD_LEN(src_cnt)  (sizeof(struct mld_v2_record) + (src_cnt << 4))
#endif /* LWIP_IPV6_MLD_V2 */


#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_PROT_MLD6_H */
