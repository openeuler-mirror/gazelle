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

#ifndef __LWIPGZ_FLOW__
#define __LWIPGZ_FLOW__

#include <stdbool.h>

#include "lwipopts.h"

/*  compatible with lwip_ip_addr_type */
enum gz_ip_addr_type {
  /** IPv4 */
  GZ_ADDR_TYPE_V4 =   0U,
  /** IPv6 */
  GZ_ADDR_TYPE_V6 =   6U,
  /** IPv4+IPv6 ("dual-stack") */
  GZ_ADDR_TYPE_ANY = 46U
};

/*  compatible with ip4_addr_t */
struct gz_ip4 {
  uint32_t addr;
};

/*  compatible with ip6_addr_t */
#if LWIP_IPV6
struct gz_ip6 {
  uint32_t addr[4];
#if LWIP_IPV6_SCOPES
  uint8_t zone;
#endif /* LWIP_IPV6_SCOPES */
};
#endif /* LWIP_IPV6 */

/* gazelle ip address, compatible with ip_addr_t */
typedef struct gz_addr {
    union {
#if LWIP_IPV6
        struct gz_ip6 ip6;
#endif /* LWIP_IPV6 */
        struct gz_ip4 ip4;
    } u_addr;
    /** @ref lwip_ip_addr_type */
    uint8_t type;
} gz_addr_t;

enum reg_ring_type {
    REG_RING_TCP_LISTEN = 0,
    REG_RING_TCP_LISTEN_CLOSE,
    REG_RING_TCP_CONNECT,
    REG_RING_TCP_CONNECT_CLOSE,
    REG_RING_UDP_BIND,
    REG_RING_UDP_BIND_CLOSE,
    RING_REG_MAX,
};

struct gazelle_quintuple {
    uint32_t protocol;
    /* net byte order */
    uint16_t src_port;
    uint16_t dst_port;

    gz_addr_t src_ip;
    gz_addr_t dst_ip;
};

struct reg_ring_msg {
    enum reg_ring_type type;

    uint32_t tid;
    struct gazelle_quintuple qtuple;
};

extern int vdev_reg_xmit(enum reg_ring_type type, struct gazelle_quintuple *qtuple);
extern bool port_in_stack_queue(gz_addr_t *src_ip, gz_addr_t *dst_ip, uint16_t src_port, uint16_t dst_port);

#endif /* __LWIPGZ_FLOW__ */
