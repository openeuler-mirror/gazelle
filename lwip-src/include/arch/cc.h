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

#ifndef __LWIP_ARCH_CC_H__
#define __LWIP_ARCH_CC_H__

#include "lwipgz_log.h"

#ifndef LWIP_RAND
#define LWIP_RAND()     ((uint32_t)rand())
#endif

#define LWIP_NOASSERT

#define LWIP_ERRNO_STDINCLUDE 1

#define LWIP_DECLARE_MEMORY_ALIGNED(variable_name, size) \
  static PER_THREAD u8_t *variable_name;

#define LWIP_MEMORY_INIT_VAR(name, size) do { \
  name = sys_hugepage_malloc(#name, size);    \
  if (name == NULL)                           \
    return;                                   \
} while(0)


#define LWIP_MEMPOOL_DECLARE(name,num,size,desc)            \
  LWIP_DECLARE_MEMORY_ALIGNED(memp_memory_ ## name ## _base, 0); \
  static PER_THREAD struct stats_mem memp_stat_ ## name;    \
  static PER_THREAD struct memp *memp_tab_ ## name;         \
                                                            \
  PER_THREAD struct memp_desc memp_ ## name;

#define LWIP_MEMPOOL_INIT_VAR(name,num,size,desc) do {  \
  memp_memory_ ## name ## _base = sys_hugepage_malloc(#name, LWIP_MEM_ALIGN_BUFFER((num) * (MEMP_SIZE + MEMP_ALIGN_SIZE(size)))); \
  if (memp_memory_ ## name ## _base == NULL)                \
    return;                                                 \
  sys_mempool_var_init(&memp_ ## name,                      \
                       desc, size, num,                     \
                       memp_memory_ ## name ## _base,       \
                       &memp_tab_ ## name,                  \
                       &memp_stat_ ## name);                \
  memp_pools[MEMP_ ## name] = &memp_ ## name;               \
} while(0)

#endif /* _LWIP_ARCH_CC_H_ */
