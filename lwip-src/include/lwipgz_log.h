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

#ifndef __LWIPGZ_LOG__
#define __LWIPGZ_LOG__

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <rte_log.h>

#include "lwipopts.h"

#define set_errno(err) do { errno = (err); } while(0)

#if GAZELLE_USE_DPDK_LOG

#define LWIP_LOG_WARN    LWIP_DBG_LEVEL_WARNING
#define LWIP_LOG_ERROR   LWIP_DBG_LEVEL_SERIOUS
#define LWIP_LOG_FATAL   LWIP_DBG_LEVEL_SEVERE
#define RTE_LOGTYPE_LWIP RTE_LOGTYPE_USER2

#define LWIP_PLATFORM_LOG(level, fmt, ...) \
do { \
    if ((level) & LWIP_LOG_FATAL) { \
        RTE_LOG(ERR, LWIP, fmt, ##__VA_ARGS__); \
        abort();                             \
    } else if ((level) & LWIP_LOG_ERROR) { \
        RTE_LOG(ERR, LWIP, fmt, ##__VA_ARGS__); \
    } else if ((level) & LWIP_LOG_WARN) { \
        RTE_LOG(WARNING, LWIP, fmt, ##__VA_ARGS__); \
    } else { \
        RTE_LOG(INFO, LWIP, fmt, ##__VA_ARGS__); \
    } \
} while(0)


#define LWIP_PLATFORM_DIAG(x)

#define ESC_ARGS(...) __VA_ARGS__
#define STRIP_BRACES(args) args

#define LWIP_PLATFORM_ASSERT(x) \
do { LWIP_PLATFORM_LOG(LWIP_LOG_FATAL, "Assertion \"%s\" failed at line %d in %s\n", \
     x, __LINE__, __FILE__); abort();} while(0)

#else /* GAZELLE_USE_DPDK_LOG */

#define LWIP_PLATFORM_LOG(debug, message)

#endif /* GAZELLE_USE_DPDK_LOG */

#endif /* __LWIPGZ_LOG__ */
