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

#ifndef __LWIPGZ_EVENT_H__
#define __LWIPGZ_EVENT_H__

#include <sys/epoll.h>

#include "arch/sys_arch.h"
#include "lwip/api.h"
#include "lwipgz_list.h"

#define MAX_EPOLLFDS 32

#define LIBOS_EPOLLNONE (0x0)
#define LIBOS_BADEP     (NULL)

struct event_queue {
    struct list_node events;
    /* total number of sockets have events */
    int num_events;
};

struct event_array {
    sys_mbox_t mbox;
    volatile int num_events;
    struct epoll_event events[0];
};

struct libos_epoll {
    struct event_queue *libos_queue;
    int num_hostfds;
    int hints;
    int fd;  /* self fd */
    int efd; /* eventfd */
};

struct lwip_sock;
extern void add_sock_event(struct lwip_sock *sock, uint32_t event);
extern void add_sock_event_nolock(struct lwip_sock *sock, uint32_t event);
extern void del_sock_event(struct lwip_sock *sock, uint32_t event);
extern void del_sock_event_nolock(struct lwip_sock *sock, uint32_t event);

extern int32_t lstack_epoll_close(int32_t);

#endif /* __LWIPGZ_EVENT_H__ */
