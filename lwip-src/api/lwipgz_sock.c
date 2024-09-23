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

#include <sys/socket.h>
#include <fcntl.h>

#include "lwipgz_sock.h"
#include "lwipgz_posix_api.h"
#include "lwip/tcp.h"

extern struct lwip_sock *sockets;

static int socket_sys_type(enum netconn_type type)
{
  int sys_type;
  switch (NETCONNTYPE_GROUP(type)) {
    case NETCONN_RAW:
      sys_type = SOCK_RAW;
      break;
    case NETCONN_UDPLITE:
    case NETCONN_UDP:
      sys_type = SOCK_DGRAM;
      break;
    case NETCONN_TCP:
      sys_type = SOCK_STREAM;
      break;
    default:
      sys_type = -1;
      break;
  }
  return sys_type;
}

static int socket_new_sysfd(struct netconn *newconn, int flags)
{
  int domain = NETCONNTYPE_ISIPV6(newconn->type) ? AF_INET6 : AF_INET;
  int protocol = 0;
  int type = socket_sys_type(newconn->type) | flags;

  return posix_api->socket_fn(domain, type, protocol);
}

/* reference tag: alloc_socket() */
int gazelle_alloc_socket(struct netconn *newconn, int accepted, int flags)
{
  int fd;
  struct lwip_sock *sock;

  /* only support SOCK_CLOEXEC and SOCK_NONBLOCK */
  if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)){
    set_errno(EINVAL);
    return -1;
  }
  if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
    flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

  fd = socket_new_sysfd(newconn, flags);
  if (fd < 0)
    return -1;
  sock = lwip_get_socket(fd);
  if (sock == NULL)
    goto out;

  sock->conn       = newconn;
  sock->lastdata.pbuf = NULL;
#if LWIP_SOCKET_SELECT || LWIP_SOCKET_POLL
  LWIP_ASSERT("sock->select_waiting == 0", sock->select_waiting == 0);
  sock->rcvevent   = 0;
  /* TCP sendbuf is empty, but the socket is not yet writable until connected
   * (unless it has been created by accept()). */
  sock->sendevent  = (NETCONNTYPE_GROUP(newconn->type) == NETCONN_TCP ? (accepted != 0) : 1);
  sock->errevent   = 0;
#endif /* LWIP_SOCKET_SELECT || LWIP_SOCKET_POLL */

  if (do_lwip_init_sock(fd) != 0)
    goto out;

  if (accepted) {
    int ret = 0;
    struct tcp_pcb *pcb = newconn->pcb.tcp;
    if (pcb != NULL && pcb->client_rx_ring != NULL && pcb->client_tx_ring != NULL) {
        ret = find_same_node_memzone(pcb, sock);
    }
    if (pcb == NULL || ret != 0) {
        goto out;
    }
  }

  netconn_set_nonblocking(newconn, flags & SOCK_NONBLOCK);
  return fd;

out:
  if (sock != NULL)
    sock->conn = NULL;
  posix_api->close_fn(fd);
  return -1;
}

/* reference tag: free_socket() */
void gazelle_free_socket(struct lwip_sock *sock, int fd)
{
  do_lwip_clean_sock(fd);
  posix_api->close_fn(fd);
}

void lwip_sock_init(void)
{
  if (unlikely(sockets == NULL)) {
    sockets = calloc(MEMP_NUM_NETCONN, sizeof(struct lwip_sock));
    LWIP_ASSERT("sockets != NULL", sockets != NULL);
    memset(sockets, 0, MEMP_NUM_NETCONN * sizeof(struct lwip_sock));
  }
  return;
}

void lwip_exit(void)
{
  /*
   * LwIP has the following two parts of memory application, but
   * it is unnecessary to release all memory in sequentially,
   * which increases complexity. Therefore, we rely on the process
   * reclamation mechanism of the system to release memory.
   * 1. a sockets table of the process.
   * 2. a batch of hugepage memory of each thread.
   */
  return;
}

#if GAZELLE_SO_SNDBUF
void netconn_set_sndbufsize(struct netconn *conn, tcpwnd_size_t sndbufsize)
{
  struct tcp_pcb *tcp = conn->pcb.tcp;
  
  if (sndbufsize > TCP_SND_BUF_MAX) {
    LWIP_DEBUGF(GAZELLE_DEBUG_WARNING,
                ("netconn_set_sndbufsize: setting sndbufsize exceed TCP_SND_BUF_MAX. "
                 "sndbufsize=%u, snd_buf_max=%u", sndbufsize, TCP_SND_BUF_MAX));
    return;
  }
  if (sndbufsize >= tcp->snd_buf_max) {
    tcp->snd_buf += sndbufsize - tcp->snd_buf_max;
    tcp->snd_buf_max = sndbufsize;
    return;
  }
  /* remaining snd_buf less than the mount to be reduced */
  if (tcp->snd_buf < tcp->snd_buf_max - sndbufsize) {
    LWIP_DEBUGF(GAZELLE_DEBUG_WARNING,
                ("netconn_set_sndbufsize: setting sndbufsize too small. "
                 "snd_buf available is %u, need reduce is %u\n", tcp->snd_buf,
                 tcp->snd_buf_max - sndbufsize));
    return;
  }
  tcp->snd_buf -= tcp->snd_buf_max - sndbufsize;
  tcp->snd_buf_max = sndbufsize;
  return;
}
#endif /* GAZELLE_SO_SNDBUF */
