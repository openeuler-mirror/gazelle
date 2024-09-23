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

#ifndef __LWIPGZ_SOCK_H__
#define __LWIPGZ_SOCK_H__

#include "lwip/opt.h"
#include "lwip/api.h"

#if GAZELLE_SO_SNDBUF
#include  "lwip/tcp.h"
#endif /* GAZELLE_SO_SNDBUF */

#if GAZELLE_ENABLE
#include <semaphore.h>
#include <rte_common.h>
#include <rte_memzone.h>
#include "lwipgz_event.h"

enum posix_type {
  POSIX_KERNEL  = 0x100,
  POSIX_LWIP    = 0x200,
  POSIX_EPOLL   = 0x400,
  POSIX_ALL     = POSIX_KERNEL | POSIX_LWIP | POSIX_EPOLL,
  POSIX_LWIP_OR_KERNEL = POSIX_LWIP | POSIX_KERNEL,
};

#define POSIX_SET_TYPE(sock, posix_type)  do { \
  (sock)->type &= ~(POSIX_ALL);                \
  (sock)->type |= (posix_type);           } while (0)

#define POSIX_HAS_TYPE(sock, posix_type) \
  ((sock)->type & (posix_type))

#define POSIX_IS_TYPE(sock, posix_type) \
  (((sock)->type & POSIX_ALL) == (posix_type))

/* CLOSED means not lwip sock-fd, such as kernel sock-fd or file-fd or unix-fd */
#define POSIX_IS_CLOSED(sock) \
  ((sock) == NULL || (sock)->conn == NULL)

struct lwip_sock *lwip_get_socket(int fd);
int gazelle_alloc_socket(struct netconn *newconn, int accepted, int flags);
void gazelle_free_socket(struct lwip_sock *sock, int fd);
void lwip_sock_init(void);
void lwip_exit(void);

extern int do_lwip_init_sock(int fd);
extern void do_lwip_clean_sock(int fd);

extern void do_lwip_add_recvlist(int32_t fd);
extern void do_lwip_connected_callback(struct netconn *conn);

extern struct pbuf *do_lwip_udp_get_from_sendring(struct lwip_sock *sock, uint16_t remain_size);
extern struct pbuf *do_lwip_tcp_get_from_sendring(struct lwip_sock *sock, uint16_t remain_size);
extern void do_lwip_get_from_sendring_over(struct lwip_sock *sock);
extern ssize_t do_lwip_read_from_lwip(struct lwip_sock *sock, int32_t flags, u8_t apiflags);

struct sock_time_stamp {
    uint64_t rpc_time_stamp;
    uint64_t mbox_time_stamp;
};
extern void lstack_calculate_aggregate(int type, uint32_t len);
extern void time_stamp_transfer_pbuf(struct pbuf *pbuf_old, struct pbuf *pbuf_new);
extern void time_stamp_record(int fd, struct pbuf *pbuf);

// 8M
#define SAME_NODE_RING_LEN (unsigned long long)(8388608)
#define SAME_NODE_RING_MASK (unsigned long long)(8388608 - 1)
#define RING_NAME_LEN 32
struct same_node_ring {
    const struct rte_memzone *mz;
    unsigned long long sndbegin;
    unsigned long long sndend;
};
extern err_t same_node_ring_create(struct rte_ring **ring, int size, int port, char *name, char *rx);
extern err_t create_same_node_ring(struct tcp_pcb *pcb);
extern err_t find_same_node_ring(struct tcp_pcb *pcb);
extern err_t find_same_node_memzone(struct tcp_pcb *pcb, struct lwip_sock *nsock);

#endif /* GAZELLE_ENABLE */


/* move some definitions to the lwipgz_sock.h for libnet to use, and
 * at the same time avoid conflict between lwip/sockets.h and sys/socket.h
 */

/* --------------------------------------------------
 * the following definition is copied from lwip/priv/tcpip_priv.h
 * --------------------------------------------------
 */

/** This is overridable for the rare case where more than 255 threads
 * select on the same socket...
 */
#ifndef SELWAIT_T
#define SELWAIT_T u8_t
#endif

union lwip_sock_lastdata {
  struct netbuf *netbuf;
  struct pbuf *pbuf;
};

/** Contains all internal pointers and states used for a socket */
struct lwip_sock {
  /** sockets currently are built on netconns, each socket has one netconn */
  struct netconn *conn;
  /** data that was left from the previous read */
  union lwip_sock_lastdata lastdata;
#if LWIP_SOCKET_SELECT || LWIP_SOCKET_POLL
  /** number of times data was received, set by event_callback(),
      tested by the receive and select functions */
  s16_t rcvevent;
  /** number of times data was ACKed (free send buffer), set by event_callback(),
      tested by select */
  u16_t sendevent;
  /** error happened for this socket, set by event_callback(), tested by select */
  u16_t errevent;
  /** counter of how many threads are waiting for this socket using select */
  SELWAIT_T select_waiting;
#endif /* LWIP_SOCKET_SELECT || LWIP_SOCKET_POLL */
#if LWIP_NETCONN_FULLDUPLEX
  /* counter of how many threads are using a struct lwip_sock (not the 'int') */
  u8_t fd_used;
  /* status of pending close/delete actions */
  u8_t fd_free_pending;
#define LWIP_SOCK_FD_FREE_TCP  1
#define LWIP_SOCK_FD_FREE_FREE 2
#endif

#if GAZELLE_ENABLE
  char pad0 __rte_cache_aligned;
  /* app thread use */
  struct pbuf *recv_lastdata; /* unread data in one pbuf */
  uint16_t remain_len;
  uint32_t epoll_events; /* registered events, EPOLLONESHOT write frequently */
  volatile uint32_t events; /* available events */
  struct list_node event_list;

  char pad1 __rte_cache_aligned;
  /* app and stack thread all use */
  uint32_t call_num; /* avoid sock too much send rpc msg*/
  char pad2 __rte_cache_aligned;
  /* stack thread all use */
  struct list_node recv_list;
  struct pbuf *send_pre_del;
  sem_t snd_ring_sem;

  char pad3 __rte_cache_aligned;
  /* nerver change */
  enum posix_type type;
  struct lwip_sock *listen_next; /* listenfd list */
  struct protocol_stack *stack;
  struct wakeup_poll *wakeup;
  epoll_data_t ep_data;
  struct rte_ring *recv_ring;
  struct rte_ring *send_ring;

  /* same node send data ring */
  struct same_node_ring *same_node_rx_ring;
  const struct rte_memzone *same_node_rx_ring_mz;
  struct same_node_ring *same_node_tx_ring;
  const struct rte_memzone *same_node_tx_ring_mz;
  uint8_t already_bind_numa;

  struct sock_time_stamp stamp;
#endif /* GAZELLE_ENABLE */
};

#if GAZELLE_SO_SNDBUF
void netconn_set_sndbufsize(struct netconn *conn, tcpwnd_size_t sndbufsize);
#define netconn_get_sndbufsize(conn)                ((conn)->pcb.tcp->snd_buf_max)
#endif /* GAZELLE_SO_SNDBUF */

#endif /* __LWIPGZ_SOCK_H__ */
