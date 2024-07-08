/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* gazelle is licensed under the Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*     http://license.coscl.org.cn/MulanPSL2
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
* PURPOSE.
* See the Mulan PSL v2 for more details.
*/

#ifndef __GAZELLE_LWIP_H__
#define __GAZELLE_LWIP_H__
#include <stdbool.h>

#include "common/gazelle_dfx_msg.h"

#define NETCONN_IS_ACCEPTIN(sock)   (((sock)->conn->acceptmbox != NULL) && !sys_mbox_empty((sock)->conn->acceptmbox))
#define NETCONN_IS_DATAIN(sock)     ((gazelle_ring_readable_count((sock)->recv_ring) || (sock)->recv_lastdata) || (sock->same_node_rx_ring != NULL && same_node_ring_count(sock)))
#define NETCONN_IS_DATAOUT(sock)    (gazelle_ring_readover_count((sock)->send_ring) || (sock)->send_pre_del)
#define NETCONN_IS_OUTIDLE(sock)    gazelle_ring_readable_count((sock)->send_ring)
#define NETCONN_IS_UDP(sock)        (NETCONNTYPE_GROUP(netconn_type((sock)->conn)) == NETCONN_UDP)

struct lwip_sock;
struct rte_mempool;
struct rpc_msg;
struct rte_mbuf;
struct protocol_stack;

int do_lwip_socket(int domain, int type, int protocol);
int do_lwip_close(int32_t fd);
void do_lwip_init_sock(int32_t fd);
void do_lwip_clone_sockopt(struct lwip_sock *dst_sock, struct lwip_sock *src_sock);

struct pbuf *do_lwip_tcp_get_from_sendring(struct lwip_sock *sock, uint16_t remain_size);
struct pbuf *do_lwip_udp_get_from_sendring(struct lwip_sock *sock, uint16_t remain_size);
void do_lwip_get_from_sendring_over(struct lwip_sock *sock);
bool do_lwip_replenish_sendring(struct protocol_stack *stack, struct lwip_sock *sock);
ssize_t do_lwip_read_from_lwip(struct lwip_sock *sock, int32_t flags, uint8_t apiflags);

/* app write/read ring */
ssize_t do_lwip_sendmsg_to_stack(struct lwip_sock *sock, int32_t s,
                                 const struct msghdr *message, int32_t flags);
ssize_t do_lwip_recvmsg_from_stack(int32_t s, const struct msghdr *message, int32_t flags);

ssize_t do_lwip_send_to_stack(int32_t fd, const void *buf, size_t len, int32_t flags,
                              const struct sockaddr *addr, socklen_t addrlen);
ssize_t do_lwip_read_from_stack(int32_t fd, void *buf, size_t len, int32_t flags,
                                struct sockaddr *addr, socklen_t *addrlen);

void do_lwip_read_recvlist(struct protocol_stack *stack, uint32_t max_num);
void do_lwip_add_recvlist(int32_t fd);
int do_lwip_send(struct protocol_stack *stack, int32_t fd, struct lwip_sock *sock,
                 size_t len, int32_t flags);

uint32_t do_lwip_get_conntable(struct gazelle_stat_lstack_conn_info *conn, uint32_t max_num);
uint32_t do_lwip_get_connnum(void);

void do_lwip_free_pbuf(struct pbuf *pbuf);
struct pbuf *do_lwip_alloc_pbuf(pbuf_layer layer, uint16_t length, pbuf_type type);

void read_same_node_recv_list(struct protocol_stack *stack);

#endif
