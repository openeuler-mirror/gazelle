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

#ifndef __LIBOS_LWIP_H__
#define __LIBOS_LWIP_H__

#include "lstack_thread_rpc.h"
#include "lwipsock.h"

#define SOCK_RECV_RING_SIZE     (128)
#define SOCK_SEND_RING_SIZE     (32)

#define NETCONN_IS_ACCEPTIN(sock)   (((sock)->conn->acceptmbox != NULL) && !sys_mbox_empty((sock)->conn->acceptmbox))
#define NETCONN_IS_DATAIN(sock)     ((rte_ring_count((sock)->recv_ring) || (sock)->recv_lastdata))
#define NETCONN_IS_DATAOUT(sock)    rte_ring_free_count((sock)->send_ring)

void create_shadow_fd(struct rpc_msg *msg);
void listen_list_add_node(int32_t head_fd, int32_t add_fd);
void gazelle_init_sock(int32_t fd);
void gazelle_clean_sock(int32_t fd);
ssize_t write_lwip_data(struct lwip_sock *sock, int32_t fd, int32_t flags);
ssize_t write_stack_data(struct lwip_sock *sock, const void *buf, size_t len);
ssize_t read_stack_data(int32_t fd, void *buf, size_t len, int32_t flags);
ssize_t read_lwip_data(struct lwip_sock *sock, int32_t flags, u8_t apiflags);
void read_recv_list(void);
void add_recv_list(int32_t fd);
void stack_eventlist_count(struct rpc_msg *msg);
void stack_wakeuplist_count(struct rpc_msg *msg);
void get_lwip_conntable(struct rpc_msg *msg);
void get_lwip_connnum(struct rpc_msg *msg);
void stack_recvlist_count(struct rpc_msg *msg);
void stack_replenish_send_idlembuf(struct protocol_stack *stack);
int32_t gazelle_alloc_pktmbuf(struct rte_mempool *pool, struct rte_mbuf **mbufs, uint32_t num);
void gazelle_free_pbuf(struct pbuf *pbuf);
ssize_t sendmsg_to_stack(int32_t s, const struct msghdr *message, int32_t flags);
ssize_t recvmsg_from_stack(int32_t s, struct msghdr *message, int32_t flags);
ssize_t gazelle_send(int32_t fd, const void *buf, size_t len, int32_t flags);
void add_self_event(struct lwip_sock *sock, uint32_t events);

#endif
