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

#define SOCK_RECV_RING_SIZE     (128)
#define SOCK_SEND_RING_SIZE     (128)

/* flags define last type PBUF_FLAG_TCP_FIN 0x20U in pbuf.h  */
#define PBUF_FLAG_SND_SAVE_CPY   0x40U

#define NETCONN_IS_ACCEPTIN(sock) (((sock)->conn->acceptmbox != NULL) && !sys_mbox_empty((sock)->conn->acceptmbox))

void get_sockaddr_by_fd(struct sockaddr_in *addr, struct lwip_sock *sock);
void listen_list_add_node(int32_t head_fd, int32_t add_fd);
void gazelle_init_sock(int32_t fd);
void gazelle_clean_sock(int32_t fd);
uint32_t stack_send(int32_t fd, int32_t flags);
ssize_t read_stack_data(int32_t fd, void *buf, size_t len, int32_t flags);
ssize_t write_stack_data(int32_t fd, const void *buf, size_t len);
ssize_t read_lwip_data(struct lwip_sock *sock, int32_t flags, u8_t apiflags);
void read_recv_list(void);
void add_recv_list(int32_t fd);
void get_lwip_conntable(struct rpc_msg *msg);
void get_lwip_connnum(struct rpc_msg *msg);
void stack_add_event(struct rpc_msg *msg);
void stack_recvlist_count(struct rpc_msg *msg);
void stack_replenish_send_idlembuf(struct protocol_stack *stack);

#endif
