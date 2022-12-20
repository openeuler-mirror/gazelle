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

#define NETCONN_IS_ACCEPTIN(sock)   (((sock)->conn->acceptmbox != NULL) && !sys_mbox_empty((sock)->conn->acceptmbox))
#define NETCONN_IS_DATAIN(sock)     ((gazelle_ring_readable_count((sock)->recv_ring) || (sock)->recv_lastdata))
#define NETCONN_IS_DATAOUT(sock)    (gazelle_ring_readover_count((sock)->send_ring) || (sock)->send_lastdata || (sock)->send_pre_del)
#define NETCONN_IS_OUTIDLE(sock)    gazelle_ring_readable_count((sock)->send_ring)

struct lwip_sock;
struct rte_mempool;
struct rpc_msg;
struct rte_mbuf;
struct protocol_stack;
void create_shadow_fd(struct rpc_msg *msg);
void gazelle_init_sock(int32_t fd);
int32_t gazelle_socket(int domain, int type, int protocol);
void gazelle_clean_sock(int32_t fd);
struct pbuf *write_lwip_data(struct lwip_sock *sock, uint16_t remain_size, uint8_t *apiflags);
void write_lwip_over(struct lwip_sock *sock);
ssize_t write_stack_data(struct lwip_sock *sock, const void *buf, size_t len);
ssize_t read_stack_data(int32_t fd, void *buf, size_t len, int32_t flags);
ssize_t read_lwip_data(struct lwip_sock *sock, int32_t flags, uint8_t apiflags);
void read_recv_list(struct protocol_stack *stack, uint32_t max_num);
void send_stack_list(struct protocol_stack *stack, uint32_t send_max);
void add_recv_list(int32_t fd);
void stack_sendlist_count(struct rpc_msg *msg);
void get_lwip_conntable(struct rpc_msg *msg);
void get_lwip_connnum(struct rpc_msg *msg);
void stack_recvlist_count(struct rpc_msg *msg);
void stack_send(struct rpc_msg *msg);
void app_rpc_write(struct rpc_msg *msg);
int32_t gazelle_alloc_pktmbuf(struct rte_mempool *pool, struct rte_mbuf **mbufs, uint32_t num);
void gazelle_free_pbuf(struct pbuf *pbuf);
ssize_t sendmsg_to_stack(int32_t s, const struct msghdr *message, int32_t flags);
ssize_t recvmsg_from_stack(int32_t s, struct msghdr *message, int32_t flags);
ssize_t gazelle_send(int32_t fd, const void *buf, size_t len, int32_t flags);
void rpc_replenish(struct rpc_msg *msg);
void stack_mempool_size(struct rpc_msg *msg);

#endif
