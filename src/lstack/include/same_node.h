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

#ifndef __GAZELLE_SAME_NODE_H__
#define __GAZELLE_SAME_NODE_H__

#include <lwip/lwipgz_sock.h>

#if GAZELLE_SAME_NODE

unsigned same_node_ring_count(const struct lwip_sock *sock);

void read_same_node_recv_list(struct protocol_stack *stack);
ssize_t gazelle_same_node_ring_recv(struct lwip_sock *sock, const void *buf, size_t len, int32_t flags);
ssize_t gazelle_same_node_ring_send(struct lwip_sock *sock, const void *buf, size_t len, int32_t flags);

#define NETCONN_NEED_SAME_NODE(sock)     \
    ( (sock->same_node_rx_ring && same_node_ring_count(sock)) )

#else /* GAZELLE_SAME_NODE */

#define NETCONN_NEED_SAME_NODE(sock) false

#endif /* GAZELLE_SAME_NODE */

#endif /* __GAZELLE_SAME_NODE_H__ */
