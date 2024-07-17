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

#ifndef __GAZELLE_RPC_PROC_H__
#define __GAZELLE_RPC_PROC_H__
#include "lstack_thread_rpc.h"

void stack_clean_epoll(struct rpc_msg *msg);
void stack_arp(struct rpc_msg *msg);
void stack_socket(struct rpc_msg *msg);
void stack_close(struct rpc_msg *msg);
void stack_shutdown(struct rpc_msg *msg);
void stack_bind(struct rpc_msg *msg);
void stack_listen(struct rpc_msg *msg);
void stack_accept(struct rpc_msg *msg);
void stack_connect(struct rpc_msg *msg);
void stack_recv(struct rpc_msg *msg);
void stack_getpeername(struct rpc_msg *msg);
void stack_getsockname(struct rpc_msg *msg);
void stack_getsockopt(struct rpc_msg *msg);
void stack_setsockopt(struct rpc_msg *msg);
void stack_fcntl(struct rpc_msg *msg);
void stack_ioctl(struct rpc_msg *msg);
void stack_tcp_send(struct rpc_msg *msg);
void stack_udp_send(struct rpc_msg *msg);
void stack_mempool_size(struct rpc_msg *msg);
void stack_rpcpool_size(struct rpc_msg *msg);
void stack_create_shadow_fd(struct rpc_msg *msg);
void stack_replenish_sendring(struct rpc_msg *msg);
void stack_get_conntable(struct rpc_msg *msg);
void stack_get_connnum(struct rpc_msg *msg);
void stack_get_mem_info(struct gazelle_stat_lstack_memory *memory);
void stack_get_total_mem(struct rpc_msg *msg);
void stack_recvlist_count(struct rpc_msg *msg);
void stack_exit_by_rpc(struct rpc_msg *msg);

void thread_register_phase1(struct rpc_msg *msg);
void thread_register_phase2(struct rpc_msg *msg);

#endif
