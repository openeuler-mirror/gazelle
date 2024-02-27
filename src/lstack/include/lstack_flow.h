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

#ifndef __LSTACK_FLOW_H__
#define __LSTACK_FLOW_H__

#include <rte_mbuf.h>

enum port_type {
    PORT_LISTEN,
    PORT_CONNECT,
};

enum PACKET_TRANSFER_TYPE {
    TRANSFER_KERNEL = -1,
    TRANSFER_OTHER_THREAD,
    TRANSFER_CURRENT_THREAD,
};

enum TRANSFER_MESSAGE_RESULT {
    CONNECT_ERROR = -2,
    REPLY_ERROR = -1,
    TRANSFER_SUCESS = 0,
};

int distribute_pakages(struct rte_mbuf *mbuf);
void flow_init(void);
int32_t check_params_from_primary(void);

int recv_pkts_from_other_process(int process_index, void* arg);
void transfer_delete_rule_info_to_process0(uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
void transfer_create_rule_info_to_process0(uint16_t queue_id, uint32_t src_ip,
                                           uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
void transfer_add_or_delete_listen_port_to_process0(uint16_t listen_port, uint8_t process_idx, uint8_t is_add);
void transfer_arp_to_other_process(struct rte_mbuf *mbuf);

void add_user_process_port(uint16_t dst_port, uint8_t process_idx, enum port_type type);
void delete_user_process_port(uint16_t dst_port, enum port_type type);

void gazelle_listen_thread(void *arg);

#endif
