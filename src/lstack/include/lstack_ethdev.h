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

#ifndef __GAZELLE_ETHDEV_H__
#define __GAZELLE_ETHDEV_H__

#define INVAILD_PROCESS_IDX 255

enum port_type {
    PORT_LISTEN,
    PORT_CONNECT,
};

enum PACKET_TRANSFER_TYPE{
    TRANSFER_KERNEL = -1,
    TRANSFER_OTHER_THREAD,
    TRANSFER_CURRENT_THREAD, 
};

enum TRANSFER_MESSAGE_RESULT {
    CONNECT_ERROR = -2,
    REPLY_ERROR = -1,
    TRANSFER_SUCESS = 0,
};

struct protocol_stack;
struct rte_mbuf;
struct lstack_dev_ops {
    uint32_t (*rx_poll)(struct protocol_stack *stack, struct rte_mbuf **pkts, uint32_t max_mbuf);
    uint32_t (*tx_xmit)(struct protocol_stack *stack, struct rte_mbuf **pkts, uint32_t nr_pkts);
};

int32_t ethdev_init(struct protocol_stack *stack);
int32_t eth_dev_poll(void);
int32_t gazelle_eth_dev_poll(struct protocol_stack *stack, uint8_t use_ltran_flag, uint32_t nic_read_number);
void eth_dev_recv(struct rte_mbuf *mbuf, struct protocol_stack *stack);

int recv_pkts_from_other_process(int process_index, void* arg);
void create_flow_rule_map();
void kni_handle_rx(uint16_t port_id);
void delete_user_process_port(uint16_t dst_port, enum port_type type);
void add_user_process_port(uint16_t dst_port, uint8_t process_idx, enum port_type type);
void delete_flow_director(uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
void config_flow_director(uint16_t queue_id, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
void netif_poll(struct netif *netif);

#endif /* __GAZELLE_ETHDEV_H__ */
