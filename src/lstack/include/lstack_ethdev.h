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

#include <lwip/ip_addr.h>
#include <lwip/netif.h>

#include "gazelle_dfx_msg.h"
#include "lstack_protocol_stack.h"

#define RTE_TEST_TX_DESC_DEFAULT 512
#define RTE_TEST_RX_DESC_DEFAULT 128

#define DPDK_PKT_BURST_SIZE 512

struct eth_dev_ops {
    uint32_t (*rx_poll)(struct protocol_stack *stack, struct rte_mbuf **pkts, uint32_t max_mbuf);
    uint32_t (*tx_xmit)(struct protocol_stack *stack, struct rte_mbuf **pkts, uint32_t nr_pkts);
};

int32_t ethdev_init(struct protocol_stack *stack);
int32_t eth_dev_poll(void);
uint32_t eth_get_flow_cnt(void);
void eth_dev_recv(struct rte_mbuf *mbuf);

#endif /* __GAZELLE_ETHDEV_H__ */
