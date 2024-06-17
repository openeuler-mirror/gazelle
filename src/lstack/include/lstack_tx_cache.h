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

#ifndef _LSTACK_TX_CACHE_H_
#define _LSTACK_TX_CACHE_H_

#define STACK_SEND_MAX              (2048)
#define STACK_SEND_MASK             (STACK_SEND_MAX - 1)
#define STACK_SEND_INDEX(index)     ((index) & STACK_SEND_MASK)

struct lstack_tx_cache {
    uint32_t send_start;
    uint32_t send_end;
    struct rte_mbuf *send_pkts[STACK_SEND_MAX];
};

void stack_send_pkts(struct protocol_stack *stack);

#endif /* _LSTACK_TX_CACHE_H_ */
