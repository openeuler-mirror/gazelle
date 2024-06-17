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

#include "lwip/sockets.h"
#include "lstack_cfg.h"
#include "lstack_protocol_stack.h"
#include "lstack_tx_cache.h"

void stack_send_pkts(struct protocol_stack *stack)
{
    if (!get_global_cfg_params()->send_cache_mode) {
        return;
    }

    uint32_t send_num = stack->tx_cache.send_end - stack->tx_cache.send_start;

    if (send_num == 0) {
        return;
    }

    uint32_t start = stack->tx_cache.send_start & STACK_SEND_MASK;
    uint32_t end = stack->tx_cache.send_end & STACK_SEND_MASK;
    uint32_t sent_pkts = 0;

    if (start < end) {
        sent_pkts = stack->dev_ops.tx_xmit(stack, &stack->tx_cache.send_pkts[start], send_num);
    } else {
        send_num = STACK_SEND_MAX - start;
        sent_pkts = stack->dev_ops.tx_xmit(stack, &stack->tx_cache.send_pkts[start], send_num);
        if (sent_pkts == send_num) {
            sent_pkts += stack->dev_ops.tx_xmit(stack, stack->tx_cache.send_pkts, end);
        }
    }

    stack->tx_cache.send_start += sent_pkts;
    stack->stats.tx += sent_pkts;
}

