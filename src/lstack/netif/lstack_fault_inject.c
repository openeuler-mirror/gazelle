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

#include <securec.h>
#include <rte_gro.h>
#include <rte_net.h>

#include <lwip/posix_api.h>

#include "lstack_cfg.h"
#include "lstack_log.h"
#include "lstack_vdev.h"

#define INJECT_MODULO 1000  /* used in modulus operator */
#define INJECT_US_TO_MS 1000  /* transefer time unit us to ms */

typedef int32_t (*inject_xmit_func)(struct protocol_stack *stack, struct rte_mbuf **pkts,
                                    uint32_t nr_pkts, struct gazelle_fault_inject_data data);
struct inject_tbl {
    struct gazelle_fault_inject_data inject_data;
    inject_xmit_func inject_func;
};
static struct inject_tbl g_inject_tbl[GAZELLE_FAULT_INJECT_TYPE_MAX];

struct inject_func_tbl {
    enum GAZELLE_FAULT_INJECT_TYPE type;
    enum GAZELLE_FAULT_INJECT_RULE rule;
    inject_xmit_func inject_func;
};

static int32_t inject_packet_delay_random(struct protocol_stack *stack, struct rte_mbuf **pkts,
                                          uint32_t nr_pkts, struct gazelle_fault_inject_data data);
static int32_t inject_packet_loss_random(struct protocol_stack *stack, struct rte_mbuf **pkts,
                                         uint32_t nr_pkts, struct gazelle_fault_inject_data data);

static struct inject_func_tbl g_inject_func_tbl[] = {
    {GAZELLE_FAULT_INJECT_PACKET_LOSS,  INJECT_LOSS_RANDOM, inject_packet_loss_random},
    {GAZELLE_FAULT_INJECT_PACKET_DELAY, INJECT_DELAY_RANDOM, inject_packet_delay_random},
};

static int32_t inject_func_tbl_update()
{
    int32_t func_count = sizeof(g_inject_func_tbl) / sizeof(g_inject_func_tbl[0]);
    
    for (int32_t i = 0; i < GAZELLE_FAULT_INJECT_TYPE_MAX; ++i) {
        if (!g_inject_tbl[i].inject_data.fault_inject_on) {
            continue;
        }
        for (int32_t j = 0; j < func_count; ++j) {
            if (g_inject_func_tbl[j].type == g_inject_tbl[i].inject_data.inject_type &&
                g_inject_func_tbl[j].rule == g_inject_tbl[i].inject_data.inject_rule) {
                g_inject_tbl[i].inject_func = g_inject_func_tbl[j].inject_func;
            }
        }
    }
    return 0;
}

static uint32_t inject_tx_xmit(struct protocol_stack *stack, struct rte_mbuf **pkts, uint32_t nr_pkts)
{
    for (int32_t i = 0; i < GAZELLE_FAULT_INJECT_TYPE_MAX; ++i) {
        if (g_inject_tbl[i].inject_data.fault_inject_on) {
            int32_t xmit_pkts = 0;
            xmit_pkts =  g_inject_tbl[i].inject_func(stack, pkts, nr_pkts,
                                                     g_inject_tbl[i].inject_data);
            if (xmit_pkts == nr_pkts) {
                continue;
            }
            return xmit_pkts;
        }
    }
    if (rte_mbuf_refcnt_read(*pkts) == 1) {
        return nr_pkts;
    }
    return vdev_tx_xmit(stack, pkts, nr_pkts);
}

static int32_t inject_strategy_update()
{
    inject_func_tbl_update();
    
    int32_t inject_on = 0;
    for (int32_t i = 0; i < GAZELLE_FAULT_INJECT_TYPE_MAX; ++i) {
        if (g_inject_tbl[i].inject_data.fault_inject_on) {
            inject_on = 1;
            break;
        }
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    
    if (inject_on) {
        for (uint32_t i = 0; i < stack_group->stack_num; ++i) {
            struct protocol_stack *stack = stack_group->stacks[i];
            stack->dev_ops.tx_xmit = inject_tx_xmit;
        }
        return 0;
    }
    
    for (uint32_t i = 0; i < stack_group->stack_num; ++i) {
        struct protocol_stack *stack = stack_group->stacks[i];
        vdev_dev_ops_init(&stack->dev_ops);
    }

    return 0;
}

static int32_t inject_packet_delay_random(struct protocol_stack *stack, struct rte_mbuf **pkts,
                                          uint32_t nr_pkts, struct gazelle_fault_inject_data data)
{
    /* while *pkts->refcnt == 1, other inject type is on, and the packets have been loss. */
    if (rte_mbuf_refcnt_read(*pkts) == 1) {
        return nr_pkts;
    }
    int32_t delay_time = data.inject_data.delay.delay_time;
    int32_t delay_range = data.inject_data.delay.delay_range;
    int32_t rand_num = rte_rand();
    rand_num %= INJECT_MODULO;
    delay_time += delay_range * rand_num / INJECT_MODULO;
    rte_delay_us(delay_time * INJECT_US_TO_MS);

    return nr_pkts;
}

static int32_t inject_packet_loss_random(struct protocol_stack *stack, struct rte_mbuf **pkts,
                                         uint32_t nr_pkts, struct gazelle_fault_inject_data data)
{
    double loss_rate = data.inject_data.loss.loss_rate;
    int32_t boundary = (int32_t) (loss_rate * INJECT_MODULO);
    
    uint32_t rand_num = rte_rand();
    rand_num %= INJECT_MODULO;
    
    if (rand_num > boundary) {
        return nr_pkts;
    }
    
    for (int32_t i = 0; i < nr_pkts; ++i) {
        rte_pktmbuf_free(pkts[i]);
    }
    return nr_pkts;
}

static int32_t inject_respond_msg(int32_t sockfd)
{
    struct gazelle_stack_dfx_data rsp = {0};
    int32_t ret = 0;
    for (int32_t i = 0; i < GAZELLE_FAULT_INJECT_TYPE_MAX; ++i) {
        ret = memcpy_s(&rsp.data.inject, sizeof(struct gazelle_fault_inject_data),
                       &g_inject_tbl[i].inject_data, sizeof(struct gazelle_fault_inject_data));
        if (ret != EOK) {
            LSTACK_LOG(ERR, LSTACK, "fault inject memcpy_s error, ret = %d", ret);
            return -1;
        }
        if (i == GAZELLE_FAULT_INJECT_TYPE_MAX -1) {
            rsp.eof = 1;
        }
        ret = (int32_t) posix_api->write_fn(sockfd, (void *)&rsp, sizeof(rsp));
        if (ret <= 0) {
            LSTACK_LOG(ERR, LSTACK, "write msg from peer failed, errno %d. ret=%d\n", errno, ret);
            return -1;
        }
    }
    
    return 0;
}

static int32_t inject_unset_cmd(int32_t sockfd, struct gazelle_fault_inject_data inject)
{
    if (inject.inject_type == GAZELLE_FAULT_INJECT_TYPE_MAX) {
        /* means unset all kinds of fault inject type */
        for (int32_t i = 0; i < GAZELLE_FAULT_INJECT_TYPE_MAX; ++i) {
            g_inject_tbl[i].inject_data.fault_inject_on = 0;
        }
    } else {
        int32_t ret = 0;
        ret = memcpy_s(&g_inject_tbl[inject.inject_type].inject_data,
                       sizeof(struct gazelle_fault_inject_data),
                       &inject, sizeof(struct gazelle_fault_inject_data));
        if (ret != EOK) {
            LSTACK_LOG(ERR, LSTACK, "fault inject memcpy_s error, ret = %d", ret);
            return -1;
        }
    }

    inject_strategy_update();

    return inject_respond_msg(sockfd);
}

static int32_t inject_set_cmd(int32_t sockfd, struct gazelle_fault_inject_data inject)
{
    int32_t ret = 0;
    ret = memcpy_s(&g_inject_tbl[inject.inject_type].inject_data,
                   sizeof(struct gazelle_fault_inject_data),
                   &inject, sizeof(struct gazelle_fault_inject_data));
    if (ret != EOK) {
        LSTACK_LOG(ERR, LSTACK, "fault inject memcpy_s error, ret = %d", ret);
        return -1;
    }

    inject_strategy_update();
    
    return inject_respond_msg(sockfd);
}

int32_t handle_fault_inject_cmd(int32_t sockfd, struct gazelle_fault_inject_data inject, enum GAZELLE_STAT_MODE stat_mode)
{
    if (stat_mode == GAZELLE_STAT_FAULT_INJECT_UNSET) {
        return inject_unset_cmd(sockfd, inject);
    }
    return inject_set_cmd(sockfd, inject);
}

