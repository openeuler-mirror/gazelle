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

#include <unistd.h>
#include <securec.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <lwip/api.h>

#include "lstack_cfg.h"
#include "lstack_ethdev.h"
#include "posix_api.h"
#include "lstack_control_plane.h"
#include "lstack_log.h"
#include "dpdk_common.h"
#include "gazelle_dfx_msg.h"
#include "lstack_thread_rpc.h"
#include "lstack_stack_stat.h"

#define US_PER_SEC  1000000

static uint64_t g_cycles_per_us;

void stack_stat_init(void)
{
    uint64_t freq = rte_get_tsc_hz();
    g_cycles_per_us = (freq + US_PER_SEC - 1) / US_PER_SEC;
}

uint64_t get_current_time(void)
{
    if (g_cycles_per_us == 0) {
        return 0;
    }

    return (rte_rdtsc() / g_cycles_per_us);
}

void calculate_lstack_latency(struct gazelle_stack_latency *stack_latency, const struct pbuf *pbuf,
    enum GAZELLE_LATENCY_TYPE type)
{
    const uint64_t *priv = (uint64_t *)((uint8_t *)(pbuf) - GAZELLE_MBUFF_PRIV_SIZE);
    if (*priv != ~(*(priv + 1)) || *priv < stack_latency->start_time) {
        return;
    }

    uint64_t latency = get_current_time();
    latency = latency - *priv;

    struct stack_latency *latency_stat = (type == GAZELLE_LATENCY_LWIP) ?
        &stack_latency->lwip_latency : &stack_latency->read_latency;

    latency_stat->latency_total += latency;
    latency_stat->latency_max = (latency_stat->latency_max > latency) ? latency_stat->latency_max : latency;
    latency_stat->latency_min = (latency_stat->latency_min < latency) ? latency_stat->latency_min : latency;
    latency_stat->latency_pkts++;
}

static void set_latency_start_flag(bool start)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    if (start == stack_group->latency_start) {
        return;
    }

    stack_group->latency_start = start;
    if (!start) {
        return;
    }

    for (uint32_t i = 0; i < stack_group->stack_num; i++) {
        struct protocol_stack *stack = stack_group->stacks[i];
        memset_s(&stack->latency, sizeof(struct gazelle_stack_latency), 0, sizeof(stack->latency));
        stack->latency.start_time = get_current_time();
        stack->latency.lwip_latency.latency_min = ~((uint64_t)0);
        stack->latency.read_latency.latency_min = ~((uint64_t)0);
    }
}

void lstack_get_low_power_info(struct gazelle_stat_low_power_info *low_power_info)
{
    struct cfg_params *cfg = get_global_cfg_params();

    low_power_info->lpm_rx_pkts = cfg->lpm_rx_pkts;
    low_power_info->lpm_detect_ms = cfg->lpm_detect_ms;
    low_power_info->low_power_mod = cfg->low_power_mod;
    low_power_info->lpm_pkts_in_detect = cfg->lpm_pkts_in_detect;
}

static void get_stack_stats(struct gazelle_stack_dfx_data *dfx, struct protocol_stack *stack)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    dfx->loglevel = rte_log_get_level(RTE_LOGTYPE_LSTACK);
    lstack_get_low_power_info(&dfx->low_power_info);
    memcpy_s(&dfx->data.pkts, sizeof(dfx->data.pkts), &stack->stats, sizeof(dfx->data.pkts));
    dfx->data.pkts.call_alloc_fail = stack_group->call_alloc_fail;

    int32_t rpc_call_result = rpc_call_msgcnt(stack);
    dfx->data.pkts.call_msg_cnt = (rpc_call_result < 0) ? 0 : rpc_call_result;

    rpc_call_result = rpc_call_recvlistcnt(stack);
    dfx->data.pkts.recv_list = (rpc_call_result < 0) ? 0 : rpc_call_result;

    rpc_call_result = rpc_call_eventlistcnt(stack);
    dfx->data.pkts.event_list = (rpc_call_result < 0) ? 0 : rpc_call_result;

    rpc_call_result = rpc_call_sendlistcnt(stack);
    dfx->data.pkts.send_list = (rpc_call_result < 0) ? 0 : rpc_call_result;

    dfx->data.pkts.conn_num = stack->conn_num;
}

static void get_stack_dfx_data(struct gazelle_stack_dfx_data *dfx, struct protocol_stack *stack,
    enum GAZELLE_STAT_MODE stat_mode)
{
    int32_t rpc_call_result;

    switch (stat_mode) {
        case GAZELLE_STAT_LSTACK_SHOW:
        case GAZELLE_STAT_LSTACK_SHOW_RATE:
            get_stack_stats(dfx, stack);
            break;
        case GAZELLE_STAT_LSTACK_SHOW_SNMP:
            memcpy_s(&dfx->data.snmp, sizeof(dfx->data.snmp), &stack->lwip_stats->mib2,
                sizeof(stack->lwip_stats->mib2));
            break;
        case GAZELLE_STAT_LSTACK_SHOW_CONN:
            rpc_call_result = rpc_call_conntable(stack, dfx->data.conn.conn_list, GAZELLE_LSTACK_MAX_CONN);
            dfx->data.conn.conn_num = (rpc_call_result < 0) ? 0 : rpc_call_result;
            rpc_call_result = rpc_call_connnum(stack);
            dfx->data.conn.total_conn_num = (rpc_call_result < 0) ? 0 : rpc_call_result;
            break;
        case GAZELLE_STAT_LSTACK_SHOW_LATENCY:
            memcpy_s(&dfx->data.latency, sizeof(dfx->data.latency), &stack->latency, sizeof(stack->latency));
            break;
        case GAZELLE_STAT_LTRAN_START_LATENCY:
            set_latency_start_flag(true);
            break;
        case GAZELLE_STAT_LTRAN_STOP_LATENCY:
            set_latency_start_flag(false);
            break;
        default:
            break;
    }
}

static int32_t send_control_cmd_data(int32_t fd, struct gazelle_stack_dfx_data *data)
{
    ssize_t cur_size;
    uint32_t target_size = sizeof(struct gazelle_stack_dfx_data);
    char *tmp_buf = (char *)data;

    while (target_size > 0) {
        cur_size = posix_api->write_fn(fd, tmp_buf, target_size);
        if (cur_size <= 0) {
            LSTACK_LOG(ERR, LSTACK, "write msg from peer failed, errno %d.\n", errno);
            return -1;
        }

        target_size -= cur_size;
        tmp_buf += cur_size;
    }

    return 0;
}

int32_t handle_stack_cmd(int32_t fd, enum GAZELLE_STAT_MODE stat_mode)
{
    struct gazelle_stack_dfx_data dfx = {0};
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    for (uint32_t i = 0; i < stack_group->stack_num; i++) {
        struct protocol_stack *stack = stack_group->stacks[i];
        get_stack_dfx_data(&dfx, stack, stat_mode);

        if (!use_ltran() &&
            (stat_mode == GAZELLE_STAT_LTRAN_START_LATENCY || stat_mode == GAZELLE_STAT_LTRAN_STOP_LATENCY)) {
            continue;
        }

        dfx.tid = stack->tid;
        if (i == stack_group->stack_num - 1) {
            dfx.eof = 1;
        }

        if (send_control_cmd_data(fd, &dfx) != 0) {
            break;
        }
    }
    return 0;
}
