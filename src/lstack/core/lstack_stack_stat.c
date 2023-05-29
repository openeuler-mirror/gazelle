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
#include <lwip/gazelle_posix_api.h>

#include "lstack_cfg.h"
#include "lstack_ethdev.h"
#include "lstack_control_plane.h"
#include "lstack_log.h"
#include "common/dpdk_common.h"
#include "common/gazelle_dfx_msg.h"
#include "lstack_thread_rpc.h"
#include "lstack_protocol_stack.h"
#include "posix/lstack_epoll.h"
#include "lstack_dpdk.h"
#include "lstack_stack_stat.h"

void calculate_lstack_latency(struct gazelle_stack_latency *stack_latency, const struct pbuf *pbuf,
    enum GAZELLE_LATENCY_TYPE type)
{
    uint64_t latency;
    const struct latency_timestamp *lt;

    if (pbuf == NULL) {
        return;
    }

    lt = &pbuf_to_private(pbuf)->lt;
    if (lt->stamp != ~(lt->check) || lt->stamp < stack_latency->start_time) {
        return;
    }
    latency = get_now_us() - lt->stamp;

    struct stack_latency *latency_stat = (type == GAZELLE_LATENCY_LWIP) ?
        &stack_latency->lwip_latency : &stack_latency->read_latency;

    latency_stat->latency_total += latency;
    latency_stat->latency_max = (latency_stat->latency_max > latency) ? latency_stat->latency_max : latency;
    latency_stat->latency_min = (latency_stat->latency_min < latency) ? latency_stat->latency_min : latency;
    latency_stat->latency_pkts++;
}

void lstack_calculate_aggregate(int type, uint32_t len)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    if (stack_group->latency_start) {
        struct protocol_stack *stack = get_protocol_stack();
        if (type == 1) {
            stack->aggregate_stats.tx_bytes  += len;
        } else if (type == 0) {
            stack->aggregate_stats.rx_bytes  += len;
        }

        if (len <= 64) {
            stack->aggregate_stats.size_1_64[type]++;
        } else if (len <= 512) {
            stack->aggregate_stats.size_65_512[type]++;
        } else if (len <= 1460) {
            stack->aggregate_stats.size_513_1460[type]++;
        } else if (len <= 8192) {
            stack->aggregate_stats.size_1461_8192[type]++;
        } else {
            stack->aggregate_stats.size_8193_max[type]++;
        }
    }
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
        int32_t ret = memset_s(&stack->latency, sizeof(struct gazelle_stack_latency), 0, sizeof(stack->latency));
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "memset_s faile\n");
        }
        stack->latency.start_time = get_now_us();
        stack->latency.lwip_latency.latency_min = ~((uint64_t)0);
        stack->latency.read_latency.latency_min = ~((uint64_t)0);
        memset_s(&stack->aggregate_stats, sizeof(struct gazelle_stack_aggregate_stats),
            0, sizeof(stack->aggregate_stats));
    }
}

static void get_wakeup_stat(struct protocol_stack_group *stack_group, struct protocol_stack *stack,
    struct gazelle_wakeup_stat *stat)
{
    struct wakeup_poll *wakeup;
    struct list_node *node, *next;

    pthread_spin_lock(&stack_group->poll_list_lock);

    list_for_each_node(node, next, &stack_group->poll_list) {
        wakeup = list_entry(node, struct wakeup_poll, poll_list);

        if (wakeup->bind_stack == stack) {
            stat->app_events += wakeup->stat.app_events;
            stat->read_null += wakeup->stat.read_null;
            stat->app_write_cnt += wakeup->stat.app_write_cnt;
            stat->app_write_rpc += wakeup->stat.app_write_rpc;
            stat->app_read_cnt += wakeup->stat.app_read_cnt;
        }
    }

    pthread_spin_unlock(&stack_group->poll_list_lock);
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

    int32_t ret = memcpy_s(&dfx->data.pkts.stack_stat, sizeof(struct gazelle_stack_stat),
        &stack->stats, sizeof(struct gazelle_stack_stat));
    if (ret != EOK) {
        LSTACK_LOG(ERR, LSTACK, "memcpy_s err ret=%d \n", ret);
        return;
    }

    get_wakeup_stat(stack_group, stack, &dfx->data.pkts.wakeup_stat);

    dfx->data.pkts.call_alloc_fail = stack_group->call_alloc_fail;

    int32_t rpc_call_result = rpc_call_msgcnt(stack);
    dfx->data.pkts.call_msg_cnt = (rpc_call_result < 0) ? 0 : rpc_call_result;

    rpc_call_result = rpc_call_mempoolsize(stack);
    dfx->data.pkts.mempool_freecnt = (rpc_call_result < 0) ? 0 : rpc_call_result;

    rpc_call_result = rpc_call_recvlistcnt(stack);
    dfx->data.pkts.recv_list_cnt = (rpc_call_result < 0) ? 0 : rpc_call_result;

    dfx->data.pkts.conn_num = stack->conn_num;
}

static void get_stack_dfx_data(struct gazelle_stack_dfx_data *dfx, struct protocol_stack *stack,
    enum GAZELLE_STAT_MODE stat_mode)
{
    int32_t rpc_call_result;
    int32_t ret;

    switch (stat_mode) {
        case GAZELLE_STAT_LSTACK_SHOW:
        case GAZELLE_STAT_LSTACK_SHOW_RATE:
            get_stack_stats(dfx, stack);
            break;
        case GAZELLE_STAT_LSTACK_SHOW_SNMP:
            ret = memcpy_s(&dfx->data.snmp, sizeof(dfx->data.snmp), &stack->lwip_stats->mib2,
                sizeof(stack->lwip_stats->mib2));
            if (ret != EOK) {
                LSTACK_LOG(ERR, LSTACK, "memcpy_s err ret=%d \n", ret);
            }
            break;
        case GAZELLE_STAT_LSTACK_SHOW_CONN:
            rpc_call_result = rpc_call_conntable(stack, dfx->data.conn.conn_list, GAZELLE_LSTACK_MAX_CONN);
            dfx->data.conn.conn_num = (rpc_call_result < 0) ? 0 : rpc_call_result;
            rpc_call_result = rpc_call_connnum(stack);
            dfx->data.conn.total_conn_num = (rpc_call_result < 0) ? 0 : rpc_call_result;
            break;
        case GAZELLE_STAT_LSTACK_SHOW_LATENCY:
            ret = memcpy_s(&dfx->data.latency, sizeof(dfx->data.latency), &stack->latency, sizeof(stack->latency));
            if (ret != EOK) {
                LSTACK_LOG(ERR, LSTACK, "memcpy_s err ret=%d \n", ret);
            }
            break;
        case GAZELLE_STAT_LSTACK_SHOW_AGGREGATE:
            ret = memcpy_s(&dfx->data.aggregate_stats, sizeof(dfx->data.aggregate_stats),
                &stack->aggregate_stats, sizeof(stack->aggregate_stats));
            if (ret != EOK) {
                LSTACK_LOG(ERR, LSTACK, "memcpy_s err ret=%d \n", ret);
            }
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
    struct gazelle_stack_dfx_data dfx;
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    if (stat_mode == GAZELLE_STAT_LSTACK_SHOW_XSTATS) {
        dpdk_nic_xstats_get(&dfx, get_port_id());
        dfx.tid = 0;
        dfx.eof = 1;
        send_control_cmd_data(fd, &dfx);
        return 0;
    }

    for (uint32_t i = 0; i < stack_group->stack_num; i++) {
        struct protocol_stack *stack = stack_group->stacks[i];

        memset_s(&dfx, sizeof(dfx), 0, sizeof(dfx));
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
