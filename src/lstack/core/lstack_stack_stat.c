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
#include "lstack_protocol_stack.h"
#include "posix/lstack_epoll.h"
#include "lstack_dpdk.h"
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

void time_stamp_transfer_pbuf(struct pbuf *pbuf_old, struct pbuf *pbuf_new)
{
    if (!get_protocol_stack_group()->latency_start) {
        return;
    }
    struct latency_timestamp *lt_old;
    struct latency_timestamp *lt_new;

    lt_old = &pbuf_to_private(pbuf_old)->lt;
    lt_new = &pbuf_to_private(pbuf_new)->lt;

    lt_new->stamp = lt_old->stamp;
    lt_new->check = lt_old->check;
    lt_new->type = lt_old->type;
    for (int i = 0; i < GAZELLE_LATENCY_MAX; i++) {
        lt_new->stamp_seg[i] = lt_old->stamp_seg[i];
    }
}

void time_stamp_into_rpcmsg(struct rpc_msg *msg)
{
    msg->time_stamp = get_current_time();
}

void calculate_rpcmsg_latency(struct gazelle_stack_latency *stack_latency, struct rpc_msg *msg,
    enum GAZELLE_LATENCY_TYPE type)
{
    uint64_t latency;
    struct stack_latency *latency_stat;
    if (msg == NULL || msg->time_stamp < stack_latency->start_time || type >= GAZELLE_LATENCY_MAX) {
        return;
    }

    latency = get_current_time() - msg->time_stamp;
    latency_stat = &stack_latency->latency[type];

    latency_stat->latency_total += latency;
    latency_stat->latency_max = (latency_stat->latency_max > latency) ? latency_stat->latency_max : latency;
    latency_stat->latency_min = (latency_stat->latency_min < latency) ? latency_stat->latency_min : latency;
    latency_stat->latency_pkts++;
}

void calculate_latency_stat(struct gazelle_stack_latency *stack_latency, uint64_t latency,
    enum GAZELLE_LATENCY_TYPE type)
{
    struct stack_latency *latency_stat;

    latency_stat = &stack_latency->latency[type];
    latency_stat->latency_total += latency;
    latency_stat->latency_max = (latency_stat->latency_max > latency) ? latency_stat->latency_max : latency;
    latency_stat->latency_min = (latency_stat->latency_min < latency) ? latency_stat->latency_min : latency;
    latency_stat->latency_pkts++;
}

void calculate_lstack_latency(struct gazelle_stack_latency *stack_latency, const struct pbuf *pbuf,
    enum GAZELLE_LATENCY_TYPE type, uint64_t time_record)
{
    uint64_t latency;
    uint16_t lt_type;
    struct latency_timestamp *lt;

    if (pbuf == NULL || type >= GAZELLE_LATENCY_MAX) {
        return;
    }

    lt = &pbuf_to_private(pbuf)->lt;
    lt_type = (type / GAZELLE_LATENCY_READ_MAX) ? GAZELLE_LATENCY_WR : GAZELLE_LATENCY_RD;
    if (lt->stamp != ~(lt->check) || lt->stamp < stack_latency->start_time || lt_type != lt->type) {
        return;
    }

    if (time_record == 0) {
        lt->stamp_seg[type] = get_current_time() - lt->stamp;
    } else {
        lt->stamp_seg[type] = time_record > (lt->stamp_seg[type - 1] + lt->stamp) ?
            (time_record - lt->stamp) : lt->stamp_seg[type - 1];
    }

    latency = lt->stamp_seg[type];
    if (((lt_type == GAZELLE_LATENCY_RD && type > GAZELLE_LATENCY_READ_LWIP) ||
        (lt_type == GAZELLE_LATENCY_WR && type > GAZELLE_LATENCY_WRITE_INTO_RING)) &&
        latency >= lt->stamp_seg[type - 1]) {
        latency -= lt->stamp_seg[type - 1];
    }

    /* calculate the time of the entire read/write process */
    if (type == GAZELLE_LATENCY_READ_MAX - 1 || type == GAZELLE_LATENCY_WRITE_MAX - 1) {
        calculate_latency_stat(stack_latency, lt->stamp_seg[type], type + 1);
    }

    calculate_latency_stat(stack_latency, latency, type);
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
        stack->latency.start_time = get_current_time();

        for (uint32_t j = 0; j < GAZELLE_LATENCY_MAX; j++) {
            stack->latency.latency[j].latency_min = ~((uint64_t)0);
        }
 
        memset_s(&stack->aggregate_stats, sizeof(struct gazelle_stack_aggregate_stats),
            0, sizeof(stack->aggregate_stats));
    }
}

static void get_wakeup_stat(struct protocol_stack_group *stack_group, struct protocol_stack *stack,
    struct gazelle_wakeup_stat *stat)
{
    struct list_node *node, *temp;

    pthread_spin_lock(&stack_group->poll_list_lock);

    list_for_each_safe(node, temp, &stack_group->poll_list) {
        struct wakeup_poll *wakeup = container_of(node, struct wakeup_poll, poll_list);

        if (wakeup->bind_stack == stack) {
            stat->kernel_events += wakeup->stat.kernel_events;
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

    dfx->data.pkts.call_alloc_fail = rpc_stats_get()->call_alloc_fail;

    int32_t rpc_call_result = rpc_msgcnt(&stack->rpc_queue);
    dfx->data.pkts.call_msg_cnt = (rpc_call_result < 0) ? 0 : rpc_call_result;

    rpc_call_result = rpc_call_mbufpoolsize(&stack->dfx_rpc_queue);
    dfx->data.pkts.mbufpool_avail_cnt = (rpc_call_result < 0) ? 0 : rpc_call_result;

    rpc_call_result = rpc_call_recvlistcnt(&stack->dfx_rpc_queue);
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
        case GAZELLE_STAT_LTRAN_SHOW_LSTACK:
            get_stack_stats(dfx, stack);
	    /* fall through */
        case GAZELLE_STAT_LSTACK_SHOW_AGGREGATE:
            ret = memcpy_s(&dfx->data.pkts.aggregate_stats, sizeof(dfx->data.pkts.aggregate_stats),
                &stack->aggregate_stats, sizeof(stack->aggregate_stats));
            if (ret != EOK) {
                LSTACK_LOG(ERR, LSTACK, "memcpy_s err ret=%d \n", ret);
            }
            break;
        case GAZELLE_STAT_LSTACK_SHOW_SNMP:
            ret = memcpy_s(&dfx->data.snmp, sizeof(dfx->data.snmp), &stack->lwip_stats->mib2,
                sizeof(stack->lwip_stats->mib2));
            if (ret != EOK) {
                LSTACK_LOG(ERR, LSTACK, "memcpy_s err ret=%d \n", ret);
            }
            break;
        case GAZELLE_STAT_LSTACK_SHOW_CONN:
            rpc_call_result = rpc_call_conntable(&stack->dfx_rpc_queue, dfx->data.conn.conn_list,
                                                 GAZELLE_LSTACK_MAX_CONN);
            dfx->data.conn.conn_num = (rpc_call_result < 0) ? 0 : rpc_call_result;
            rpc_call_result = rpc_call_connnum(&stack->dfx_rpc_queue);
            dfx->data.conn.total_conn_num = (rpc_call_result < 0) ? 0 : rpc_call_result;
            break;
        case GAZELLE_STAT_LSTACK_SHOW_LATENCY:
            ret = memcpy_s(&dfx->data.latency, sizeof(dfx->data.latency), &stack->latency, sizeof(stack->latency));
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

int handle_dpdk_cmd(int fd, enum GAZELLE_STAT_MODE stat_mode)
{
    struct gazelle_stack_dfx_data dfx;

    if (stat_mode == GAZELLE_STAT_LSTACK_SHOW_XSTATS) {
        dpdk_nic_xstats_get(&dfx, get_protocol_stack_group()->port_id);
    } else if (stat_mode == GAZELLE_STAT_LSTACK_SHOW_NIC_FEATURES) {
        dpdk_nic_features_get(&dfx, get_protocol_stack_group()->port_id);
    } else {
        return 0;
    }

    dfx.tid = 0;
    dfx.eof = 1;
    send_control_cmd_data(fd, &dfx);
    return 0;
}

int handle_stack_cmd(int fd, enum GAZELLE_STAT_MODE stat_mode)
{
    struct gazelle_stack_dfx_data dfx;
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    for (uint32_t i = 0; i < stack_group->stack_num; i++) {
        struct protocol_stack *stack = stack_group->stacks[i];

        memset_s(&dfx, sizeof(dfx), 0, sizeof(dfx));
        get_stack_dfx_data(&dfx, stack, stat_mode);

        if (!use_ltran() &&
            (stat_mode == GAZELLE_STAT_LTRAN_START_LATENCY || stat_mode == GAZELLE_STAT_LTRAN_STOP_LATENCY)) {
            continue;
        }

        dfx.tid = stack->tid;
        dfx.stack_id = i;
        if (i == stack_group->stack_num - 1) {
            dfx.eof = 1;
        }

        if (send_control_cmd_data(fd, &dfx) != 0) {
            break;
        }
    }
    return 0;
}
