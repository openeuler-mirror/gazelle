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

#ifndef GAZELLE_STACK_STAT_H
#define GAZELLE_STACK_STAT_H

struct gazelle_stack_latency;
struct pbuf;
struct gazelle_stat_low_power_info;
struct wakeup_poll;
struct protocol_stack;
enum GAZELLE_LATENCY_TYPE;
enum GAZELLE_STAT_MODE;
struct gazelle_stat_msg_request;

void calculate_lstack_latency(struct gazelle_stack_latency *stack_latency, const struct pbuf *pbuf,
    enum GAZELLE_LATENCY_TYPE type);
void stack_stat_init(void);
int handle_stack_cmd(int fd, struct gazelle_stat_msg_request *msg);
int handle_dpdk_cmd(int fd, enum GAZELLE_STAT_MODE stat_mode);
uint64_t get_current_time(void);
void lstack_get_low_power_info(struct gazelle_stat_low_power_info *low_power_info);
void unregister_wakeup(struct protocol_stack *stack, struct wakeup_poll *wakeup);
void lstack_calculate_aggregate(int type, uint32_t len);
void time_stamp_transfer_pbuf(struct pbuf *pbuf_old, struct pbuf *pbuf_new);

#endif /* GAZELLE_STACK_STAT_H */
