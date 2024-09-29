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

#ifndef __LSTACK_INTERRUPT_H__
#define __LSTACK_INTERRUPT_H__

enum intr_type {
    INTR_DPDK_EVENT = 0,
    INTR_LOCAL_EVENT,
    INTR_REMOTE_EVENT,
};

struct intr_dpdk_event_args {
    uint16_t port_id;
    uint16_t queue_id;
};

int intr_init(void);
int intr_register(uint16_t stack_id, enum intr_type type, void *priv);
void intr_wakeup(uint16_t stack_id, enum intr_type type);
void intr_wait(uint16_t stack_id, uint32_t timeout);
int intr_stats_get(uint16_t stack_id, void *ptr, int len);

#endif

