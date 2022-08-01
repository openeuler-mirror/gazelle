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

#ifndef __GAZELLE_INSTANCE_H__
#define __GAZELLE_INSTANCE_H__

#include <lwip/hlist.h>
#include <netinet/in.h>
#include <limits.h>

#include "gazelle_opt.h"
#include "gazelle_reg_msg.h"

struct gazelle_stack;
struct gazelle_instance {
    // key
    uint32_t pid;
    /* net byte order */
    struct in_addr ip_addr;

    /* instance_reg_tick==instance_cur_tick:instance on; instance_reg_tick!=instance_cur_tick:instance off */
    volatile int32_t *instance_cur_tick;
    int32_t instance_reg_tick;

    // data
    uint32_t stack_cnt;
    struct gazelle_stack* stack_array[GAZELLE_MAX_STACK_ARRAY_SIZE];

    int32_t sockfd;
    enum request_type reg_state;
    uintptr_t base_virtaddr;
    uint64_t socket_size;
    uint8_t mac_addr[ETHER_ADDR_LEN];
    char file_prefix[PATH_MAX];

    struct gazelle_instance *next;
};

struct gazelle_instance_mgr {
    uint32_t cur_instance_num;
    uint32_t max_instance_num;

    /* when instance online or offline instance_cur_tick++.
       instance_reg_tick==instance_cur_tick:instance on; instance_reg_tick!=instance_cur_tick:instance off */
    volatile int32_t instance_cur_tick[GAZELLE_MAX_INSTANCE_NUM];

    struct gazelle_instance *instances[GAZELLE_MAX_INSTANCE_NUM];

    /* net byte order */
    uint32_t net_mask;
    uint32_t subnet_size;
};

#define INSTANCE_IS_ON(type)        ((type)->instance_reg_tick == *(type)->instance_cur_tick)
#define INSTANCE_CUR_TICK_INIT_VAL  (-1)
#define INSTANCE_REG_TICK_INIT_VAL  (0)
int32_t *instance_cur_tick_init_val(void);

void set_tx_loop_count(void);
unsigned long get_tx_loop_count(void);

void set_rx_loop_count(void);
unsigned long get_rx_loop_count(void);

void set_instance_mgr(struct gazelle_instance_mgr *instance);
struct gazelle_instance_mgr *get_instance_mgr(void);

// Add for gazelle_instance_mgr
void gazelle_instance_mgr_destroy(void);
struct gazelle_instance_mgr *gazelle_instance_mgr_create(void);

struct gazelle_instance *gazelle_instance_get_by_pid(const struct gazelle_instance_mgr *mgr, uint32_t pid);
struct gazelle_instance *gazelle_instance_get_by_ip(const struct gazelle_instance_mgr *mgr, uint32_t ip);
struct gazelle_instance *gazelle_instance_add_by_pid(struct gazelle_instance_mgr *mgr, uint32_t pid);

int32_t handle_reg_msg_proc_mem(int32_t fd, struct reg_request_msg *recv_msg);
int32_t instance_match_bond_port(const uint8_t *mac);
int32_t handle_reg_msg_proc_reconn(int32_t fd, const struct reg_request_msg *recv_msg);
int32_t handle_reg_msg_proc_att(int32_t fd, struct reg_request_msg *recv_msg);
void handle_instance_logout(uint32_t pid);
int32_t handle_reg_msg_thrd_ring(int32_t fd, const struct reg_request_msg *recv_msg);

#endif
