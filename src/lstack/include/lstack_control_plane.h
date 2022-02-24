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

#ifndef LIBOS_CONTROL_PLANE_H
#define LIBOS_CONTROL_PLANE_H

#include "lstack_thread_rpc.h"

#define CONTROL_THREAD_NAME "control_thread"

enum vdev_request {
    VDEV_SET_MEM_TABLE = 1,
    VDEV_SET_QUEUE_NUM = 2,
    VDEV_SET_QUEUE_ADDR = 3,
    VDEV_SET_QUEUE_KICK = 4,
    VDEV_NONE,
};

int client_reg_thrd_ring(void);
int32_t control_init_client(bool is_reconnect);
void control_client_thread(void *arg);
void control_server_thread(void *arg);
bool get_register_state(void);
void thread_register_phase1(struct rpc_msg *msg);
void thread_register_phase2(struct rpc_msg *msg);

#endif /* LIBOS_CONTROL_PLANE_H */
