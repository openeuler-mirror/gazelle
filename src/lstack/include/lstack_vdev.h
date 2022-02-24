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

#ifndef LIBOS_VDEV_H
#define LIBOS_VDEV_H

#include "lstack_ethdev.h"
#include "gazelle_reg_msg.h"

#define DEFAULT_RING_SIZE                 (512)
#define DEFAULT_BACKUP_RING_SIZE_FACTOR   (16)

#define VDEV_RX_QUEUE_SZ     (DEFAULT_RING_SIZE)
#define VDEV_EVENT_QUEUE_SZ  (DEFAULT_RING_SIZE)
#define VDEV_REG_QUEUE_SZ    (DEFAULT_RING_SIZE)
#define VDEV_CALL_QUEUE_SZ   (DEFAULT_RING_SIZE)
#define VDEV_WEAKUP_QUEUE_SZ (DEFAULT_RING_SIZE)
#define VDEV_IDLE_QUEUE_SZ   (DEFAULT_RING_SIZE)

#define VDEV_TX_QUEUE_SZ     (DEFAULT_RING_SIZE)
#define FREE_RX_QUEUE_SZ     (DPDK_PKT_BURST_SIZE)

struct eth_dev_ops;
void vdev_dev_ops_init(struct eth_dev_ops **dev_ops);
int vdev_reg_xmit(enum reg_ring_type type, struct gazelle_quintuple *qtuple);

#endif /* LIBOS_VDEV_H */
