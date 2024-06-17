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
#ifndef __LSTACK_VIRTIO_H__
#define __LSTACK_VIRTIO_H__

#include <stdint.h>

#define VIRTIO_MAX_QUEUE_NUM 8
struct virtio_instance {
    uint16_t lstack_port_id;
    uint16_t virtio_port_id;
    uint16_t rx_queue_num;
    uint16_t tx_queue_num;

    uint64_t rx_pkg[VIRTIO_MAX_QUEUE_NUM];
    uint64_t rx_drop[VIRTIO_MAX_QUEUE_NUM];
    uint64_t tx_pkg[VIRTIO_MAX_QUEUE_NUM];
    uint64_t tx_drop[VIRTIO_MAX_QUEUE_NUM];
};

void virtio_tap_process_rx(uint16_t port, uint32_t queue_id);
void virtio_tap_process_tx(uint16_t queue_id, struct rte_mbuf *mbuf_copy);

int virtio_port_create(int lstack_net_port);

struct virtio_instance* virtio_instance_get(void);
#endif