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

#ifndef _GAZELLE_VDEV_H_
#define _GAZELLE_VDEV_H_

#include <stdbool.h>

struct lstack_dev_ops;
struct gazelle_quintuple;
enum reg_ring_type;
void vdev_dev_ops_init(struct lstack_dev_ops *dev_ops);
int vdev_reg_xmit(enum reg_ring_type type, struct gazelle_quintuple *qtuple);

int recv_pkts_from_other_process(int process_index, void* arg);
void transfer_delete_rule_info_to_process0(uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
void transfer_create_rule_info_to_process0(uint16_t queue_id, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
void transfer_add_or_delete_listen_port_to_process0(uint16_t listen_port, uint8_t process_idx, uint8_t is_add);
void init_listen_and_user_ports();

#endif /* _GAZELLE_VDEV_H_ */
