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

struct lstack_dev_ops;
struct gazelle_quintuple;
enum reg_ring_type;
void vdev_dev_ops_init(struct lstack_dev_ops *dev_ops);
int vdev_reg_xmit(enum reg_ring_type type, struct gazelle_quintuple *qtuple);

#endif /* _GAZELLE_VDEV_H_ */
