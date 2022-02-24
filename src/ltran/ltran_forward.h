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

#ifndef __GAZELLE_FORWORD_H__
#define __GAZELLE_FORWORD_H__

#include "ltran_stack.h"
#include "ltran_base.h"

void upstream_forward(const uint16_t *port);
int32_t downstream_forward(uint16_t *port);

static __rte_always_inline unsigned rte_ring_cn_count(const struct rte_ring *r)
{
    const uint32_t old_head = r->prod.tail;
    rte_smp_rmb();

    return r->cons.head - old_head;
}

#endif /* ifndef __GAZELLE_FORWORD_H__ */
