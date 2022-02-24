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

#ifndef __GAZELLE_JHASH_H__
#define __GAZELLE_JHASH_H__

#include <rte_jhash.h>

static __rte_always_inline uint32_t tuple_hash_fn(uint32_t laddr, uint16_t lport, uint32_t faddr, uint16_t fport)
{
    return rte_jhash_3words(laddr, faddr, lport | (fport) << 16, 0);
}

static __rte_always_inline uint32_t ip_port_hash_fn(uint32_t ip, uint16_t port)
{
    return rte_jhash_3words(ip, port, 0, 0);
}

static __rte_always_inline uint32_t tid_hash_fn(uint32_t tid)
{
    return rte_jhash_3words(tid, 0, 0, 0);
}

#endif

