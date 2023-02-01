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

#include <stdint.h>
#include <stdlib.h>

uint64_t get_current_time(void)
{
    return 0;
}

int rte_pdump_init(void)
{
    return 0;
}

void *__wrap_rte_malloc(const char *type, size_t size, unsigned align)
{
    return malloc(size);
}

void __wrap_rte_free(void *ptr)
{
    free(ptr);
}
