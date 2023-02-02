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

#include <stdlib.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <securec.h>
#include "ltran_stack.h"

void test_ltran_stack(void)
{
    struct gazelle_stack *stack = NULL;
    const struct gazelle_stack *exist_stack = NULL;
    struct gazelle_stack_htable *stack_htable;
    /* 1: tick init val */
    int32_t instance_cur_tick = 1;

    stack_htable = gazelle_stack_htable_create(GAZELLE_MAX_STACK_NUM);
    CU_ASSERT(stack_htable != NULL);
    gazelle_set_stack_htable(stack_htable);

    stack = gazelle_stack_add_by_tid(gazelle_get_stack_htable(), 1111); /* 1111:tid number */
    CU_ASSERT(stack != NULL);
    CU_ASSERT(stack->tid == 1111); /* 1111: tid number */
    stack->instance_cur_tick = &instance_cur_tick;
    /* 1: set instacn_cur_tick = instance_reg_tick indicate instance is on */
    stack->instance_reg_tick = 1;

    exist_stack = gazelle_stack_get_by_tid(gazelle_get_stack_htable(), 1111); /* 1111: tid number */

    CU_ASSERT(exist_stack != NULL);
    CU_ASSERT(exist_stack->tid == 1111); /* 1111:tid number */

    gazelle_stack_del_by_tid(gazelle_get_stack_htable(), 1111); /* 1111:tid number */
    exist_stack = gazelle_stack_get_by_tid(gazelle_get_stack_htable(), 1111); /* 1111:tid number */

    CU_ASSERT(exist_stack == NULL);

    gazelle_stack_del_by_tid(gazelle_get_stack_htable(), 1111);

    for (int i = 0; i <= stack_htable->max_stack_num; i++) {
        stack = gazelle_stack_add_by_tid(gazelle_get_stack_htable(), i);
        if (i < stack_htable->max_stack_num) {
            CU_ASSERT(stack != NULL);
            stack->instance_cur_tick = &instance_cur_tick;
            /* 1: set instacn_cur_tick = instance_reg_tick indicate instance is on */
            stack->instance_reg_tick = 1;
        } else {
            CU_ASSERT(stack == NULL);
        }
        exist_stack = gazelle_stack_get_by_tid(gazelle_get_stack_htable(), i);
        if (i < stack_htable->max_stack_num) {
            CU_ASSERT(exist_stack != NULL);
        } else {
            CU_ASSERT(exist_stack == NULL);
        }
    }

    gazelle_stack_htable_destroy();
}
