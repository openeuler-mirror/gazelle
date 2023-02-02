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
#include "ltran_instance.h"
#include "ltran_param.h"
#include "ltran_stack.h"

void test_ltran_instance(void)
{
    struct gazelle_instance *instance = NULL;
    uint32_t ret;

    get_ltran_config()->dispatcher.num_clients = 30; /* 30:clients num */
    get_ltran_config()->dispatcher.ipv4_subnet_size = 256; /* 256:ipv4 subnet size */
    get_ltran_config()->dispatcher.ipv4_net_mask = get_ltran_config()->dispatcher.ipv4_subnet_size - 1;
    set_instance_mgr(gazelle_instance_mgr_create());
    CU_ASSERT(get_instance_mgr() != NULL);

    instance = gazelle_instance_add_by_pid(get_instance_mgr(), 1111); /* 1111:test pid */
    CU_ASSERT(instance != NULL);
    CU_ASSERT(instance->pid == 1111); /* 1111:test pid */

    instance = gazelle_instance_get_by_pid(get_instance_mgr(), 1111); /* 1111:test pid */
    CU_ASSERT(instance != NULL);
    CU_ASSERT(instance->pid == 1111); /* 1111:test pid */

    instance->ip_addr.s_addr = inet_addr("192.168.1.1");

    instance = gazelle_instance_get_by_ip(get_instance_mgr(), inet_addr("192.168.1.1"));
    CU_ASSERT(instance != NULL);
    CU_ASSERT(instance->pid == 1111); /* 1111:test pid */
    CU_ASSERT(instance->ip_addr.s_addr == inet_addr("192.168.1.1"));

    instance = gazelle_instance_get_by_ip(get_instance_mgr(), inet_addr("192.168.1.2"));
    CU_ASSERT(instance == NULL);

    instance = gazelle_instance_get_by_pid(get_instance_mgr(), 1112); /* 1112:test pid */
    CU_ASSERT(instance == NULL);

    for (int i = 1; i <= get_instance_mgr()->max_instance_num; i++) {
        instance = gazelle_instance_add_by_pid(get_instance_mgr(), i);
        if (i < get_instance_mgr()->max_instance_num) {
            CU_ASSERT(instance != NULL);
        } else {
            CU_ASSERT(instance == NULL);
        }
        instance = gazelle_instance_get_by_pid(get_instance_mgr(), i);
        if (i < get_instance_mgr()->max_instance_num) {
            CU_ASSERT(instance != NULL);
        } else {
            CU_ASSERT(instance == NULL);
        }
    }

    gazelle_instance_mgr_destroy();
}
