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

#include <pthread.h>
#include <stdint.h>
#include "lstack_port_map.h"

#define PORT_MAP_UNIX_TCP_PORT_MAX 65535

static uint32_t g_rule_port[PORT_MAP_UNIX_TCP_PORT_MAX] = {0};
static pthread_mutex_t g_rule_map_mutex = PTHREAD_MUTEX_INITIALIZER;

void port_map_mod(uint16_t port, uint16_t flag)
{
    pthread_mutex_lock(&g_rule_map_mutex);
    if (flag == 0) {
        g_rule_port[port]--;
    } else {
        g_rule_port[port]++;
    }
    pthread_mutex_unlock(&g_rule_map_mutex);
}

uint16_t port_map_get(uint16_t port)
{
    uint16_t val = 0;
    pthread_mutex_lock(&g_rule_map_mutex);
    if (g_rule_port[port] > 0) {
        val = 1;
    }
    pthread_mutex_unlock(&g_rule_map_mutex);
    return val;
}
