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
#define PORT_MAP_EIGHT_BIT 8

static uint8_t g_rule_port[(PORT_MAP_UNIX_TCP_PORT_MAX + 1) / PORT_MAP_EIGHT_BIT]; // 8k byte
static pthread_mutex_t g_rule_map_mutex = PTHREAD_MUTEX_INITIALIZER;

void port_map_set(uint32_t modBit, int setVal)
{
    pthread_mutex_lock(&g_rule_map_mutex);
    g_rule_port[modBit / PORT_MAP_EIGHT_BIT] &= ~(1 << (modBit % PORT_MAP_EIGHT_BIT));
    g_rule_port[modBit / PORT_MAP_EIGHT_BIT] |= (setVal << (modBit % PORT_MAP_EIGHT_BIT));
    pthread_mutex_unlock(&g_rule_map_mutex);
}

int port_map_get(int bit_index)
{
    int bit_val = 0;
    int byte_index = bit_index / PORT_MAP_EIGHT_BIT;
    int bit_offset = bit_index % PORT_MAP_EIGHT_BIT;
    uint8_t mask = 1 << bit_offset;
    pthread_mutex_lock(&g_rule_map_mutex);
    if ((g_rule_port[byte_index] & mask) != 0) {
        bit_val = 1;
    }
    pthread_mutex_unlock(&g_rule_map_mutex);
    return bit_val;
}