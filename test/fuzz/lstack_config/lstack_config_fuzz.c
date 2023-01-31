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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <securec.h>

#include "lstack_cfg.h"
#include "lstack_protocol_stack.h"

#define MAX_CMD_LEN 1024
#define MAX_STR_LEN 20

#define FUZZ_LSTACK_CONF_PATH_TMP "./lstack.conf"
#define FUZZ_LSTACK_CONF_PATH     "/etc/gazelle/lstack.conf"
#define FUZZ_LSTACK_CONF_PATH_BAK "/etc/gazelle/lstack.conf.bak"

void lwip_set_host_ipv4(unsigned int ipv4)
{
    return;
}

int rte_log(uint32_t level, uint32_t logtype, const char *format, ...)
{
    return 0;
}

static struct protocol_stack_group g_stack_group = {0};
struct protocol_stack_group *get_protocol_stack_group(void)
{
        return &g_stack_group;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
    char str[MAX_STR_LEN + 1] = {0};
    char cmd[MAX_CMD_LEN + 1] = {0};
    char *sed_str[] = {"dpdk_args", "host_addr", "mask_addr", "gateway_addr", "devices"};
    static int index = 0;
    struct cfg_params *cfg_params = get_global_cfg_params();

    if (data == NULL) {
        return 0;
    }

    system("mkdir -p /etc/gazelle");

    if (sprintf_s(cmd, MAX_CMD_LEN, "cp -f %s %s; cp -f %s %s", FUZZ_LSTACK_CONF_PATH, FUZZ_LSTACK_CONF_PATH_BAK,
        FUZZ_LSTACK_CONF_PATH_TMP, FUZZ_LSTACK_CONF_PATH) < 0) {
        return -1;
    }
    system(cmd);

    for (int i = 0; i < MAX_STR_LEN && i < size; i++) {
        if (((data[i] >= 'a') && (data[i] <= 'z')) ||
            ((data[i] >= 'A') && (data[i] <= 'Z')) ||
            ((data[i] >= '0') && (data[i] <= '9'))) {
            str[i] = data[i];
        } else {
            str[i] = ' ';
        }
    }
    index = (index + 1) % 5; /* 5:匹配字符串总数 */
    if (sprintf_s(cmd, MAX_CMD_LEN, "sed -i '/%s/s/\".*\"/\"%s\"/' %s",
        sed_str[index], str, FUZZ_LSTACK_CONF_PATH) < 0) {
        return -1;
    }
    system(cmd);

    memset_s(cfg_params, sizeof(struct cfg_params), 0, sizeof(*cfg_params));

    // test parse config
    (void)cfg_init();

    // free memory if used
    if (cfg_params->dpdk_argv) {
        if (cfg_params->dpdk_argv[0] != NULL) {
            free(cfg_params->dpdk_argv[0]);
        }
        for (int i = 0; i < cfg_params->dpdk_argc; i++) {
            if (cfg_params->dpdk_argv[i + 1] != NULL) {
                free(cfg_params->dpdk_argv[i + 1]);
            }
        }
        free(cfg_params->dpdk_argv);
    }

    if (sprintf_s(cmd, MAX_CMD_LEN, "cp -f %s %s;rm -f %s", FUZZ_LSTACK_CONF_PATH_BAK, FUZZ_LSTACK_CONF_PATH,
        FUZZ_LSTACK_CONF_PATH_BAK) < 0) {
        return -1;
    }
    system(cmd);
    return 0;
}

