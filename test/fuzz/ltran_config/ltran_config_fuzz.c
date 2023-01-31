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

#include "ltran_base.h"
#include "ltran_param.h"

#define MAX_CMD_LEN 1024
#define MAX_STR_LEN 20

#define FUZZ_LTRAN_CONF_PATH     "./ltran.conf"
#define FUZZ_LTRAN_CONF_PATH_TMP "./ltran_tmp.conf"

int rte_log(uint32_t level, uint32_t logtype, const char *format, ...)
{
    return 0;
}

void restore_conf_file(const unsigned char *data, size_t size)
{
    int ret;
    char cmd[MAX_CMD_LEN];
    char str[MAX_STR_LEN + 1] = {0};
    char *sed_str[] = {"forward_kit_args", "kni_switch", "dispatch_subnet", "dispatch_subnet_length",
        "dispatch_max_clients", "bond_mode", "bond_miimon", "bond_mtu", "bond_ports", "bond_macs",
        "tcp_conn_scan_interval"};
    static int index = 0;

    // reset conf file
    ret = sprintf_s(cmd, MAX_CMD_LEN, "rm -f %s", FUZZ_LTRAN_CONF_PATH_TMP);
    if (ret < 0) {
        return;
    }
    system(cmd);

    ret = sprintf_s(cmd, MAX_CMD_LEN, "cp -f %s %s", FUZZ_LTRAN_CONF_PATH, FUZZ_LTRAN_CONF_PATH_TMP);
    if (ret < 0) {
        return;
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
    index = (index + 1) % 11; /* 11:匹配字符串总数 */
    ret = sprintf_s(cmd, MAX_CMD_LEN, "sed -i '/%s/s/= .*/= \"%s\"/' %s",
                    sed_str[index], str, FUZZ_LTRAN_CONF_PATH_TMP);
    if (ret < 0) {
        return;
    }
    system(cmd);
    ret = sprintf_s(cmd, MAX_CMD_LEN, "sed -i '/%s/s/= [0-9].*/= %s/' %s",
                    sed_str[index], str, FUZZ_LTRAN_CONF_PATH_TMP);
    if (ret < 0) {
        return;
    }
    system(cmd);
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
    struct ltran_config ltran_config;

    if (data == NULL) {
        return 0;
    }

    restore_conf_file(data, size);
    (void)memset_s(&ltran_config, sizeof(struct ltran_config), 0, sizeof(struct ltran_config));

    // test parse DEFAULT_LTRAN_CONF_PATH_TMP
    (void)parse_config_file_args(FUZZ_LTRAN_CONF_PATH_TMP, &ltran_config);
    // free memory if used
    for (int i = 0; i < ltran_config.dpdk.dpdk_argc; i++) {
        if ((ltran_config.dpdk.dpdk_argv != NULL) &&
            (ltran_config.dpdk.dpdk_argv[i] != NULL)) {
            free(ltran_config.dpdk.dpdk_argv[i]);
            ltran_config.dpdk.dpdk_argv[i] != NULL;
        }
    }
    if (ltran_config.dpdk.dpdk_argv != NULL) {
        free(ltran_config.dpdk.dpdk_argv);
        ltran_config.dpdk.dpdk_argv = NULL;
    }
    return 0;
}

