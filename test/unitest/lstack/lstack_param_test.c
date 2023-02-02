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
#include "lstack_cfg.h"

#define MAX_CMD_LEN 1024

int parse_conf_file(const char *path);

static int execute_cmd(const char *cmd)
{
    int result;
    result = system(cmd);
    if (result < 0) {
        printf("Executing cmd: %s error!!!\n", cmd);
    }
    return result;
}

static int lstack_bad_param(const char *conf_file_filed)
{
    int ret;
    const char *conf_file_path = "../lstack/config/lstack_tmp.conf";
    char cmd[MAX_CMD_LEN];

    execute_cmd("rm -rf ../lstack/config/lstack_tmp.conf");
    execute_cmd("cp -f ../lstack/config/lstack.conf ../lstack/config/lstack_tmp.conf");

    ret = sprintf_s(cmd, MAX_CMD_LEN, "sed -i '%s' %s", conf_file_filed, conf_file_path);
    if (ret < 0) {
        printf("sprintf_s cmd error %s %s!!!\n", conf_file_filed, conf_file_path);
        return ret;
    }

    execute_cmd(cmd);

    ret = parse_conf_file(conf_file_path);

    return ret;
}

void test_lstack_bad_params_lowpower(void)
{
    /* lstack start lowpower empty */
    CU_ASSERT(lstack_bad_param("/^low_power_mode/clow_power_mode=/") != 0);

    /* lstack start lowpower none */
    CU_ASSERT(lstack_bad_param("/low_power_mode/d") == 0);

    /* lstack start lowpower exceed str */
    CU_ASSERT(lstack_bad_param("/^low_power_mode/clow_power_mode=aaa/") != 0);
}

void test_lstack_bad_params_num_cpus(void)
{
    /* lstack start num_cpus empty */
    CU_ASSERT(lstack_bad_param("/^num_cpus/cnum_cpus=/") != 0);

    /* lstack start num_cpus none */
    CU_ASSERT(lstack_bad_param("/num_cpus/d") != 0);

    /* lstack start num_cpus exceed str */
    CU_ASSERT(lstack_bad_param("/^num_cpus/cnum_cpus=aaa/") != 0);
}

void test_lstack_bad_params_host_addr(void)
{
    /* lstack start host_addr empty */
    CU_ASSERT(lstack_bad_param("/^host_addr/chost_addr=/") != 0);

    /* lstack start host_addr none */
    CU_ASSERT(lstack_bad_param("/^host_addr/d") != 0);

    /* lstack start host_addr invaild str */
    CU_ASSERT(lstack_bad_param("/^host_addr/chost_addr=\"aaa\"/") != 0);

    /* lstack start host_addr exceed str */
    CU_ASSERT(lstack_bad_param("/^host_addr/chost_addr=\"192.168.1.256\"/") != 0);
}

void test_lstack_bad_params_mask_addr(void)
{
    /* lstack start mask_addr empty */
    CU_ASSERT(lstack_bad_param("/^mask_addr/cmask_addr=/") != 0);

    /* lstack start mask_addr none */
    CU_ASSERT(lstack_bad_param("/^mask_addr/d") != 0);

    /* lstack start mask_addr invaild str */
    CU_ASSERT(lstack_bad_param("/^mask_addr/cmask_addr=\"aaa\"/") != 0);

    /* lstack start mask_addr exceed str */
    CU_ASSERT(lstack_bad_param("/^mask_addr/cmask_addr=\"256.255.255.0\"/") != 0);

    /* lstack start mask_addr exceed str */
    CU_ASSERT(lstack_bad_param("/^mask_addr/cmask_addr=\"255.254.255.0\"/") != 0);
}

void test_lstack_bad_params_gateway_addr(void)
{
    /* lstack start gateway_addr empty */
    CU_ASSERT(lstack_bad_param("/^gateway_addr/cgateway_addr=/") != 0);

    /* lstack start gateway_addr none */
    CU_ASSERT(lstack_bad_param("/^gateway_addr/d") != 0);

    /* lstack start gateway_addr invaild str */
    CU_ASSERT(lstack_bad_param("/^gateway_addr/cgateway_addr=\"aaa\"/") != 0);

    /* lstack start gateway_addr exceed str */
    CU_ASSERT(lstack_bad_param("/^gateway_addr/cgateway_addr=\"192.168.1.256\"/") != 0);
}

void test_lstack_bad_params_devices(void)
{
    /* lstack start devices empty */
    CU_ASSERT(lstack_bad_param("/^devices/cdevices=/") != 0);

    /* lstack start devices none */
    CU_ASSERT(lstack_bad_param("/^devices/d") != 0);

    /* lstack start devices invaild str */
    CU_ASSERT(lstack_bad_param("/^devices/cdevices=\"aaa\"/") != 0);

    /* lstack start devices exceed str */
    CU_ASSERT(lstack_bad_param("/^devices/cdevices=\"ff:ff:ff:ff:ff:ff:ff\"/") != 0);

    /* lstack start devices exceed str */
    CU_ASSERT(lstack_bad_param("/^devices/cdevices=\"ff:ff:ff:ff:ff-ff\"/") != 0);

    /* lstack start devices exceed str */
    CU_ASSERT(lstack_bad_param("/^devices/cdevices=\"ff:ff:ff:ff:ff:fg\"/") != 0);
}

void test_lstack_normal_param(void)
{
    int ret;
    char ip_str[16] = {0}; /* 16:IP max len */
    char str[18] = {0};
    const char *config_file_path = "../lstack/config/lstack.conf";

    ret = parse_conf_file(config_file_path);
    CU_ASSERT(ret == 0);
    struct cfg_params *global_params = get_global_cfg_params();
    for (int i =0; i< global_params->dpdk_argc; i++)
        printf("arcv is %s\n", global_params->dpdk_argv[i]);

    CU_ASSERT(global_params->dpdk_argc == 9); /* 9:参数个数 */
    CU_ASSERT(strcmp(global_params->dpdk_argv[0], "lstack") == 0);
    CU_ASSERT(strcmp(global_params->dpdk_argv[1], "--socket-mem") == 0); /* 1:lstack 参数 */
    CU_ASSERT(strcmp(global_params->dpdk_argv[2], "2048,0,0,0") == 0);  /* 2:lstack 参数 */
    CU_ASSERT(strcmp(global_params->dpdk_argv[3], "--huge-dir") == 0); /* 3:lstack socket内存参数 */
    CU_ASSERT(strcmp(global_params->dpdk_argv[4], "/mnt/hugepages-2M") == 0); /* 4:lstack socket内存值 */
    CU_ASSERT(strcmp(global_params->dpdk_argv[5], "--proc-type") == 0); /* 5:lstack huge路径参数 */
    CU_ASSERT(strcmp(global_params->dpdk_argv[6], "primary") == 0); /* 6:lstack huge路径值 */
    CU_ASSERT(strcmp(global_params->dpdk_argv[7], "-l") == 0);  /* 7:lstack进程类型参数 */
    CU_ASSERT(strcmp(global_params->dpdk_argv[8], "0,2,4") == 0); /* 8:lstack参数 */

    struct in_addr tmp_subnet;
    tmp_subnet.s_addr = global_params->host_addr.addr;
    char *subnet_str = strdup(inet_ntop(AF_INET, &tmp_subnet, ip_str, sizeof(ip_str)));
    CU_ASSERT(subnet_str != NULL);
    CU_ASSERT(strcmp(subnet_str, "192.168.1.10") == 0);
    free(subnet_str);

    tmp_subnet.s_addr = global_params->netmask.addr;
    subnet_str = strdup(inet_ntop(AF_INET, &tmp_subnet, ip_str, sizeof(ip_str)));
    CU_ASSERT(subnet_str != NULL);
    CU_ASSERT(strcmp(subnet_str, "255.255.255.0") == 0);
    free(subnet_str);

    tmp_subnet.s_addr = global_params->gateway_addr.addr;
    subnet_str = strdup(inet_ntop(AF_INET, &tmp_subnet, ip_str, sizeof(ip_str)));
    CU_ASSERT(subnet_str != NULL);
    CU_ASSERT(strcmp(subnet_str, "192.168.1.1") == 0);
    free(subnet_str);

    /* MAC地址转换为字符串 */
    ret = sprintf_s(str, sizeof(str), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", global_params->mac_addr[0],
        global_params->mac_addr[1],
        global_params->mac_addr[2], // 2mac地址
        global_params->mac_addr[3], // 3mac地址
        global_params->mac_addr[4], // 4mac地址
        global_params->mac_addr[5]); // 5mac地址
    CU_ASSERT(ret > 0);
    CU_ASSERT(strcmp(str, "aa:bb:cc:dd:ee:ff") == 0); /* 匹配的MAC地址 */
}
