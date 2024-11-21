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
#include "ltran_param.h"

#define MAX_CMD_LEN 1024

static int execute_cmd(const char *cmd)
{
    int ret;
    ret = system(cmd);
    if (ret < 0) {
        printf("Executing cmd: %s error!!!\n", cmd);
        abort();
    }
    return ret;
}

static void restore_tmp_config(void)
{
    execute_cmd("rm -rf ../ltran/config/ltran_tmp.conf");
    execute_cmd("cp -f ../ltran/config/ltran.conf ../ltran/config/ltran_tmp.conf");
}

static int ltran_bad_param(const char *conf_file_filed)
{
    int ret;
    struct ltran_config ltran_conf;
    const char *conf_file_path = "../ltran/config/ltran_tmp.conf";
    char cmd[MAX_CMD_LEN];

    restore_tmp_config();
    gazelle_set_errno(GAZELLE_SUCCESS);

    ret = sprintf_s(cmd, MAX_CMD_LEN, "sed -i '%s' %s", conf_file_filed, conf_file_path);
    if (ret < 0) {
        printf("sprintf_s return error!!!\n");
        return ret;
    }

    execute_cmd(cmd);

    ret = parse_config_file_args(conf_file_path, &ltran_conf);

    return ret;
}

void test_ltran_bad_params_clients(void)
{
    /* ltran start negative client */
    CU_ASSERT(ltran_bad_param("s/dispatch_max_clients = 32/dispatch_max_clients = -1/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start 0 client */
    CU_ASSERT(ltran_bad_param("s/dispatch_max_clients = 32/dispatch_max_clients = 0/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start 999 client */
    CU_ASSERT(ltran_bad_param("s/dispatch_max_clients = 32/dispatch_max_clients = 999/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start str client */
    CU_ASSERT(ltran_bad_param("s/dispatch_max_clients = 32/dispatch_max_clients = \"aaa\"/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EPARAM);

    /* ltran start none client */
    CU_ASSERT(ltran_bad_param("s/dispatch_max_clients = 32//") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EPARAM);

    /* ltran start empty client */
    CU_ASSERT(ltran_bad_param("s/dispatch_max_clients = 32/dispatch_max_clients = /") == -GAZELLE_EPATH);
}

void test_ltran_bad_params_port(void)
{
    /* ltran start zero port */
    CU_ASSERT(ltran_bad_param("s/0x3/0x0/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start max port */
    CU_ASSERT(ltran_bad_param("s/0x3/0xff/") == 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_SUCCESS);

    /* ltran start str port */
    CU_ASSERT(ltran_bad_param("s/0x3/aaa/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EPARAM);

    /* ltran start none port */
    CU_ASSERT(ltran_bad_param("s/bond_ports = \"0x3, 0xC\"//") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EPARAM);

    /* ltran start empty port */
    CU_ASSERT(ltran_bad_param("s/bond_ports = \"0x3, 0xC\"/bond_ports = /") == -GAZELLE_EPATH);

    /* ltran start exceed max port */
    CU_ASSERT(ltran_bad_param("s/bond_ports = \"0x3, 0xC\"/bond_ports = \"0xffffffff\"/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);
}

void test_ltran_bad_params_subnet(void)
{
    /* ltran start bad subnet */
    CU_ASSERT(ltran_bad_param("s/dispatch_subnet =/cdispatch_subnet = \"aaa\"/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EPARAM);

    /* ltran start empty subnet */
    CU_ASSERT(ltran_bad_param("/^dispatch_subnet /cdispatch_subnet=") == -GAZELLE_EPATH);

    /* ltran start none subnet */
    CU_ASSERT(ltran_bad_param("/dispatch_subnet =/d") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EPARAM);

    /* ltran start not match subnet */
    CU_ASSERT(ltran_bad_param("s/.0\"/.1\"/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EHOSTADDR);

    /* ltran start error subnet */
    CU_ASSERT(ltran_bad_param("s/1.0\"/288.0\"/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EINETATON);

    /* ltran start exceed subnet length */
    CU_ASSERT(ltran_bad_param("s/dispatch_subnet_length = 8/dispatch_subnet_length = 17/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start exceed subnet length */
    CU_ASSERT(ltran_bad_param("s/dispatch_subnet_length = 8/dispatch_subnet_length = 0/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start str subnet length */
    CU_ASSERT(ltran_bad_param("s/dispatch_subnet_length = 8/dispatch_subnet_length = aaa/") == -GAZELLE_EPATH);

    /* ltran start empty subnet length */
    CU_ASSERT(ltran_bad_param("s/dispatch_subnet_length = 8/dispatch_subnet_length = /") == -GAZELLE_EPATH);

    /* ltran start none subnet length */
    CU_ASSERT(ltran_bad_param("s/dispatch_subnet_length = 8//") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EPARAM);
}

void test_ltran_bad_params_bond_mode(void)
{
    /* ltran start negative bond mode */
    CU_ASSERT(ltran_bad_param("s/bond_mode = 1/bond_mode = -1/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start unsupport bond mode0 */
    CU_ASSERT(ltran_bad_param("s/bond_mode = 1/bond_mode = 0/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start unsupport bond mode2 */
    CU_ASSERT(ltran_bad_param("s/bond_mode = 1/bond_mode = 2/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start empty bond mode */
    CU_ASSERT(ltran_bad_param("/^bond_mode /cbond_mode =") == -GAZELLE_EPATH);

    /* ltran start unsupport none mode2 */
    CU_ASSERT(ltran_bad_param("s/bond_mode = 1//") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EPARAM);
}

void test_ltran_bad_params_bond_miimon(void)
{
    /* ltran start negative bond miimon */
    CU_ASSERT(ltran_bad_param("s/bond_miimon = 100/bond_miimon = -1/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start zero bond miimon */
    CU_ASSERT(ltran_bad_param("s/bond_miimon = 100/bond_miimon = 0/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start max bond miimon */
    CU_ASSERT(ltran_bad_param("s/bond_miimon = 100/bond_miimon = 2147483647/") == 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_SUCCESS);

    /* ltran start exceed str bond miimon */
    CU_ASSERT(ltran_bad_param("s/bond_miimon = 100/bond_miimon = aaa/") == -GAZELLE_EPATH);

    /* ltran start empty bond miimon */
    CU_ASSERT(ltran_bad_param("s/bond_miimon = 100/bond_miimon = /") == -GAZELLE_EPATH);

    /* ltran start none bond miimon */
    CU_ASSERT(ltran_bad_param("s/bond_miimon = 100//") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EPARAM);
}

void test_ltran_bad_params_bond_mtu(void)
{
    /* ltran start negative bond mtu */
    CU_ASSERT(ltran_bad_param("s/bond_mtu = 1500/bond_mtu = -1/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start exceed min bond mtu */
    CU_ASSERT(ltran_bad_param("s/bond_mtu = 1500/bond_mtu = 67/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start exceed max bond mtu */
    CU_ASSERT(ltran_bad_param("s/bond_mtu = 1500/bond_mtu = 1501/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ERANGE);

    /* ltran start str bond mtu */
    CU_ASSERT(ltran_bad_param("s/bond_mtu = 1500/bond_mtu = aaa/") == -GAZELLE_EPATH);

    /* ltran start empty bond mtu */
    CU_ASSERT(ltran_bad_param("s/bond_mtu = 1500/bond_mtu = /") == -GAZELLE_EPATH);

    /* ltran start none bond mtu */
    CU_ASSERT(ltran_bad_param("s/bond_mtu = 1500//") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EPARAM);
}

void test_ltran_bad_params_macs(void)
{
    /* ltran start max macs */
    CU_ASSERT(ltran_bad_param("s/52:54:00:25:ef:e0/ff:ff:ff:ff:ff:ff/") == 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_SUCCESS);

    /* ltran start error macs */
    CU_ASSERT(ltran_bad_param("s/52:54:00:25:ef:e0/ff:ff:ff:ff:ff:fg/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ECONSIST);

    /* ltran start error macs */
    CU_ASSERT(ltran_bad_param("s/52:54:00:25:ef:e0/ff:ff:ff:ff:ff:ff:ff/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ECONSIST);

    /* ltran start error macs */
    CU_ASSERT(ltran_bad_param("s/52:54:00:25:ef:e0/ff:ff:ff:ff:ff-ff/") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ECONSIST);

    /* ltran start empty macs */
    CU_ASSERT(ltran_bad_param("s/52:54:00:25:ef:e0, aa:bb:cc:dd:ee:ff//") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_ECONSIST);

    /* ltran start none macs */
    CU_ASSERT(ltran_bad_param("s/bond_macs = \"52:54:00:25:ef:e0, aa:bb:cc:dd:ee:ff\"//") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EPARAM);

    /* ltran start duplicated macs */
    CU_ASSERT(ltran_bad_param("/bond_macs/cbond_macs = \"52:54:00:25:ef:e0, 52:54:00:25:ef:e0\"") != 0);
    CU_ASSERT(gazelle_get_errno() == GAZELLE_EMAC);
}

void check_bond_param(const struct ltran_config *ltran_conf)
{
    CU_ASSERT(ltran_conf->bond.mode == 1);
    CU_ASSERT(ltran_conf->bond.miimon == 100); /* 100:bond链路监控时间 */
    CU_ASSERT(ltran_conf->bond.mtu == 1500); /* 1500:bond mtu值 */
    CU_ASSERT(ltran_conf->bond.port_num == 2); /* 2:bond port数目 */
    CU_ASSERT(ltran_conf->bond.portmask[0] == 3); /* 3:bond mac端口掩码 */
    CU_ASSERT(ltran_conf->bond.portmask[1] == 12); /* 12:bond mac端口掩码 */
    CU_ASSERT(ltran_conf->bond.mac_num == 2); /* 2:bond mac地址数目 */
    CU_ASSERT(ltran_conf->bond.mac[0].addr_bytes[0] == 82); /* 82:bond mac地址 */
    CU_ASSERT(ltran_conf->bond.mac[0].addr_bytes[1] == 84); /* 84:bond mac地址 */
    CU_ASSERT(ltran_conf->bond.mac[0].addr_bytes[2] == 0); /* 2:bond mac地址 */
    CU_ASSERT(ltran_conf->bond.mac[0].addr_bytes[3] == 37); /* 3:37:bond mac地址 */
    CU_ASSERT(ltran_conf->bond.mac[0].addr_bytes[4] == 239); /* 4:239:bond mac地址 */
    CU_ASSERT(ltran_conf->bond.mac[0].addr_bytes[5] == 224); /* 5:224:bond mac地址 */
    CU_ASSERT(ltran_conf->bond.mac[1].addr_bytes[0] == 170); /* 170:bond mac地址 */
    CU_ASSERT(ltran_conf->bond.mac[1].addr_bytes[1] == 187); /* 187:bond mac地址 */
    CU_ASSERT(ltran_conf->bond.mac[1].addr_bytes[2] == 204); /* 2:204:bond mac地址 */
    CU_ASSERT(ltran_conf->bond.mac[1].addr_bytes[3] == 221); /* 3:221:bond mac地址 */
    CU_ASSERT(ltran_conf->bond.mac[1].addr_bytes[4] == 238); /* 4:238:bond mac地址 */
    CU_ASSERT(ltran_conf->bond.mac[1].addr_bytes[5] == 255); /* 5:255:bond mac地址 */
}

void test_ltran_normal_param(void)
{
    int ret;
    struct ltran_config ltran_conf;
    char ip_str[16] = {0}; /* 16:IP max len */
    const char *config_file_path = "../ltran/config/ltran.conf";

    (void)memset_s(&ltran_conf, sizeof(struct ltran_config), 0, sizeof(struct ltran_config));
    ret = parse_config_file_args(config_file_path, &ltran_conf);
    CU_ASSERT(ret == GAZELLE_OK);

    struct in_addr tmp_subnet;
    tmp_subnet.s_addr = ntohl(ltran_conf.dispatcher.ipv4_subnet_addr.s_addr);
    char *subnet_str = strdup(inet_ntop(AF_INET, &tmp_subnet, ip_str, sizeof(ip_str)));
    CU_ASSERT(subnet_str != NULL);
    CU_ASSERT(ltran_conf.dpdk.dpdk_argc == 11); /* 11:参数个数 */
    CU_ASSERT(strcmp(ltran_conf.dpdk.dpdk_argv[0], "ltran") == 0);
    CU_ASSERT(strcmp(ltran_conf.dpdk.dpdk_argv[1], "-l") == 0);
    CU_ASSERT(strcmp(ltran_conf.dpdk.dpdk_argv[2], "0,1") == 0); /* 2:ltran绑在0,1核 */
    CU_ASSERT(strcmp(ltran_conf.dpdk.dpdk_argv[3], "--socket-mem") == 0); /* 3:ltran socket内存参数 */
    CU_ASSERT(strcmp(ltran_conf.dpdk.dpdk_argv[4], "1024,0,0,0") == 0); /* 4:ltran socket内存值 */
    CU_ASSERT(strcmp(ltran_conf.dpdk.dpdk_argv[5], "--huge-dir") == 0); /* 5:ltran huge路径参数 */
    CU_ASSERT(strcmp(ltran_conf.dpdk.dpdk_argv[6], "/mnt/hugepages") == 0); /* 6:ltran huge路径值 */
    CU_ASSERT(strcmp(ltran_conf.dpdk.dpdk_argv[7], "--proc-type") == 0); /* 7:ltran进程类型参数 */
    CU_ASSERT(strcmp(ltran_conf.dpdk.dpdk_argv[8], "auto") == 0); /* 8:ltran进程类型值 */
    CU_ASSERT(strcmp(ltran_conf.dpdk.dpdk_argv[9], "-n") == 0); /* 9:ltran处理器socket内存通道数目 */
    CU_ASSERT(strcmp(ltran_conf.dpdk.dpdk_argv[10], "4") == 0); /* 10:ltran处理器socket内存通道数值 */
    CU_ASSERT(ltran_conf.dpdk.kni_switch == 0);
    CU_ASSERT(strcmp(subnet_str, "192.168.1.0") == 0);
    CU_ASSERT(ltran_conf.dispatcher.ipv4_subnet_length == 8); /* 8:ipv4子网长度, 表示ltran能识别的子网长度 */
    CU_ASSERT(ltran_conf.dispatcher.ipv4_subnet_size == 256); /* 256:ipv4子网大小 */
    CU_ASSERT(ltran_conf.dispatcher.ipv4_net_mask == 255); /* 255:ipv4掩码 */
    CU_ASSERT(ltran_conf.dispatcher.num_clients == 32); /* 32:client 数目 */
    check_bond_param(&ltran_conf);
    free(subnet_str);
}
