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

#include <netinet/in.h>
#include <sys/socket.h>
#include <libconfig.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>
#include <securec.h>

#include "ltran_errno.h"
#include "ltran_base.h"
#include "ltran_log.h"
#include "common/gazelle_dfx_msg.h"
#include "common/gazelle_base_func.h"
#include "ltran_param.h"

#define HEX_BASE 16

#define PARAM_DISPATCH_SUB_NET          "dispatch_subnet"
#define PARAM_FORWARD_KIT_ARGS          "forward_kit_args"
#define PARAM_DISPATCH_MAX_CLIENT       "dispatch_max_clients"
#define PARAM_DISPATCH_SUB_NET_LENGTH   "dispatch_subnet_length"
#define PARAM_BOND_MIIMON               "bond_miimon"
#define PARAM_BOND_MODE                 "bond_mode"
#define PARAM_BOND_PORTS                "bond_ports"
#define PARAM_BOND_MTU                  "bond_mtu"
#define PARAM_KNI_SWITCH                "kni_switch"
#define PARAM_BOND_TX_QUEUE_NUM         "bond_tx_queue_num"
#define PARAM_BOND_RX_QUEUE_NUM         "bond_rx_queue_num"
#define PARAM_BOND_MACS                 "bond_macs"
#define PARAM_TCP_CONN_SCAN_INTERVAL    "tcp_conn_scan_interval"
#define PARAM_UNIX_PREFIX               "unix_prefix"
#define PARAM_RX_MBUF_POOL_SIZE         "rx_mbuf_pool_size"
#define PARAM_TX_MBUF_POOL_SIZE         "tx_mbuf_pool_size"

static struct ltran_config g_ltran_config = {0};
struct ltran_config* get_ltran_config(void)
{
    return &g_ltran_config;
}

static int32_t parse_str2mac(char *mac_str, uint8_t *ether_addr)
{
    const char *delim = ":";
    char *token = NULL;
    unsigned long one_bit_mac;
    char *end = NULL;

    char *tmp = NULL;
    int32_t i = 0;
    token = strtok_s(mac_str, delim, &tmp);
    while (token != NULL && *token != '\0') {
        one_bit_mac = strtoul(token, &end, HEX_BASE);
        if ((end == NULL) || (*end != '\0')) {
            gazelle_set_errno(GAZELLE_EMAC);
            return GAZELLE_ERR;
        }
        if (one_bit_mac > UINT8_MAX) {
            gazelle_set_errno(GAZELLE_ERANGE);
            return GAZELLE_ERR;
        }

        if (i >= ETHER_ADDR_LEN) {
            gazelle_set_errno(GAZELLE_EPARAM);
            return GAZELLE_ERR;
        }
        token = strtok_s(NULL, delim, &tmp);
        ether_addr[i++] = (uint8_t)one_bit_mac;
    }

    if (i != ETHER_ADDR_LEN) {
        gazelle_set_errno(GAZELLE_EMAC);
        return GAZELLE_ERR;
    }
    return GAZELLE_OK;
}

void param_resource_destroy(struct ltran_config *ltran_config)
{
    if (ltran_config->dpdk.dpdk_argv != NULL) {
        for (int32_t i = 0; i < ltran_config->dpdk.dpdk_argc; i++) {
            GAZELLE_FREE(ltran_config->dpdk.dpdk_argv[i]);
        }
        GAZELLE_FREE(ltran_config->dpdk.dpdk_argv);
    }
}

static int32_t parse_forward_kit_args_single(char *dpdk_str, size_t len, struct ltran_config *ltran_config)
{
    (void)len;
    do {
        ltran_config->dpdk.dpdk_argc = 0;
        ltran_config->dpdk.dpdk_argv = calloc(GAZELLE_MAX_DPDK_ARGS_NUM, sizeof(char *));
        if (ltran_config->dpdk.dpdk_argv == NULL) {
            gazelle_set_errno(GAZELLE_ENOMEM);
            break;
        }

        ltran_config->dpdk.dpdk_argv[0] = strdup(PROGRAM_NAME);
        if (ltran_config->dpdk.dpdk_argv[0] == NULL) {
            gazelle_set_errno(GAZELLE_ENOMEM);
            break;
        }
        ltran_config->dpdk.dpdk_argc = 1;

        char *tmp = NULL;
        const char *delim = " ";
        char *token = strtok_s(dpdk_str, delim, &tmp);
        while (token != NULL) {
            if (ltran_config->dpdk.dpdk_argc == GAZELLE_MAX_DPDK_ARGS_NUM) {
                gazelle_set_errno(GAZELLE_ERANGE);
                break;
            }
            ltran_config->dpdk.dpdk_argv[ltran_config->dpdk.dpdk_argc] = strdup(token);
            if (ltran_config->dpdk.dpdk_argv[ltran_config->dpdk.dpdk_argc] == NULL) {
                gazelle_set_errno(GAZELLE_ENOMEM);
                break;
            }
            ltran_config->dpdk.dpdk_argc++;
            token = strtok_s(NULL, delim, &tmp);
        }
    } while (0);

    if (gazelle_get_errno() != GAZELLE_SUCCESS) {
        /* all param release at last */
        return GAZELLE_ERR;
    }
    return GAZELLE_OK;
}

static int32_t parse_forward_kit_args(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    const char *forward_kit_args = NULL;
    int32_t ret = config_lookup_string(config, key, &forward_kit_args);
    if (ret == 0) {
        gazelle_set_errno(GAZELLE_EPARAM);
        return GAZELLE_ERR;
    }

    char *dpdk_str = strdup(forward_kit_args);
    if (dpdk_str == NULL) {
        gazelle_set_errno(GAZELLE_ENOMEM);
        return GAZELLE_ERR;
    }

    ret = parse_forward_kit_args_single(dpdk_str, strlen(dpdk_str), ltran_config);
    free(dpdk_str);

    if (ret != GAZELLE_OK) {
        return GAZELLE_ERR;
    }
    return GAZELLE_OK;
}

static int32_t parse_dispatch_subnet(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    struct in_addr subnet_addr = {0};
    const char *subnet = NULL;
    int32_t ret = config_lookup_string(config, key, &subnet);
    if (ret == 0) {
        gazelle_set_errno(GAZELLE_EPARAM);
        return GAZELLE_ERR;
    }

    ret = inet_aton(subnet, &subnet_addr);
    if (ret == 0) {
        gazelle_set_errno(GAZELLE_EINETATON);
        return GAZELLE_ERR;
    }

    ltran_config->dispatcher.ipv4_subnet_addr.s_addr = ntohl(subnet_addr.s_addr);
    return GAZELLE_OK;
}

static int32_t parse_dispatch_subnet_length(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    int32_t subnet_length;
    int32_t ret;
    ret = config_lookup_int(config, key, &subnet_length);
    if (ret == 0) {
        gazelle_set_errno(GAZELLE_EPARAM);
        return GAZELLE_ERR;
    }

    if ((subnet_length < GAZELLE_SUBNET_LENGTH_MIN) || (subnet_length > GAZELLE_SUBNET_LENGTH_MAX)) {
        gazelle_set_errno(GAZELLE_ERANGE);
        return GAZELLE_ERR;
    }

    ltran_config->dispatcher.ipv4_subnet_size = 1 << (uint32_t)subnet_length;
    ltran_config->dispatcher.ipv4_subnet_length = subnet_length;
    ltran_config->dispatcher.ipv4_net_mask = ltran_config->dispatcher.ipv4_subnet_size - 1;

    ret = ltran_config->dispatcher.ipv4_subnet_addr.s_addr & (~ltran_config->dispatcher.ipv4_net_mask);
    if (ret == 0) {
        gazelle_set_errno(GAZELLE_ENETADDR);
        LTRAN_ERR("subnet's net addr can NOT be 0\n");
        return GAZELLE_ERR;
    }
    ret = ltran_config->dispatcher.ipv4_subnet_addr.s_addr & ltran_config->dispatcher.ipv4_net_mask;
    if (ret != 0) {
        gazelle_set_errno(GAZELLE_EHOSTADDR);
        LTRAN_ERR("subnet's host addr must be 0. ret=%d.\n", ret);
        return GAZELLE_ERR;
    }

    return GAZELLE_OK;
}

static int32_t parse_dispatch_max_client(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    int32_t max_client;
    int32_t ret;
    ret = config_lookup_int(config, key, &max_client);
    if (ret == 0) {
        gazelle_set_errno(GAZELLE_EPARAM);
        return GAZELLE_ERR;
    }

    if ((max_client < GAZELLE_CLIENT_NUM_MIN) || (max_client > GAZELLE_CLIENT_NUM)) {
        gazelle_set_errno(GAZELLE_ERANGE);
        return GAZELLE_ERR;
    }

    ltran_config->dispatcher.num_clients = max_client;
    return GAZELLE_OK;
}

static int32_t parse_bond_mode(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    int32_t bond_mode;
    int32_t ret;
    ret = config_lookup_int(config, key, &bond_mode);
    if (ret == 0) {
        gazelle_set_errno(GAZELLE_EPARAM);
        return GAZELLE_ERR;
    }

    if ((bond_mode < GAZELLE_BOND_MODE_MIN) || (bond_mode > GAZELLE_BOND_MODE_MAX)) {
        gazelle_set_errno(GAZELLE_ERANGE);
        return GAZELLE_ERR;
    }

    ltran_config->bond.mode = bond_mode;
    return GAZELLE_OK;
}

static int32_t parse_bond_miimon(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    int32_t bond_miimon;
    int32_t ret;
    ret = config_lookup_int(config, key, &bond_miimon);
    if (ret == 0) {
        gazelle_set_errno(GAZELLE_EPARAM);
        return GAZELLE_ERR;
    }

    if (bond_miimon <= GAZELLE_BOND_MIIMON_MIN) {
        gazelle_set_errno(GAZELLE_ERANGE);
        return GAZELLE_ERR;
    }

    ltran_config->bond.miimon = bond_miimon;
    return GAZELLE_OK;
}

static int32_t parse_bond_mtu(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    int32_t bond_mtu;
    int32_t ret;
    ret = config_lookup_int(config, key, &bond_mtu);
    if (ret == 0) {
        gazelle_set_errno(GAZELLE_EPARAM);
        return GAZELLE_ERR;
    }

    if ((bond_mtu < GAZELLE_BOND_MTU_MIN) || (bond_mtu > GAZELLE_BOND_MTU_MAX)) {
        gazelle_set_errno(GAZELLE_ERANGE);
        return GAZELLE_ERR;
    }

    ltran_config->bond.mtu = bond_mtu;
    return GAZELLE_OK;
}

static int32_t is_bond_port_prefix_valid(const char *port_str)
{
    const char prefix[] = "0x";
    const uint32_t prefix_len = 2;

    if (strlen(port_str) < prefix_len) {
        return GAZELLE_ERR;
    }

    for (uint32_t i = 0; i < prefix_len; i++) {
        if (port_str[i] != prefix[i]) {
            return GAZELLE_ERR;
        }
    }

    return GAZELLE_OK;
}

static int32_t parse_bond_ports(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    const char *port_mask_str = NULL;
    int32_t ret;

    ret = config_lookup_string(config, key, &port_mask_str);
    if (ret == 0) {
        gazelle_set_errno(GAZELLE_EPARAM);
        return GAZELLE_ERR;
    }

    char *port_str = strdup(port_mask_str);
    if (port_str == NULL) {
        gazelle_set_errno(GAZELLE_ENOMEM);
        return GAZELLE_ERR;
    }

    ret = is_bond_port_prefix_valid(port_str);
    if (ret != GAZELLE_OK) {
        syslog(LOG_ERR, "Err: bond_port should start with 0x, please check configuration. ret=%d\n", ret);
        gazelle_set_errno(GAZELLE_EPARAM);
        free(port_str);
        return GAZELLE_ERR;
    }

    ltran_config->bond.port_num = separate_str_to_array(port_str, ltran_config->bond.portmask,
                                                        GAZELLE_MAX_BOND_NUM, UINT16_MAX);

    if (ltran_config->bond.port_num > GAZELLE_MAX_BOND_NUM) {
        free(port_str);
        gazelle_set_errno(GAZELLE_ERANGE);
        return GAZELLE_ERR;
    }

    for (uint32_t i = 0; i < ltran_config->bond.port_num; i++) {
        if (ltran_config->bond.portmask[i] < GAZELLE_BOND_PORT_MASK_MIN ||
            ltran_config->bond.portmask[i] > GAZELLE_BOND_PORT_MASK_MAX) {
            free(port_str);
            gazelle_set_errno(GAZELLE_ERANGE);
            return GAZELLE_ERR;
        }
    }

    free(port_str);
    return GAZELLE_OK;
}


static int32_t parse_bond_tx_queue_num(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    (void)key;
    (void)config;
    int32_t bond_tx_queue_num = GAZELLE_TX_QUEUES;

    if ((bond_tx_queue_num < GAZELLE_BOND_QUEUE_MIN) || (bond_tx_queue_num > GAZELLE_BOND_QUEUE_MAX)) {
        gazelle_set_errno(GAZELLE_ERANGE);
        syslog(LOG_ERR, "Err: bond_tx_queue_num out of range: 1 ~ 64.\n");
        return GAZELLE_ERR;
    }

    ltran_config->bond.tx_queue_num = bond_tx_queue_num;
    return GAZELLE_OK;
}

static int32_t parse_bond_rx_queue_num(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    (void)key;
    (void)config;
    int32_t bond_rx_queue_num = GAZELLE_RX_QUEUES;

    if ((bond_rx_queue_num < GAZELLE_BOND_QUEUE_MIN) || (bond_rx_queue_num > GAZELLE_BOND_QUEUE_MAX)) {
        gazelle_set_errno(GAZELLE_ERANGE);
        syslog(LOG_ERR, "Err: bond_rx_queue_num out of range: 1 ~ 64.\n");
        return GAZELLE_ERR;
    }

    ltran_config->bond.rx_queue_num = bond_rx_queue_num;
    return GAZELLE_OK;
}

static int32_t check_bond_dup_mac(const struct ltran_config *ltran_config)
{
    uint32_t i, j;
    for (i = 0; i < ltran_config->bond.mac_num; i++) {
        for (j = i + 1; j < ltran_config->bond.mac_num; j++) {
            if (is_same_mac_addr(ltran_config->bond.mac[i].addr_bytes, ltran_config->bond.mac[j].addr_bytes)) {
                syslog(LOG_ERR, "Err:MAC address must be unique, same MAC %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
                    ltran_config->bond.mac[i].addr_bytes[0], /* 0 byte index */
                    ltran_config->bond.mac[i].addr_bytes[1], /* 1 byte index */
                    ltran_config->bond.mac[i].addr_bytes[2], /* 2 byte index */
                    ltran_config->bond.mac[i].addr_bytes[3], /* 3 byte index */
                    ltran_config->bond.mac[i].addr_bytes[4], /* 4 byte index */
                    ltran_config->bond.mac[i].addr_bytes[5]); /* 5 byte index */
                gazelle_set_errno(GAZELLE_EMAC);
                return GAZELLE_ERR;
            }
        }
    }
    return GAZELLE_OK;
}

static void macs_cache_free(char **bond_mac_cache, int32_t cnt, int32_t max_cnt)
{
    if ((bond_mac_cache == NULL) || (cnt > max_cnt)) {
        return;
    }

    for (int32_t i = 0; i < cnt; i++) {
        GAZELLE_FREE(bond_mac_cache[i]);
    }
}

static void parse_bond_macs_separate(const char *bond_macs_str, char **bond_mac_cache, int32_t cache_cnt,
    int32_t *real_cnt)
{
    char *bond_macs = strdup(bond_macs_str);
    if (bond_macs == NULL) {
        gazelle_set_errno(GAZELLE_ENOMEM);
        return;
    }

    char *tmp = NULL;
    const char *delim = ",";
    char *token = strtok_s(bond_macs, delim, &tmp);
    while (token != NULL) {
        if (*real_cnt == cache_cnt) {
            gazelle_set_errno(GAZELLE_ERANGE);
            break;
        }

        bond_mac_cache[*real_cnt] = strdup(token);
        if (bond_mac_cache[*real_cnt] == NULL) {
            gazelle_set_errno(GAZELLE_ENOMEM);
            break;
        }

        (*real_cnt)++;
        token = strtok_s(NULL, delim, &tmp);
    }

    free(bond_macs);
}

static int32_t parse_bond_macs(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    const char *bond_macs_str = NULL;
    int32_t bond_mac_cache_count = 0;
    char *bond_mac_cache[GAZELLE_MAX_BOND_NUM];
    int32_t ret;

    ret = config_lookup_string(config, key, &bond_macs_str);
    if (ret == 0) {
        gazelle_set_errno(GAZELLE_EPARAM);
        return GAZELLE_ERR;
    }

    parse_bond_macs_separate(bond_macs_str, bond_mac_cache, GAZELLE_MAX_BOND_NUM, &bond_mac_cache_count);

    for (int32_t j = 0; j < bond_mac_cache_count; j++) {
        ret = parse_str2mac(bond_mac_cache[j], ltran_config->bond.mac[ltran_config->bond.mac_num].addr_bytes);
        if (ret != GAZELLE_OK) {
            break;
        }
        ltran_config->bond.mac_num++;
    }

    if (ltran_config->bond.port_num != ltran_config->bond.mac_num) {
        gazelle_set_errno(GAZELLE_ECONSIST);
    }

    macs_cache_free(bond_mac_cache, bond_mac_cache_count, GAZELLE_MAX_BOND_NUM);
    if (gazelle_get_errno() != GAZELLE_SUCCESS) {
        return GAZELLE_ERR;
    }

    return check_bond_dup_mac(ltran_config);
}

static int32_t parse_kni_switch(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    int32_t ret;
    int32_t kni_switch = GAZELLE_OFF;
    ret = config_lookup_int(config, key, &kni_switch);
    if (ret == 0) {
        syslog(LOG_ERR, "Err: kni switch not set, default OFF. ret=%d\n", ret);
        ltran_config->dpdk.kni_switch = GAZELLE_OFF;
        return GAZELLE_OK;
    }

    if ((kni_switch != GAZELLE_ON) && (kni_switch != GAZELLE_OFF)) {
        gazelle_set_errno(GAZELLE_ERANGE);
        return GAZELLE_ERR;
    }

    ltran_config->dpdk.kni_switch = kni_switch;
    return GAZELLE_OK;
}

static int32_t parse_tcp_conn_scan_interval(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    int32_t ret;
    int32_t interval_time = GAZELLE_TCP_CONN_SCAN_INTERVAL_DEFAULT_S;
    ret = config_lookup_int(config, key, &interval_time);
    if (ret == 0) {
        syslog(LOG_INFO, "tcp_conn_scan_interval not set, set default value %d. ret=%d\n",
            GAZELLE_TCP_CONN_SCAN_INTERVAL_DEFAULT_S, ret);
        ltran_config->tcp_conn.tcp_conn_scan_interval = (unsigned long)(GAZELLE_TCP_CONN_SCAN_INTERVAL_DEFAULT_S) *
                                                        SEC_TO_USEC;
        return GAZELLE_OK;
    }

    if ((interval_time < GAZELLE_TCP_CONN_SCAN_INTERVAL_MIN_S) ||
        (interval_time > GAZELLE_TCP_CONN_SCAN_INTERVAL_MAX_S)) {
        gazelle_set_errno(GAZELLE_ERANGE);
        return GAZELLE_ERR;
    }

    ltran_config->tcp_conn.tcp_conn_scan_interval = (unsigned long)(interval_time) * SEC_TO_USEC;
    return GAZELLE_OK;
}

typedef int32_t (*param_parse_func)(const config_t *, const char *, struct ltran_config *);

struct param_parser {
    char param_name[GAZELLE_MAX_NAME_LEN];
    param_parse_func func;
};

static int32_t parse_unix_prefix(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    const char *prefix = NULL;
    int32_t ret = 0;

    ret = memset_s(ltran_config->unix_socket_filename, sizeof(ltran_config->unix_socket_filename),
        0, sizeof(ltran_config->unix_socket_filename));
    if (ret != EOK) {
        gazelle_set_errno(GAZELLE_EINETATON);
        return GAZELLE_ERR;
    }

    ret = memset_s(ltran_config->dfx_socket_filename, sizeof(ltran_config->dfx_socket_filename),
        0, sizeof(ltran_config->dfx_socket_filename));
    if (ret != EOK) {
        gazelle_set_errno(GAZELLE_EINETATON);
        return GAZELLE_ERR;
    }

    ret = strncpy_s(ltran_config->unix_socket_filename, sizeof(ltran_config->unix_socket_filename),
        GAZELLE_RUN_DIR, strlen(GAZELLE_RUN_DIR) + 1);
    if (ret != EOK) {
        gazelle_set_errno(GAZELLE_EINETATON);
        return GAZELLE_ERR;
    }

    ret = strncpy_s(ltran_config->dfx_socket_filename, sizeof(ltran_config->dfx_socket_filename),
        GAZELLE_RUN_DIR, strlen(GAZELLE_RUN_DIR) + 1);
    if (ret != EOK) {
        gazelle_set_errno(GAZELLE_EINETATON);
        return GAZELLE_ERR;
    }

    ret = config_lookup_string(config, key, &prefix);
    if (ret) {
        if (filename_check(prefix)) {
            gazelle_set_errno(GAZELLE_EINETATON);
            return GAZELLE_ERR;
        }

        ret = strncat_s(ltran_config->unix_socket_filename, sizeof(ltran_config->unix_socket_filename),
            prefix, strlen(prefix) + 1);
        if (ret != EOK) {
            gazelle_set_errno(GAZELLE_EINETATON);
            return GAZELLE_ERR;
        }

        ret = strncat_s(ltran_config->dfx_socket_filename, sizeof(ltran_config->dfx_socket_filename),
            prefix, strlen(prefix) + 1);
        if (ret != EOK) {
            gazelle_set_errno(GAZELLE_EINETATON);
            return GAZELLE_ERR;
        }
    }

    ret = strncat_s(ltran_config->unix_socket_filename, sizeof(ltran_config->unix_socket_filename),
        GAZELLE_REG_SOCK_FILENAME, strlen(GAZELLE_REG_SOCK_FILENAME) + 1);
    if (ret != EOK) {
        gazelle_set_errno(GAZELLE_EINETATON);
        return GAZELLE_ERR;
    }

    ret = strncat_s(ltran_config->dfx_socket_filename, sizeof(ltran_config->dfx_socket_filename),
        GAZELLE_DFX_SOCK_FILENAME, strlen(GAZELLE_DFX_SOCK_FILENAME) + 1);
    if (ret != EOK) {
        gazelle_set_errno(GAZELLE_EINETATON);
        return GAZELLE_ERR;
    }

    return GAZELLE_OK;
}

static int32_t parse_rx_mbuf_pool_size(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    int32_t ret;
    int32_t rx_mbuf_pool_size = 0;
    ret = config_lookup_int(config, key, &rx_mbuf_pool_size);
    if (ret == 0) {
        ltran_config->rx_mbuf_pool_size = GAZELLE_MBUFS_RX_COUNT;
        return GAZELLE_OK;
    }

    ltran_config->rx_mbuf_pool_size = rx_mbuf_pool_size;
    return GAZELLE_OK;
}

static int32_t parse_tx_mbuf_pool_size(const config_t *config, const char *key, struct ltran_config *ltran_config)
{
    int32_t ret;
    int32_t tx_mbuf_pool_size = 0;
    ret = config_lookup_int(config, key, &tx_mbuf_pool_size);
    if (ret == 0) {
        ltran_config->tx_mbuf_pool_size = GAZELLE_MBUFS_TX_COUNT;
        return GAZELLE_OK;
    }

    ltran_config->tx_mbuf_pool_size = tx_mbuf_pool_size;
    return GAZELLE_OK;
}

struct param_parser g_param_parse_tbl[] = {
    {PARAM_FORWARD_KIT_ARGS,        parse_forward_kit_args},
    {PARAM_DISPATCH_MAX_CLIENT,     parse_dispatch_max_client},
    {PARAM_DISPATCH_SUB_NET,        parse_dispatch_subnet},
    {PARAM_DISPATCH_SUB_NET_LENGTH, parse_dispatch_subnet_length},
    {PARAM_BOND_MIIMON,             parse_bond_miimon},
    {PARAM_BOND_MODE,               parse_bond_mode},
    {PARAM_BOND_PORTS,              parse_bond_ports},
    {PARAM_BOND_MTU,                parse_bond_mtu},
    {PARAM_BOND_MACS,               parse_bond_macs},
    {PARAM_BOND_RX_QUEUE_NUM,       parse_bond_rx_queue_num},
    {PARAM_BOND_TX_QUEUE_NUM,       parse_bond_tx_queue_num},
    {PARAM_TCP_CONN_SCAN_INTERVAL,  parse_tcp_conn_scan_interval},
    {PARAM_KNI_SWITCH,              parse_kni_switch},
    {PARAM_UNIX_PREFIX,             parse_unix_prefix},
    {PARAM_RX_MBUF_POOL_SIZE,       parse_rx_mbuf_pool_size},
    {PARAM_TX_MBUF_POOL_SIZE,       parse_tx_mbuf_pool_size},
};

int32_t parse_config_file_args(const char *conf_file_path, struct ltran_config *ltran_config)
{
    config_t config;
    config_init(&config);
    int32_t ret;

    ret = memset_s(ltran_config, sizeof(struct ltran_config), 0, sizeof(struct ltran_config));
    if (ret != 0) {
        config_destroy(&config);
        syslog(LOG_ERR, "memset_s failed\n");
        return ret;
    }
    ret = config_read_file(&config, conf_file_path);
    if (ret == 0) {
        config_destroy(&config);
        syslog(LOG_ERR, "Err: Config file path %s error, Please check conf file path.\n", conf_file_path);
        return -GAZELLE_EPATH;
    }

    int32_t param_num = sizeof(g_param_parse_tbl) / sizeof(g_param_parse_tbl[0]);
    for (int32_t i = 0; i < param_num; i++) {
        gazelle_set_errno(GAZELLE_SUCCESS);
        ret = g_param_parse_tbl[i].func(&config, g_param_parse_tbl[i].param_name, ltran_config);
        if (ret != GAZELLE_OK) {
            config_destroy(&config);
            LTRAN_ERR("parse args %s error!. errno: %d ret=%d\n", g_param_parse_tbl[i].param_name, gazelle_get_errno(),
                ret);
            return ret;
        }
    }

    config_destroy(&config);
    return GAZELLE_OK;
}

bool is_same_mac_addr(const uint8_t *smac, const uint8_t *dmac)
{
    for (int32_t i = 0; i < ETHER_ADDR_LEN; i++) {
        if (smac[i] != dmac[i]) {
            return false;
        }
    }
    return true;
}
