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

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <securec.h>
#include <unistd.h>
#include <rte_log.h>
#include <rte_ethdev.h>

#include <lwip/dpdk_version.h>

#include "ltran_stat.h"
#include "ltran_base.h"
#include "common/gazelle_dfx_msg.h"

/* seeing show_usage() */
#define GAZELLE_TARGET_ARG_IDX   1
#define GAZELLE_COMMAND_ARG_IDX  2
#define GAZELLE_OPTIONS_ARG_IDX  3
#define GAZELLE_OPTIONS1_ARG_IDX 4
#define GAZELLE_OPTIONS2_ARG_IDX 5
#define GAZELLE_OPTIONS3_ARG_IDX 6
#define GAZELLE_OPT_LPM_ARG_IDX1 5

#define GAZELLE_PARAM_MINNUM     2
#define GAZELLE_LTRAN_PARAM_NUM  3
#define GAZELLE_LSTACK_PARAM_NUM 4

#define GAZELLE_LTRAN_SET_MINNUM 5
#define GAZELLE_LSTACK_SET_MINNUM 6

#define GAZELLE_CMD_MAX          5
#define CMD_WAIT_TIME            1   // sec

#define GAZELLE_DECIMAL          10
#define GAZELLE_KEEPALIVE_STR_LEN 35
#define GAZELLE_TIME_STR_LEN 25

static int32_t g_unix_fd = -1;
static int32_t g_ltran_rate_show_flag = GAZELLE_OFF;    // not show when first get total statistics
static struct gazelle_stat_ltran_total g_last_ltran_total;
static struct gazelle_stat_lstack_total g_last_lstack_total[GAZELLE_MAX_STACK_ARRAY_SIZE];
static struct gazelle_stack_dfx_data g_last_lstack_data[GAZELLE_MAX_STACK_ARRAY_SIZE];

#ifdef GAZELLE_FAULT_INJECT_ENABLE
#define INJECT_NAME_SIZE 32
#define INJECT_RULE_SIZE 32

typedef int32_t  (*inject_parse_digit_fun)(char*, char*, struct gazelle_stat_msg_request *req_msg);
static int32_t parse_inject_packet_delay_digit(char *time, char *range, struct gazelle_stat_msg_request *req_msg);
static int32_t parse_inject_packet_loss_digit(char *rate, char *count, struct gazelle_stat_msg_request *req_msg);
static int32_t parse_inject_packet_duplicate_digit(char *rate, char *count, struct gazelle_stat_msg_request *req_msg);
static int32_t parse_inject_packet_reorder_digit(char *rate, char *count, struct gazelle_stat_msg_request *req_msg);

struct gazelle_fault_inject_type_list {
    char inject_type_item[INJECT_NAME_SIZE];
    enum GAZELLE_FAULT_INJECT_TYPE inject_type_parsed;
    inject_parse_digit_fun parse_digit_func;
};

static struct gazelle_fault_inject_type_list inject_type_list[] = {
    {"loss",      GAZELLE_FAULT_INJECT_PACKET_LOSS,       parse_inject_packet_loss_digit},
    {"reorder",  GAZELLE_FAULT_INJECT_PACKET_REORDER,   parse_inject_packet_reorder_digit},
    {"delay",     GAZELLE_FAULT_INJECT_PACKET_DELAY,      parse_inject_packet_delay_digit},
    {"duplicate", GAZELLE_FAULT_INJECT_PACKAET_DUPLICATE, parse_inject_packet_duplicate_digit},
};

struct gazelle_fault_inject_rule_list {
    char inject_rule_item[INJECT_RULE_SIZE];
    enum GAZELLE_FAULT_INJECT_RULE inject_rule_parsed;
    enum GAZELLE_FAULT_INJECT_TYPE rule_parse_assit;
};

static struct gazelle_fault_inject_rule_list g_gazelle_fault_inject_rule_list[] = {
    {"random",     INJECT_DELAY_RANDOM,         GAZELLE_FAULT_INJECT_PACKET_DELAY},
    {"random",     INJECT_LOSS_RANDOM,          GAZELLE_FAULT_INJECT_PACKET_LOSS},
    {"random",      INJECT_DUPLICATE_RANDOM,     GAZELLE_FAULT_INJECT_PACKAET_DUPLICATE},
    {"random",      INJECT_REORDER_RANDOM,      GAZELLE_FAULT_INJECT_PACKET_REORDER},
};

static void gazelle_print_fault_inject_set_status(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_fault_inject_unset_status(void *buf, const struct gazelle_stat_msg_request *req_msg);
#endif /* GAZELLE_FAULT_INJECT_ENABLE */

static bool g_use_ltran = false;
static char g_ltran_unix_path[PATH_MAX];
static char g_lstack_unix_path[PATH_MAX];

static char* g_unix_prefix;

/* Use the largest data structure. */
#define GAZELLE_CMD_RESP_BUFFER_SIZE (sizeof(struct gazelle_stack_dfx_data) / sizeof(char))

typedef void (*print_stat_func)(void *buf, const struct gazelle_stat_msg_request *req_msg);

struct gazelle_dfx_list {
    enum GAZELLE_STAT_MODE stat_mode;
    size_t recv_size;
    print_stat_func print_func;
};

static void gazelle_print_ltran_stat_total(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_stat_rate(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_stat_lb_rate(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_stat_client(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_stat_burst(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_stat_latency(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_wait(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_start_latency(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_total(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_rate(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_snmp(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_virtio(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_conn(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_latency(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_lpm(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_sock(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_conn(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_xstats(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_aggregate(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_nic_features(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_proto(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_total_stat_memory(void *buf,  const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_memory(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_socket_stat_memory(uint32_t idx, struct gazelle_socket_mem_info *socket_info);
static void gazelle_print_lstack_mem_general(
    struct gazelle_stack_dfx_data *buf,
    const struct gazelle_stat_msg_request *req_msg
);

#ifdef GAZELLE_FAULT_INJECT_ENABLE
static void gazelle_print_fault_inject_set_status(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_fault_inject_unset_status(void *buf, const struct gazelle_stat_msg_request *req_msg);
#endif /* GAZELLE_FAULT_INJECT_ENABLE */

static struct gazelle_dfx_list g_gazelle_dfx_tbl[] = {
    {GAZELLE_STAT_LTRAN_SHOW,          sizeof(struct gazelle_stat_ltran_total),  gazelle_print_ltran_stat_total},
    {GAZELLE_STAT_LTRAN_SHOW_RATE,     sizeof(struct gazelle_stat_ltran_total),  gazelle_print_ltran_stat_rate},
    {GAZELLE_STAT_LTRAN_SHOW_LB_RATE,     sizeof(struct gazelle_stat_lstack_total),  gazelle_print_ltran_stat_lb_rate},
    {GAZELLE_STAT_LTRAN_SHOW_INSTANCE, sizeof(struct gazelle_stat_ltran_client), gazelle_print_ltran_stat_client},
    {GAZELLE_STAT_LTRAN_SHOW_BURST,    sizeof(struct gazelle_stat_ltran_total),  gazelle_print_ltran_stat_burst},
    {GAZELLE_STAT_LTRAN_SHOW_LATENCY,  sizeof(struct in_addr),                  gazelle_print_ltran_stat_latency},
    {GAZELLE_STAT_LTRAN_QUIT,          0,                                       gazelle_print_ltran_wait},
    {GAZELLE_STAT_LTRAN_START_LATENCY, 0,                                       gazelle_print_ltran_start_latency},
    {GAZELLE_STAT_LTRAN_STOP_LATENCY,  0,                                       gazelle_print_ltran_wait},
    {GAZELLE_STAT_LTRAN_LOG_LEVEL_SET, 0,                                       gazelle_print_ltran_wait},
    {GAZELLE_STAT_LTRAN_SHOW_SOCKTABLE, sizeof(struct gazelle_stat_forward_table), gazelle_print_ltran_sock},
    {GAZELLE_STAT_LTRAN_SHOW_CONNTABLE, sizeof(struct gazelle_stat_forward_table), gazelle_print_ltran_conn},

    {GAZELLE_STAT_LTRAN_SHOW_LSTACK,   sizeof(struct gazelle_stat_lstack_total), gazelle_print_lstack_stat_total},
    {GAZELLE_STAT_LSTACK_SHOW,         sizeof(struct gazelle_stack_dfx_data), gazelle_print_lstack_stat_total},

    {GAZELLE_STAT_LSTACK_LOG_LEVEL_SET, 0,                                      gazelle_print_ltran_wait},
    {GAZELLE_STAT_LSTACK_SHOW_RATE,    sizeof(struct gazelle_stack_dfx_data), gazelle_print_lstack_stat_rate},
    {GAZELLE_STAT_LSTACK_SHOW_SNMP,    sizeof(struct gazelle_stack_dfx_data),  gazelle_print_lstack_stat_snmp},
    {GAZELLE_STAT_LSTACK_SHOW_VIRTIO,  sizeof(struct gazelle_stack_dfx_data),  gazelle_print_lstack_stat_virtio},
    {GAZELLE_STAT_LSTACK_SHOW_CONN,    sizeof(struct gazelle_stack_dfx_data),  gazelle_print_lstack_stat_conn},
    {GAZELLE_STAT_LSTACK_SHOW_LATENCY, sizeof(struct gazelle_stack_dfx_data),  gazelle_print_lstack_stat_latency},
    {GAZELLE_STAT_LSTACK_LOW_POWER_MDF, sizeof(struct gazelle_stack_dfx_data),  gazelle_print_lstack_stat_lpm},
    {GAZELLE_STAT_LSTACK_SHOW_XSTATS, sizeof(struct gazelle_stack_dfx_data), gazelle_print_lstack_xstats},
    {GAZELLE_STAT_LSTACK_SHOW_AGGREGATE, sizeof(struct gazelle_stack_dfx_data), gazelle_print_lstack_aggregate},
    {GAZELLE_STAT_LSTACK_SHOW_NIC_FEATURES, sizeof(struct gazelle_stack_dfx_data), gazelle_print_lstack_nic_features},
    {GAZELLE_STAT_LSTACK_SHOW_PROTOCOL,    sizeof(struct gazelle_stack_dfx_data),  gazelle_print_lstack_stat_proto},
    {GAZELLE_STAT_LSTACK_SHOW_MEMORY_USAGE, sizeof(struct gazelle_stack_dfx_data), gazelle_print_total_stat_memory}
    
#ifdef GAZELLE_FAULT_INJECT_ENABLE
    {GAZELLE_STAT_FAULT_INJECT_SET, sizeof(struct gazelle_stack_dfx_data), gazelle_print_fault_inject_set_status},
    {GAZELLE_STAT_FAULT_INJECT_UNSET, sizeof(struct gazelle_stack_dfx_data), gazelle_print_fault_inject_unset_status},
#endif /* GAZELLE_FAULT_INJECT_ENABLE */
};

static int32_t g_wait_reply = 1;
static int32_t g_repeat_time = 0;
static int32_t g_repeat_interval = 1;

static double rate_convert_type(uint64_t bytes, char **type)
{
    static char *rate_type[] = {"b/s", "Kb/s", "Mb/s"};
    const uint32_t per_unit = 1024; // 1KB=1024B
    double now = bytes * 8;
    uint32_t type_max = sizeof(rate_type) / sizeof(char *);
    uint32_t index = 0;

    while (now > per_unit && index < type_max - 1) {
        now /= per_unit;
        index++;
    }

    *type = rate_type[index];
    return now;
}

static void gazelle_print_lstack_xstats(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    struct gazelle_stack_dfx_data *stat = (struct gazelle_stack_dfx_data *)buf;
    struct nic_eth_xstats *xstats = &stat->data.nic_xstats;
    static const char *nic_stats_border = "########################";

    printf("###### NIC extended statistics for port %-2d #########\n", xstats->port_id);
    if (xstats->bonding.mode >= 0) {
        printf("############# NIC bonding mode display #############\n");
        printf("%s############################\n", nic_stats_border);
        printf("Bonding mode: [%d]\n", xstats->bonding.mode);
        printf("Bonding miimon: [%d]\n", xstats->bonding.miimon);
        printf("Slaves(%d): [", xstats->bonding.slave_count);
        for (int i = 0; i < xstats->bonding.slave_count - 1; i++) {
            printf("%d ", xstats->bonding.slaves[i]);
        }
        printf("%d]\n", xstats->bonding.slaves[xstats->bonding.slave_count - 1]);
        printf("Primary: [%d]\n", xstats->bonding.primary_port_id);
    }
    printf("%s############################\n", nic_stats_border);
    if (xstats->len <= 0 || xstats->len > RTE_ETH_XSTATS_MAX_LEN) {
        printf("xstats item(%d) num error!\n", xstats->len);
        return;
    }

    for (uint32_t i = 0; i < xstats->len; i++) {
        printf("%s: %"PRIu64"\n", xstats->xstats_name[i].name, xstats->values[i]);
    }

    printf("%s############################\n", nic_stats_border);
}

static void gazelle_print_lstack_nic_features(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    struct nic_eth_features *f = &(((struct gazelle_stack_dfx_data *)buf)->data.nic_features);
    printf("###### NIC offload and other features for port %-2d #########\n", f->port_id);

    printf("tx-ipv4-checksum: %s\n", (f->tx_offload & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) ? "on" : "off");
    printf("tx-tcp-checksum: %s\n", (f->tx_offload & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) ? "on" : "off");
    printf("tx-tcp-tso: %s\n", (f->tx_offload & RTE_ETH_TX_OFFLOAD_TCP_TSO) ? "on" : "off");
    printf("tx-udp-checksum: %s\n", (f->tx_offload & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) ? "on" : "off");
    printf("tx-vlan-insert: %s\n", (f->tx_offload & RTE_ETH_TX_OFFLOAD_VLAN_INSERT) ? "on" : "off");

    printf("rx-ipv4-checksum: %s\n", (f->rx_offload & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM) ? "on" : "off");
    printf("rx-tcp-checksum: %s\n", (f->rx_offload & RTE_ETH_RX_OFFLOAD_TCP_CKSUM) ? "on" : "off");
    printf("rx-udp-checksum: %s\n", (f->rx_offload & RTE_ETH_RX_OFFLOAD_UDP_CKSUM) ? "on" : "off");
    printf("rx-vlan-strip: %s\n", (f->rx_offload & RTE_ETH_RX_OFFLOAD_VLAN_STRIP) ? "on" : "off");
}

static void gazelle_print_ltran_conn(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    struct gazelle_stat_forward_table *table = (struct gazelle_stat_forward_table *)buf;
    char addr[GAZELLE_INET_ADDRSTRLEN];

    (void)req_msg;
    printf("ltran conn table:\n");
    printf("tid         protocol  src_ip          src_port  dst_ip          dst_port\n");
    for (uint32_t i = 0; i < table->conn_num && i < GAZELLE_LSTACK_MAX_CONN; i++) {
        printf("%-12u", table->conn_list[i].tid);
        printf("%-10u", table->conn_list[i].protocol);
        (void)inet_ntop(AF_INET, &table->conn_list[i].src_ip, addr, sizeof(addr));
        printf("%-16s", addr);
        printf("%-10u", (uint32_t)table->conn_list[i].src_port);
        (void)inet_ntop(AF_INET, &table->conn_list[i].dst_ip, addr, sizeof(addr));
        printf("%-16s", addr);
        printf("%-7u\n", (uint32_t)table->conn_list[i].dst_port);
    }
    printf("ltran conn table num: %u\n", table->conn_num);
}

static void gazelle_print_ltran_sock(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    struct gazelle_stat_forward_table *table = (struct gazelle_stat_forward_table *)buf;
    char addr[GAZELLE_INET_ADDRSTRLEN];

    (void)req_msg;
    printf("ltran sock table:\n");
    printf("tid         listen_ip       listen_port    conn_num\n");
    for (uint32_t i = 0; i < table->conn_num && i < GAZELLE_LSTACK_MAX_CONN; i++) {
        printf("%-12u", table->conn_list[i].tid);
        (void)inet_ntop(AF_INET, &table->conn_list[i].dst_ip, addr, sizeof(addr));
        printf("%-16s", addr);
        printf("%-15u", (uint32_t)table->conn_list[i].dst_port);
        printf("%-7u\n", table->conn_list[i].conn_num);
    }
    printf("ltran sock table num: %u\n", table->conn_num);
}

static int dfx_make_unix_addr(struct sockaddr_un *addr, bool use_ltran)
{
    int ret;
    ret = memset_s(addr, sizeof(*addr), 0, sizeof(struct sockaddr_un));
    if (ret != EOK) {
        printf("%s:%d memset_s fail ret=%d\n", __FUNCTION__, __LINE__, ret);
        goto END;
    }

    ret = strncpy_s(addr->sun_path, sizeof(addr->sun_path), GAZELLE_RUN_DIR,
                    strlen(GAZELLE_RUN_DIR) + 1);
    if (ret != EOK) {
        printf("%s:%d strncpy_s fail ret=%d\n", __FUNCTION__, __LINE__, ret);
        goto END;
    }

    if (g_unix_prefix) {
        ret = strncat_s(addr->sun_path, sizeof(addr->sun_path), g_unix_prefix,
                        strlen(g_unix_prefix) + 1);
        if (ret != EOK) {
            printf("%s:%d strncat_s fail ret=%d\n", __FUNCTION__, __LINE__, ret);
            goto END;
        }
    }

    addr->sun_family = AF_UNIX;
    if (use_ltran) {
        ret = strncat_s(addr->sun_path, sizeof(addr->sun_path), LTRAN_DFX_SOCK_FILENAME,
            strlen(LTRAN_DFX_SOCK_FILENAME) + 1);
        if (ret != EOK) {
            printf("%s:%d strncat_s fail ret=%d\n", __FUNCTION__, __LINE__, ret);
            goto END;
        }
        memcpy_s(g_ltran_unix_path, PATH_MAX, addr->sun_path, sizeof(addr->sun_path));
    } else {
        ret = strncat_s(addr->sun_path, sizeof(addr->sun_path), LSTACK_DFX_SOCK_FILENAME,
            strlen(LSTACK_DFX_SOCK_FILENAME) + 1);
        if (ret != EOK) {
            printf("%s:%d strncat_s fail ret=%d\n", __FUNCTION__, __LINE__, ret);
            goto END;
        }
        memcpy_s(g_lstack_unix_path, PATH_MAX, addr->sun_path, sizeof(addr->sun_path));
    }
       return 0;
END:
       return -1;
}

static int32_t dfx_connect_server(bool use_ltran)
{
    int32_t ret, fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        printf("create socket failed. errno: %d\n", errno);
        return GAZELLE_ERR;
    }

    ret = dfx_make_unix_addr(&addr, use_ltran);
       if (ret != 0) {
               goto END;
       }

    ret = connect(fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    if (ret != 0) {
        goto END;
    }

    return fd;
END:
    ret = errno;
    close(fd);
    return -ret;
}

static int dfx_connect_probe(void)
{
    int32_t ret1;
    int32_t ret2;
    ret1 = dfx_connect_server(true);
    if (ret1 > 0) {
        close(ret1);
        return 1;
    }
    ret2 = dfx_connect_server(false);
    if (ret2 > 0) {
        close(ret2);
        return 0;
    }

    printf("Connect lstack(path:%s) failed, errno: %d; Connect ltran(path:%s) failed, errno: %d\n",
        g_lstack_unix_path, -ret2, g_ltran_unix_path, -ret1);
    printf("Please ensure the process is started; If use ltran mode, "
           "set use_ltran=1 in lstack.conf, otherwise set use_ltran=0\n");
    return -1;
}

static int32_t dfx_stat_conn_to_ltran(struct gazelle_stat_msg_request *req_msg)
{
    int32_t fd = dfx_connect_server(g_use_ltran);
    if (fd < 0) {
        if (g_use_ltran) {
            printf("Connect ltran(path:%s) failed. errno: %d\n", g_ltran_unix_path, -fd);
        } else {
            printf("Connect lstack(path:%s) failed. errno: %d\n", g_lstack_unix_path, -fd);
        }
        return GAZELLE_ERR;
    }

    int32_t ret = write_specied_len(fd, (char *)req_msg, sizeof(*req_msg));
    if (ret == -1) {
        printf("write request msg failed ret=%d\n", ret);
        close(fd);
        return GAZELLE_ERR;
    }

    g_unix_fd = fd;
    return GAZELLE_OK;
}

static struct gazelle_dfx_list *find_dfx_node(enum GAZELLE_STAT_MODE stat_mode)
{
    for (uint32_t i = 0; i < sizeof(g_gazelle_dfx_tbl) / sizeof(g_gazelle_dfx_tbl[0]); i++) {
        if (g_gazelle_dfx_tbl[i].stat_mode == stat_mode) {
            return &g_gazelle_dfx_tbl[i];
        }
    }

    printf("stat_mode=%d outrange\n", (int32_t)stat_mode);
    return NULL;
}

static int32_t dfx_stat_read_from_ltran(char *buf, uint32_t len, enum GAZELLE_STAT_MODE mode)
{
    int32_t ret;
    char *tmp_pbuf = buf;
    int32_t fd = g_unix_fd;
    struct gazelle_dfx_list *dfx = NULL;
    dfx = find_dfx_node(mode);
    if (dfx == NULL) {
        close(fd);
        g_unix_fd = -1;
        return GAZELLE_ERR;
    }

    if (dfx->recv_size != 0) {
        ret = read_specied_len(fd, tmp_pbuf, dfx->recv_size);
        if (ret == -1) {
            printf("read stat response msg failed ret=%d\n", ret);
            close(fd);
            g_unix_fd = -1;
            return GAZELLE_ERR;
        }
    }

    return GAZELLE_OK;
}

static const char *tcp_state_to_str(enum GAZELLE_TCP_STATE state)
{
    switch (state) {
        case GAZELLE_TCP_STATE_CLS:
            return "CLOSED";
        case GAZELLE_TCP_STATE_LSN:
            return "LISTEN";
        case GAZELLE_TCP_STATE_S_S:
            return "SYN_SENT";
        case GAZELLE_TCP_STATE_S_R:
            return "SYN_RECVD";
        case GAZELLE_TCP_STATE_ESTB:
            return "ESTABLISHED";
        case GAZELLE_TCP_STATE_FW1:
            return "FIN_WAIT_1";
        case GAZELLE_TCP_STATE_FW2:
            return "FIN_WAIT_2";
        case GAZELLE_TCP_STATE_CW:
            return "CLOSE_WAIT";
        case GAZELLE_TCP_STATE_CLSING:
            return "CLOSING";
        case GAZELLE_TCP_STATE_LA:
            return "LAST_ACK";
        case GAZELLE_TCP_STATE_TW:
            return "TIME_WAIT";
        default:
            break;
    }

    return "UNKNOWN";
}

static char* get_loglevel_string(int32_t level)
{
    switch (level) {
        case RTE_LOG_INFO:
            return "info";
        case RTE_LOG_DEBUG:
            return "debug";
        case RTE_LOG_ERR:
            return "error";
        default:
            return "unknown";
    }
}

static void gazelle_print_ltran_stat_total(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    uint32_t i;
    struct gazelle_stat_ltran_total *stat = (struct gazelle_stat_ltran_total *)buf;

    (void)req_msg;
    printf("Statistics of ltran:\n");
    for (i = 0; i < stat->port_num; i++) {
        struct gazelle_stat_ltran_port *port_stat = &stat->port_list[i];
        printf("\nBond port: %-14u", i);
        printf("loglevel: %-15s \n", get_loglevel_string(port_stat->loglevel));
        printf("rx_pkts: %-15"PRIu64" ", port_stat->rx);
        printf("rx_bytes: %-15"PRIu64" ", port_stat->rx_bytes);
        printf("rx_drop: %-15"PRIu64"\n", port_stat->rx_drop);
        printf("tx_pkts: %-15"PRIu64" ", port_stat->tx);
        printf("tx_bytes: %-15"PRIu64" ", port_stat->tx_bytes);
        printf("tx_drop: %-15"PRIu64"\n", port_stat->tx_drop);
        printf("kni_pkts:%-15"PRIu64" ", port_stat->kni_pkt);
        printf("arp_pkts: %-15"PRIu64" ", port_stat->arp_pkt);
        printf("tcp_pkts: %-15"PRIu64" ", port_stat->tcp_pkt);
        printf("icmp_pkts: %-15"PRIu64"\n", port_stat->icmp_pkt);
    }
}

static void gazelle_print_ltran_stat_rate(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    uint32_t i;
    double rate;
    int32_t ret;
    char *rate_type = NULL;
    struct gazelle_stat_ltran_total *stat = (struct gazelle_stat_ltran_total *)buf;

    (void)req_msg;
    if (g_ltran_rate_show_flag == GAZELLE_ON) {
        for (i = 0; i < stat->port_num; i++) {
            struct gazelle_stat_ltran_port *port_stat = &stat->port_list[i];
            struct gazelle_stat_ltran_port *last_port_stat = &g_last_ltran_total.port_list[i];
            printf("\nBond port %u:\n", i);
            printf("rx_pkts: %-15"PRIu64" ", (port_stat->rx - last_port_stat->rx) / GAZELLE_DFX_REQ_INTERVAL_S);
            rate = rate_convert_type((port_stat->rx_bytes - last_port_stat->rx_bytes) / GAZELLE_DFX_REQ_INTERVAL_S,
                                     &rate_type);
            printf("rx_bytes: %7.2lf%s  ", rate, rate_type);
            printf("rx_drop: %-15"PRIu64"\n", (port_stat->rx_drop - last_port_stat->rx_drop) /
                   GAZELLE_DFX_REQ_INTERVAL_S);
            printf("tx_pkts: %-15"PRIu64" ", (port_stat->tx - last_port_stat->tx) / GAZELLE_DFX_REQ_INTERVAL_S);
            rate = rate_convert_type((port_stat->tx_bytes - last_port_stat->tx_bytes) / GAZELLE_DFX_REQ_INTERVAL_S,
                                     &rate_type);
            printf("tx_bytes: %7.2lf%s  ", rate, rate_type);
            printf("tx_drop: %-15"PRIu64"\n", (port_stat->tx_drop - last_port_stat->tx_drop) /
                    GAZELLE_DFX_REQ_INTERVAL_S);
        }
    } else {
        printf("Statistics of ltran rate:\n");
        g_ltran_rate_show_flag = GAZELLE_ON;
    }

    ret = memcpy_s(&g_last_ltran_total, sizeof(g_last_ltran_total), stat, sizeof(struct gazelle_stat_ltran_total));
    if (ret != EOK) {
        printf("%s:%d memcpy_s fail ret=%d\n", __FUNCTION__, __LINE__, ret);
    }
}

static void gazelle_print_ltran_wait(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    (void)buf;
    (void)req_msg;
    sleep(CMD_WAIT_TIME); // give ltran time to read cmd
}

static void gazelle_print_ltran_start_latency(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    (void)buf;
    (void)req_msg;
    if (g_wait_reply == 0) {
        g_wait_reply = 1;
    }
    (void)sleep((uint32_t)g_wait_reply);
}

static void gazelle_print_ltran_stat_latency(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    struct in_addr *ip_addr = (struct in_addr *)buf;
    struct gazelle_stat_lstack_total *stat = (struct gazelle_stat_lstack_total *)((char *)buf + sizeof(*ip_addr));
    uint64_t total_rx = 0;
    double total_latency = 0;
    uint64_t max = 0;
    uint64_t min = ~((uint64_t)0);
    char str_ip[GAZELLE_SUBNET_LENGTH_MAX] = {0};

    (void)req_msg;
    uint32_t ret = (uint32_t)read_specied_len(g_unix_fd, (char *)stat, sizeof(*stat));

    printf("Statistics of ltran latency:  t0--->t1  \
        (t0:read form nic  t1:into lstask queue  t2:into app queue)\n");
    printf("                                      pkts        min(us)     max(us)     average(us)\n");
    do {
        if ((stat->eof != 0) || (ret != GAZELLE_OK)) {
            break;
        }

        printf("ip: %-15s  tid: %-8u    ", inet_ntop(AF_INET, ip_addr, str_ip, sizeof(str_ip)), stat->tid);
        if (stat->latency_pkts > 0) {
            printf("%-8"PRIu64"    ", stat->latency_pkts);
            printf("%-6"PRIu64"      ", stat->latency_min);
            printf("%-6"PRIu64"      ", stat->latency_max);
            printf("%-6.2f \n", (double)stat->latency_total / stat->latency_pkts);
        } else {
            printf("0\n");
        }

        max = (max > stat->latency_max) ? max : stat->latency_max;
        min = (min < stat->latency_min) ? min : stat->latency_min;
        total_latency += stat->latency_total;
        total_rx += stat->latency_pkts;

        ret |= (uint32_t)read_specied_len(g_unix_fd, (char *)ip_addr, sizeof(*ip_addr));
        ret |= (uint32_t)read_specied_len(g_unix_fd, (char *)stat, sizeof(*stat));
    } while (true);

    if (total_rx > 0) {
        printf("                          total:      ");
        printf("%-8"PRIu64"    ", total_rx);
        printf("%-6"PRIu64"      ", min);
        printf("%-6"PRIu64"      ", max);
        printf("%-6.2f \n", total_latency / total_rx);
    } else {
        printf("                          total:      0\n");
    }
}

static void gazelle_print_ltran_stat_client(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    uint32_t i;
    char str_ip[GAZELLE_SUBNET_LENGTH_MAX] = {0};
    struct gazelle_stat_ltran_client *stat = (struct gazelle_stat_ltran_client *)buf;

    (void)req_msg;
    printf("Statistics of ltran client:\n");
    printf("Client IP           ID       pid         stack_cnt       sockfd       Bond port       State\n");
    for (i = 0; i < stat->client_num; i++) {
        struct gazelle_stat_client_info *client_info = &stat->client_info[i];
        printf("%-18s  ", inet_ntop(AF_INET, &client_info->ip, str_ip, sizeof(str_ip)));
        printf("%-7u  ", client_info->id);
        printf("%-10u  ", client_info->pid);
        printf("%-14u  ", client_info->stack_cnt);
        printf("%-11d  ", client_info->sockfd);
        switch (client_info->state) {
            case GAZELLE_CLIENT_STATE_NORMAL:
                printf("%-14u  ", client_info->bond_port);
                printf("NORMAL\n");
                break;
            case GAZELLE_CLIENT_STATE_CONNECTING:
                printf("%-14s  ", "NULL");
                printf("CONNECTING\n");
                break;
            case GAZELLE_CLIENT_STATE_RECONNECTING:
                printf("%-14s  ", "NULL");
                printf("NORMAL\n\n");
                break;
            default:
                printf("\n");
                break;
        }
    }
}

static void gazelle_print_ltran_stat_burst(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    uint64_t sum, diff, percent;
    const uint8_t percent_sign = 100;
    struct gazelle_stat_ltran_total *stat = (struct gazelle_stat_ltran_total *)buf;

    (void)req_msg;
    if (g_ltran_rate_show_flag == GAZELLE_ON) {
        for (uint32_t i = 0; i < stat->port_num; i++) {
            struct gazelle_stat_ltran_port *port_stat = &stat->port_list[i];
            struct gazelle_stat_ltran_port *last_port_stat = &g_last_ltran_total.port_list[i];

            printf("\nBond port %u:\n", i);
            sum = 0;
            for (uint32_t j = 1; j <= GAZELLE_PACKET_READ_SIZE; j++) {
                sum += port_stat->rx_iter_arr[j] - last_port_stat->rx_iter_arr[j];
            }
            for (uint32_t j = 1; j <= GAZELLE_PACKET_READ_SIZE; j++) {
                diff = port_stat->rx_iter_arr[j] - last_port_stat->rx_iter_arr[j];
                (sum == 0) ? (percent = 0) : (percent = diff * percent_sign / sum);
                printf("Burst Packets[%2u]: %-15"PRIu64" Percent: %3"PRIu64"%%\n", j, diff, percent);
            }
        }
    } else {
        printf("Statistics of ltran burst:\n");
        g_ltran_rate_show_flag = GAZELLE_ON;
    }

    int32_t ret = memcpy_s(&g_last_ltran_total, sizeof(g_last_ltran_total), stat,
        sizeof(struct gazelle_stat_ltran_total));
    if (ret != EOK) {
        printf("%s:%d memcpy_s fail ret=%d\n", __FUNCTION__, __LINE__, ret);
    }
}

static void gazelle_print_lstack_stat_brief(struct gazelle_stat_lstack_total *stat,
                                            const struct gazelle_stat_msg_request *req_msg)
{
    int32_t ret;

    do {
        printf("\n------ stack tid: %6u ------\n", stat->tid);
        printf("rx_pkts: %-15"PRIu64" ", stat->rx);
        printf("rx_bytes: %-15"PRIu64" ", stat->rx_bytes);
        printf("rx_err: %-15"PRIu64" ", stat->rx_err);
        printf("rx_drop: %-15"PRIu64"\n", stat->rx_drop);
        printf("tx_pkts: %-15"PRIu64" ", stat->tx);
        printf("tx_bytes: %-15"PRIu64" ", stat->tx_bytes);
        printf("tx_err: %-15"PRIu64" ", stat->tx_err);
        printf("tx_drop: %-15"PRIu64"\n", stat->tx_drop);
        printf("backup_mbuf_cnt: %-7"PRIu32" ", stat->backup_mbuf_cnt);
        printf("rx_ring_cnt: %-12"PRIu32" ", stat->rx_ring_cnt);
        printf("tx_ring_cnt: %-11"PRIu32"", stat->tx_ring_cnt);
        printf("reg_ring_cnt: %-7"PRIu32"\n", stat->reg_ring_cnt);

        if (stat->eof != 0) {
            break;
        }

        ret = dfx_stat_read_from_ltran((char *)stat, sizeof(struct gazelle_stat_lstack_total), req_msg->stat_mode);
        if (ret != GAZELLE_OK) {
            break;
        }
    } while (true);
}

static void show_lstack_stats(struct gazelle_stack_dfx_data *lstack_stat)
{
    printf("\n------ stack tid: %6u ------\n", lstack_stat->tid);
    printf("rx_pkts: %-20"PRIu64" ", lstack_stat->data.pkts.stack_stat.rx);
    printf("rx_drop: %-20"PRIu64" ", lstack_stat->data.pkts.stack_stat.rx_drop);
    printf("rx_allocmbuf_fail: %-10"PRIu64"\n", lstack_stat->data.pkts.stack_stat.rx_allocmbuf_fail);
    printf("tx_pkts: %-20"PRIu64" ", lstack_stat->data.pkts.stack_stat.tx);
    printf("tx_drop: %-20"PRIu64" ", lstack_stat->data.pkts.stack_stat.tx_drop);
    printf("tx_allocmbuf_fail: %-10"PRIu64"\n", lstack_stat->data.pkts.stack_stat.tx_allocmbuf_fail);
    printf("app_read: %-19"PRIu64" ", lstack_stat->data.pkts.wakeup_stat.app_read_cnt);
    printf("read_lwip: %-18"PRIu64" ", lstack_stat->data.pkts.stack_stat.read_lwip_cnt);
    printf("read_lwip_drop: %-13"PRIu64" \n", lstack_stat->data.pkts.stack_stat.read_lwip_drop);
    printf("app_write: %-18"PRIu64" ", lstack_stat->data.pkts.wakeup_stat.app_write_cnt);
    printf("write_lwip: %-17"PRIu64" ", lstack_stat->data.pkts.stack_stat.write_lwip_cnt);
    printf("app_write_rpc: %-14"PRIu64" \n", lstack_stat->data.pkts.wakeup_stat.app_write_rpc);
    printf("recv_list: %-18"PRIu64" ", lstack_stat->data.pkts.recv_list_cnt);
    printf("conn_num: %-19hu ", lstack_stat->data.pkts.conn_num);

    printf("kernel_events: %-14"PRIu64"\n", lstack_stat->data.pkts.wakeup_stat.kernel_events);
    printf("wakeup_events: %-14"PRIu64" ", lstack_stat->data.pkts.stack_stat.wakeup_events);
    printf("app_events: %-17"PRIu64" ", lstack_stat->data.pkts.wakeup_stat.app_events);
    printf("read_null: %-18"PRIu64" \n", lstack_stat->data.pkts.wakeup_stat.read_null);
    printf("call_msg: %-19"PRIu64" ", lstack_stat->data.pkts.call_msg_cnt);
    printf("call_alloc_fail: %-12"PRIu64" ", lstack_stat->data.pkts.call_alloc_fail);
    printf("call_null: %-18"PRIu64" \n", lstack_stat->data.pkts.stack_stat.call_null);
    printf("send_pkts_fail: %-13"PRIu64" ", lstack_stat->data.pkts.stack_stat.send_pkts_fail);
    printf("mbuf_pool_freecnt: %-10"PRIu32" \n", lstack_stat->data.pkts.mbufpool_avail_cnt);
    printf("accpet_fail: %-16"PRIu64" ", lstack_stat->data.pkts.stack_stat.accept_fail);
    printf("sock_rx_drop: %-15"PRIu64" ", lstack_stat->data.pkts.stack_stat.sock_rx_drop);
    printf("sock_tx_merge: %-16"PRIu64" \n", lstack_stat->data.pkts.stack_stat.sock_tx_merge);
}

static void gazelle_print_lstack_stat_detail(struct gazelle_stack_dfx_data *lstack_stat,
                                             const struct gazelle_stat_msg_request *req_msg)
{
    int32_t low_power_info_show = 1;

    (void)req_msg;
    do {
        if (g_use_ltran || low_power_info_show == 0) {
            int32_t ret = read_specied_len(g_unix_fd, (char *)lstack_stat, sizeof(*lstack_stat));
            if (ret != GAZELLE_OK) {
                break;
            }
        }

        if (low_power_info_show != 0) {
            if (lstack_stat->low_power_info.low_power_mod == 0) {
                printf("low_power_mode: OFF\n");
            } else {
                printf("low_power_mode: ON, rx_pkts: %u, detect_ms: %ums, pkts_in_detect: %u\n",
                    (uint32_t)lstack_stat->low_power_info.lpm_rx_pkts,
                    lstack_stat->low_power_info.lpm_detect_ms,
                    lstack_stat->low_power_info.lpm_pkts_in_detect);
            }
            printf("loglevel: %s\n", get_loglevel_string(lstack_stat->loglevel));
            low_power_info_show = 0;
        }

        show_lstack_stats(lstack_stat);

        if (lstack_stat->eof) {
            break;
        }
    } while (true);
}

static void gazelle_print_lstack_stat_total(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    if (g_use_ltran) {
        printf("Statistics of lstack:\n");
        gazelle_print_lstack_stat_brief((struct gazelle_stat_lstack_total *)buf, req_msg);
        printf("\n\nStatistics of lstack in app:\n");
    }

    gazelle_print_lstack_stat_detail((struct gazelle_stack_dfx_data *)buf, req_msg);
}

static void parse_thread_latency_result(const struct stack_latency *latency, char *result, size_t max_len,
    int32_t *pos, struct stack_latency *record)
{
    if (latency->latency_pkts > 0) {
        *pos += sprintf_s(result + *pos, max_len, "%-8"PRIu64"    ", latency->latency_pkts);
        *pos += sprintf_s(result + *pos, max_len, "%-8"PRIu64"    ", latency->latency_min);
        *pos += sprintf_s(result + *pos, max_len, "%-8"PRIu64"    ", latency->latency_max);
        *pos += sprintf_s(result + *pos, max_len, "%-6.2f \n",
            (double)latency->latency_total / latency->latency_pkts);
    } else {
        *pos += sprintf_s(result + *pos, max_len, "0\n");
    }

    record->latency_min = (record->latency_min < latency->latency_min) ? record->latency_min : latency->latency_min;
    record->latency_max = (record->latency_max > latency->latency_max) ? record->latency_max : latency->latency_max;
    record->latency_pkts += latency->latency_pkts;
    record->latency_total += latency->latency_total;
}

static void parse_latency_total_result(char *result, size_t max_len, int32_t *pos,
    const struct stack_latency *record)
{
    if (max_len < GAZELLE_RESULT_LINE_LEN) {
        printf("total latency result show failed, out of memory bounds\n");
        return;
    }

    if (record->latency_pkts > 0) {
        *pos += sprintf_s(result + *pos, max_len, "                     total:           ");
        *pos += sprintf_s(result + *pos, max_len, "%-8"PRIu64"    ", record->latency_pkts);
        *pos += sprintf_s(result + *pos, max_len, "%-8"PRIu64"    ", record->latency_min);
        *pos += sprintf_s(result + *pos, max_len, "%-8"PRIu64"    ", record->latency_max);
        *pos += sprintf_s(result + *pos, max_len, "%-6.2f \n\n",
            (double)record->latency_total / record->latency_pkts);
    } else {
        *pos += sprintf_s(result + *pos, max_len, "                     total:           0\n\n");
    }
}

static void gazelle_show_latency_result(const struct gazelle_stat_msg_request *req_msg,
                                        struct gazelle_stack_dfx_data *stat, struct stack_latency *latency,
                                        struct gazelle_latency_result *res)
{
    char str_ip[GAZELLE_SUBNET_LENGTH_MAX] = { 0 };

    if (GAZELLE_RESULT_LEN - res->latency_stat_index < GAZELLE_RESULT_LINE_LEN) {
        printf("too many threads show latency result, out of memory bounds\n");
        return;
    }

    res->latency_stat_index += sprintf_s(res->latency_stat_result + res->latency_stat_index,
        (size_t)(GAZELLE_RESULT_LEN - res->latency_stat_index), "ip: %-15s  tid: %-8u    ",
        inet_ntop(AF_INET, &req_msg->ip, str_ip, sizeof(str_ip)), stat->tid);

    parse_thread_latency_result(latency, res->latency_stat_result,
        (size_t)(GAZELLE_RESULT_LEN - res->latency_stat_index), &res->latency_stat_index, &res->latency_stat_record);
}

static void gazelle_show_latency_result_total(void *buf, const struct gazelle_stat_msg_request *req_msg,
                                              struct gazelle_latency_result *res)
{
    int ret = GAZELLE_OK;
    struct gazelle_stack_dfx_data *stat = (struct gazelle_stack_dfx_data *)buf;
    struct gazelle_stack_latency *latency = &stat->data.latency;

    do {
        for (int i = 0; i < GAZELLE_LATENCY_MAX; i++) {
            gazelle_show_latency_result(req_msg, stat, &latency->latency[i], &res[i]);
        }

        if ((stat->eof != 0) || (ret != GAZELLE_OK)) {
            break;
        }
        ret = dfx_stat_read_from_ltran(buf, sizeof(struct gazelle_stack_dfx_data), req_msg->stat_mode);
    } while (true);

    for (int i = 0; i < GAZELLE_LATENCY_MAX; i++) {
        parse_latency_total_result(res[i].latency_stat_result, (size_t)(GAZELLE_RESULT_LEN - res[i].latency_stat_index),
            &res[i].latency_stat_index, &res[i].latency_stat_record);
    }
}

static void gazelle_print_lstack_stat_latency(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    struct gazelle_latency_result *res = calloc(GAZELLE_LATENCY_MAX, sizeof(struct gazelle_latency_result));
    if (res == NULL) {
        return;
    }

    for (int i = 0; i < GAZELLE_LATENCY_MAX; i++) {
        res[i].latency_stat_record.latency_min = ~((uint64_t)0);
    }

    gazelle_show_latency_result_total(buf, req_msg, res);

    printf("Statistics of lstack latency          pkts        min(us)     max(us)     average(us)\n");
    printf("Recv:\n");

    printf("range: t0--->t1\n%s", res[GAZELLE_LATENCY_INTO_MBOX].latency_stat_result);
    printf("range: t1--->t2\n%s", res[GAZELLE_LATENCY_READ_LWIP].latency_stat_result);
    printf("range: t2--->t3\n%s", res[GAZELLE_LATENCY_READ_APP_CALL].latency_stat_result);
    printf("range: t3--->t4\n%s", res[GAZELLE_LATENCY_READ_LSTACK].latency_stat_result);
    printf("range: t0--->t4\n%s", res[GAZELLE_LATENCY_READ_MAX].latency_stat_result);
    printf("t0: read from nic  t1: into recvmbox  t2: into recvring t3: app read start  t4: app read end\n");

    printf("Send:\n");
    printf("range: t0--->t1\n%s", res[GAZELLE_LATENCY_WRITE_INTO_RING].latency_stat_result);
    printf("range: t1--->t2\n%s", res[GAZELLE_LATENCY_WRITE_LWIP].latency_stat_result);
    printf("range: t2--->t3\n%s", res[GAZELLE_LATENCY_WRITE_LSTACK].latency_stat_result);
    printf("range: t0--->t3\n%s", res[GAZELLE_LATENCY_WRITE_MAX].latency_stat_result);
    printf("t0: app send  t1: into send ring  t2: out of send ring  t3: send to nic\n");

    printf("Others:\n");
    printf("rpc_call_send\n%s", res[GAZELLE_LATENCY_WRITE_RPC_MSG].latency_stat_result);
    printf("ready to read from recvmbox\n%s", res[GAZELLE_LATENCY_RECVMBOX_READY].latency_stat_result);

    free(res);
}

static void gazelle_print_lstack_stat_lpm(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    struct gazelle_stack_dfx_data *dfx_data = (struct gazelle_stack_dfx_data *)buf;
    printf("Lstack low power mode: %s\n", (dfx_data->low_power_info.low_power_mod) ? "ON" : "OFF");

    if (dfx_data->low_power_info.low_power_mod == 0) {
        return;
    }

    printf("Low power param: rx_pkts:%u, detect_ms:%ums, pkts_in_detect:%u\n",
        (uint32_t)dfx_data->low_power_info.lpm_rx_pkts,
        dfx_data->low_power_info.lpm_detect_ms,
        dfx_data->low_power_info.lpm_pkts_in_detect);
}

static void gazelle_print_lstack_stat_rate(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    int32_t ret;
    double rate;
    uint32_t index;
    char *rate_type = NULL;
    uint32_t total_wait_time = g_wait_reply + CMD_WAIT_TIME;   /* STOP_LATENCY would sleep */
    struct gazelle_stack_dfx_data *stats = (struct gazelle_stack_dfx_data *)buf;
    /* not show when first get total statistics */
    static int32_t g_lstack_rate_show_flag[GAZELLE_MAX_STACK_ARRAY_SIZE] = {0};

    do {
        index = stats->stack_id;
        if (index >= GAZELLE_MAX_STACK_ARRAY_SIZE) {
            break;
        }

        if (g_lstack_rate_show_flag[index] == GAZELLE_ON) {
            printf("------ Statistics of lstack rate   stack tid: %6u ------\n", stats->tid);
            printf("rx_pkts: %-15"PRIu64" ", (stats->data.pkts.stack_stat.rx -
					      g_last_lstack_data[index].data.pkts.stack_stat.rx) / total_wait_time);
            rate = rate_convert_type((stats->data.pkts.aggregate_stats.rx_bytes / g_wait_reply), &rate_type);
            printf("rx_bytes: %7.2lf%s  ", rate, rate_type);
            printf("rx_drop: %-15"PRIu64"\n", (stats->data.pkts.stack_stat.rx_drop -
					       g_last_lstack_data[index].data.pkts.stack_stat.rx_drop) /total_wait_time);
            printf("tx_pkts: %-15"PRIu64" ", (stats->data.pkts.stack_stat.tx -
					      g_last_lstack_data[index].data.pkts.stack_stat.tx) / total_wait_time);
            rate = rate_convert_type((stats->data.pkts.aggregate_stats.tx_bytes / g_wait_reply), &rate_type);
            printf("tx_bytes: %7.2lf%s  ", rate, rate_type);
            printf("tx_drop: %-15"PRIu64"\n\n", (stats->data.pkts.stack_stat.tx_drop -
						 g_last_lstack_data[index].data.pkts.stack_stat.tx_drop) / total_wait_time);
        } else {
            g_lstack_rate_show_flag[index] = GAZELLE_ON;
        }

        ret = memcpy_s(&g_last_lstack_data[index], sizeof(*stats), stats,
            sizeof(struct gazelle_stack_dfx_data));
        if (ret != EOK) {
            printf("%s:%d memcpy_s fail ret=%d\n", __FUNCTION__, __LINE__, ret);
        }

        if (stats->eof != 0) {
            break;
        }

        ret = dfx_stat_read_from_ltran(buf, sizeof(struct gazelle_stack_dfx_data), req_msg->stat_mode);
        if (ret != GAZELLE_OK) {
            return;
        }
    } while (true);
}

static void gazelle_print_lstack_tcp_stat(const struct gazelle_stat_lstack_snmp *snmp)
{
    printf("tcp_act_open: %u\n",         snmp->tcp_act_open);
    printf("tcp_passive_open: %u\n",     snmp->tcp_passive_open);
    printf("tcp_attempt_fail: %u\n",     snmp->tcp_attempt_fail);
    printf("tcp_estab_rst: %u\n",        snmp->tcp_estab_rst);
    printf("tcp_out_seg: %u\n",          snmp->tcp_out_seg);
    printf("tcp_retran_seg: %u\n",       snmp->tcp_retran_seg);
    printf("tcp_in_seg: %u\n",           snmp->tcp_in_seg);
    printf("tcp_in_err: %u\n",           snmp->tcp_in_err);
    printf("tcp_out_rst: %u\n",          snmp->tcp_out_rst);
    printf("tcp_fin_ack_cnt: %u\n",      snmp->tcp_fin_ack_cnt);
    printf("tcp_delay_ack_cnt: %u\n",    snmp->tcp_delay_ack_cnt);
    printf("tcp_refused_cnt: %u\n",      snmp->tcp_refused_cnt);
    printf("tcp_out_of_seq: %u\n",       snmp->tcp_out_of_seq);
    printf("tcp_acceptmbox_full: %u\n",  snmp->tcp_acceptmbox_full);
    printf("tcp_listen_drops: %u\n",     snmp->tcp_listen_drops);
    printf("tcp_in_empty_acks: %u\n",    snmp->tcp_in_empty_acks);
}

static void gazelle_print_ltran_stat_lb_rate(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    int32_t ret;
     double rate;
     uint32_t stack_index;
     char *rate_type = NULL;
     struct gazelle_stat_lstack_total *stats = (struct gazelle_stat_lstack_total *)buf;
     /* not show when first get total statistics */
     static int32_t g_ltran_lb_rate_show_flag[GAZELLE_MAX_STACK_ARRAY_SIZE] = {0};

     do {
         stack_index = stats->index;
         if (stack_index >= GAZELLE_MAX_STACK_ARRAY_SIZE) {
	     break;
         }
         
         if (g_ltran_lb_rate_show_flag[stack_index] == GAZELLE_ON) {
       	     printf("------ Statistics of lstack rate   stack tid: %6u ------\n", stats->tid);
       	     printf("rx_pkts: %-15"PRIu64" ", (stats->rx - g_last_lstack_total[stack_index].rx) /
		    GAZELLE_DFX_REQ_INTERVAL_S);
       	     rate = rate_convert_type((stats->rx_bytes - g_last_lstack_total[stack_index].rx_bytes) /
				      GAZELLE_DFX_REQ_INTERVAL_S, &rate_type);
       	     printf("rx_bytes: %7.2lf%s  ", rate, rate_type);
       	     printf("rx_err: %-15"PRIu64" ", (stats->rx_err - g_last_lstack_total[stack_index].rx_err) /
		    GAZELLE_DFX_REQ_INTERVAL_S);
       	     printf("rx_drop: %-15"PRIu64"\n", (stats->rx_drop - g_last_lstack_total[stack_index].rx_drop) /
		    GAZELLE_DFX_REQ_INTERVAL_S);
       	     printf("tx_pkts: %-15"PRIu64" ", (stats->tx - g_last_lstack_total[stack_index].tx) /
		    GAZELLE_DFX_REQ_INTERVAL_S);
       	     rate = rate_convert_type((stats->tx_bytes - g_last_lstack_total[stack_index].tx_bytes) /
				      GAZELLE_DFX_REQ_INTERVAL_S, &rate_type);
       	     printf("tx_bytes: %7.2lf%s  ", rate, rate_type);
       	     printf("tx_err: %-15"PRIu64" ", (stats->tx_err - g_last_lstack_total[stack_index].tx_err) /
		    GAZELLE_DFX_REQ_INTERVAL_S);
       	     printf("tx_drop: %-15"PRIu64"\n\n", (stats->tx_drop - g_last_lstack_total[stack_index].tx_drop) /
		    GAZELLE_DFX_REQ_INTERVAL_S);
         } else {
	     g_ltran_lb_rate_show_flag[stack_index] = GAZELLE_ON;
         }
         
         ret = memcpy_s(&g_last_lstack_total[stack_index], sizeof(*stats), stats,
			sizeof(struct gazelle_stat_lstack_total));
         if (ret != EOK) {
	     printf("%s:%d memcpy_s fail ret=%d\n", __FUNCTION__, __LINE__, ret);
         }
         
         if (stats->eof != 0) {
	     break;
         }
       
         ret = dfx_stat_read_from_ltran(buf, sizeof(struct gazelle_stat_lstack_total), req_msg->stat_mode);
         if (ret != GAZELLE_OK) {
	     return;
         }
     } while (true);
}

static void gazelle_print_lstack_stat_snmp_core(const struct gazelle_stack_dfx_data *stat,
                                                const struct gazelle_stat_lstack_snmp *snmp)
{
    printf("\n------ stack tid: %6u ------\n", stat->tid);
    printf("ip_inhdr_err: %u\n",     snmp->ip_inhdr_err);
    printf("ip_inaddr_err: %u\n",    snmp->ip_inaddr_err);
    printf("ip_inunknownprot: %u\n", snmp->ip_inunknownprot);
    printf("ip_in_discard: %u\n",    snmp->ip_in_discard);
    printf("ip_in_deliver: %u\n",    snmp->ip_in_deliver);
    printf("ip_out_req: %u\n",       snmp->ip_out_req);
    printf("ip_out_discard: %u\n",   snmp->ip_out_discard);
    printf("ip_outnort: %u\n",       snmp->ip_outnort);
    printf("ip_reasm_ok: %u\n",      snmp->ip_reasm_ok);
    printf("ip_reasm_fail: %u\n",    snmp->ip_reasm_fail);
    printf("ip_frag_ok: %u\n",       snmp->ip_frag_ok);
    printf("ip_frag_fail: %u\n",     snmp->ip_frag_fail);
    printf("ip_frag_create: %u\n",   snmp->ip_frag_create);
    printf("ip_reasm_reqd: %u\n",    snmp->ip_reasm_reqd);
    printf("ip_fw_dgm: %u\n",        snmp->ip_fw_dgm);
    printf("ip_in_recv: %u\n",       snmp->ip_in_recv);

    printf("udp_in_datagrams: %u\n", snmp->udp_in_datagrams);
    printf("udp_no_ports: %u\n",     snmp->udp_no_ports);
    printf("udp_in_errors: %u\n",    snmp->udp_in_errors);
    printf("udp_out_datagrams: %u\n", snmp->udp_out_datagrams);

    gazelle_print_lstack_tcp_stat(snmp);

    printf("icmp_in_msgs: %u\n", snmp->icmp_in_msgs);
    printf("icmp_in_errors: %u\n", snmp->icmp_in_errors);
    printf("icmp_in_dest_unreachs: %u\n", snmp->icmp_in_dest_unreachs);
    printf("icmp_in_time_excds: %u\n", snmp->icmp_in_time_excds);
    printf("icmp_in_parm_probs: %u\n", snmp->icmp_in_parm_probs);
    printf("icmp_in_src_quenchs: %u\n", snmp->icmp_in_src_quenchs);
    printf("icmp_in_redirects: %u\n", snmp->icmp_in_redirects);
    printf("icmp_in_echos: %u\n", snmp->icmp_in_echos);
    printf("icmp_in_echo_reps: %u\n", snmp->icmp_in_echo_reps);
    printf("icmp_in_time_stamps: %u\n", snmp->icmp_in_time_stamps);
    printf("icmp_in_time_stampreps: %u\n", snmp->icmp_in_time_stamp_reps);
    printf("icmp_in_addr_masks: %u\n", snmp->icmp_in_addr_masks);
    printf("icmp_in_addr_maskreps: %u\n", snmp->icmp_in_addr_mask_reps);
    printf("icmp_out_msgs: %u\n", snmp->icmp_out_msgs);
    printf("icmp_out_errors: %u\n", snmp->icmp_out_errors);
    printf("icmp_out_dest_unreachs: %u\n", snmp->icmp_out_dest_unreachs);
    printf("icmp_out_time_excds: %u\n", snmp->icmp_out_time_excds);
    printf("icmp_out_echos: %u\n", snmp->icmp_out_echos); /* can be incremented by user application ('ping') */
    printf("icmp_out_echo_reps: %u\n", snmp->icmp_out_echo_reps);
}

static void gazelle_print_lstack_stats_proto(const struct gazelle_stack_dfx_data *stat,
                                             const struct gazelle_stats_proto *proto)
{
    printf("\n------ stack tid: %6u ------\n", stat->tid);
    printf("tx_in: %lu\n",     proto->tx_in);
    printf("tx_out: %lu\n",    proto->tx_out);
    printf("rx_in: %lu\n",     proto->rx_in);
    printf("rx_out: %lu\n",    proto->rx_out);
    printf("fw: %lu\n", proto->fw);
    printf("drop: %lu\n",    proto->drop);
    printf("chkerr: %lu\n",    proto->chkerr);
    printf("lenerr: %lu\n",       proto->lenerr);
    printf("memerr: %lu\n",   proto->memerr);
    printf("rterr: %lu\n",       proto->rterr);
}

static void gazelle_print_lstack_stats_igmp(const struct gazelle_stack_dfx_data *stat,
                                            const struct gazelle_stats_igmp *proto)
{
    printf("\n------ IGMP Statistics , stack tid: %6u ------\n", stat->tid);
    printf("xmit: %lu\n", proto->xmit);
    printf("recv: %lu\n", proto->recv);
    printf("drop: %lu\n", proto->drop);
    printf("chkerr: %lu\n", proto->chkerr);
    printf("lenerr: %lu\n", proto->lenerr);
    printf("memerr: %lu\n", proto->memerr);
    printf("proterr: %lu\n", proto->proterr);
    printf("rx_v1: %lu\n", proto->rx_v1);
    printf("rx_group: %lu\n", proto->rx_group);
    printf("rx_general: %lu\n", proto->rx_general);
    printf("rx_report: %lu\n", proto->rx_report);
    printf("tx_join: %lu\n", proto->tx_join);
    printf("tx_leave: %lu\n", proto->tx_leave);
    printf("tx_report: %lu\n", proto->tx_report);
}

static void gazelle_print_lstack_stat_snmp(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    int32_t ret;
    struct gazelle_stack_dfx_data *stat = (struct gazelle_stack_dfx_data *)buf;
    struct gazelle_stat_lstack_snmp *snmp = &stat->data.snmp;

    printf("Statistics of lstack snmp:\n");
    do {
        gazelle_print_lstack_stat_snmp_core(stat, snmp);
        if (stat->eof != 0) {
            break;
        }
        ret = dfx_stat_read_from_ltran(buf, sizeof(struct gazelle_stack_dfx_data), req_msg->stat_mode);
        if (ret != GAZELLE_OK) {
            return;
        }
    } while (true);
}

static void gazelle_print_lstack_stat_proto(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    int32_t ret;
    struct gazelle_stack_dfx_data *stat = (struct gazelle_stack_dfx_data *)buf;
    struct gazelle_stats_proto *proto = NULL;
    struct gazelle_stats_igmp *igmp_proto = NULL;
    
    if (strcmp(req_msg->data.protocol, "IGMP")  == 0) {
        igmp_proto = &stat->data.igmp_data;
    } else {
        proto = &stat->data.proto_data;
    }
    printf("Statistics of lstack proto:\n");
    do {
        if (strcmp(req_msg->data.protocol, "IGMP") == 0) {
            gazelle_print_lstack_stats_igmp(stat, igmp_proto);
        } else {
            gazelle_print_lstack_stats_proto(stat, proto);
        }
        if (stat->eof != 0) {
            break;
        }
        ret = dfx_stat_read_from_ltran(buf, sizeof(struct gazelle_stack_dfx_data), req_msg->stat_mode);
        if (ret != GAZELLE_OK) {
            return;
        }
    } while (true);
}

static void  gazelle_print_socket_stat_memory(uint32_t idx, struct gazelle_socket_mem_info *socket_info)
{
    struct gazelle_socket_mem_info *si = socket_info;
    /* "No.","fd","info","rpc_mempool","send_ring","recv_ring","recvmbox","acceptmbox" */
    printf("%-8d%-6d%-15s%-12.6lf%-12.6lf%-12.6lf%-12.6lf\n", idx, si->fd, "total_mem(M)",
        si->send_ring_info.total_mem, si->recv_ring_info.total_mem,
        si->recvmbox_info.total_mem, si->acceptmbox_info.total_mem);
    printf("%14s%-15s%-12.6lf%-12.6lf%-12.6lf%-12.6lf\n", "", "avail_mem(M)",
        si->send_ring_info.avail_mem, si->recv_ring_info.avail_mem,
        si->recvmbox_info.avail_mem, si->acceptmbox_info.avail_mem);
    printf("%14s%-15s%-12d%-12d%-12d%-12d\n", "", "total_size",
        si->send_ring_info.total_size, si->recv_ring_info.total_size,
        si->recvmbox_info.total_size, si->acceptmbox_info.total_size);
    printf("%14s%-15s%-12d%-12d%-12d%-12d\n", "", "avail_size",
        si->send_ring_info.avail_size, si->recv_ring_info.avail_size,
        si->recvmbox_info.avail_size, si->acceptmbox_info.avail_size);
}

static void gazelle_print_lstack_stat_memory(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    struct gazelle_stack_dfx_data *stat = (struct gazelle_stack_dfx_data *)buf;
    struct gazelle_stat_lstack_memory* mem_usage = NULL;
    double rxtxpool_percent = 0;
    double rpcpool_percent = 0;
    double sndring_total = 0;
    time_t rawtime;
    struct tm *timeinfo;
    char timestamp[80];
    struct gazelle_socket_mem_info *socket;

    mem_usage = &stat->data.mem_usage;
    if (mem_usage->rxtx_mempool.total_mem != 0) {
        rxtxpool_percent = PERCENTAGE(mem_usage->rxtx_mempool.avail_mem / mem_usage->rxtx_mempool.total_mem);
    }
    if (mem_usage->rpc_mempool.total_mem != 0) {
        rpcpool_percent = PERCENTAGE(mem_usage->rpc_mempool.avail_mem / mem_usage->rpc_mempool.total_mem);
    }
    if (time(&rawtime)) {
        timeinfo = localtime(&rawtime);
        if (strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo) <= 0) {
            strcpy(timestamp, "strftime error");
        }
    } else {
        strcpy(timestamp, "time error");
    }
    printf("------ stack tid: %6u ------ time = %s\n", stat->tid, timestamp);
    printf("rxtx_mempool(M): %.6lf\n", mem_usage->rxtx_mempool.total_mem);
    printf("avail mem: %.6lf(%.3lf%%)\n", mem_usage->rxtx_mempool.avail_mem, rxtxpool_percent);
    printf("\nrpc_mempool(M): %.6lf\n", mem_usage->rpc_mempool.total_mem);
    printf("avail mem: %.6lf(%.3lf%%)\n", mem_usage->rpc_mempool.avail_mem, rpcpool_percent);
    printf("\nnic rx_queue(M): %.6lf\n", mem_usage->rx_queue_mem);
    printf("nic tx_queue(M): %.6lf\n\n", mem_usage->tx_queue_mem);

    printf("%-8s%-6s%-15s%-12s%-12s%-12s%-12s\n",
        "No.", "fd", "info", "send_ring", "recv_ring", "recvmbox", "acceptmbox");
    for (int i = 0; i < mem_usage->sock_num; i++) {
        socket = &mem_usage->sockets[i];
        gazelle_print_socket_stat_memory(i, socket);
        sndring_total += socket->send_ring_info.total_mem;
    }
    printf("\ntotal send ring mem(M): %.6lf\n", sndring_total);
    printf("\n");
}

static void gazelle_print_lstack_mem_general(
    struct gazelle_stack_dfx_data *buf,
    const struct gazelle_stat_msg_request *req_msg
)
{
    struct gazelle_general_lstack_memory general_mem_info = buf->general_mem_info;
    printf("size(M) total: %.6lf\n", general_mem_info.total_mem);
    printf("alloc: %.6lf(%.3lf%%)\n", general_mem_info.alloc_mem,
        PERCENTAGE(general_mem_info.alloc_mem / general_mem_info.total_mem));
    printf("free: %.6lf\n", general_mem_info.free_mem);
    printf("\n");

    printf("fixed alloc mem(M): %.6lf\n", general_mem_info.fixed_mem);
    printf("\n");
}

static void gazelle_print_total_stat_memory(void *buf,  const struct gazelle_stat_msg_request *req_msg)
{
    int32_t general_mem_info_show = 1;
    (void)req_msg;
    do {
        if (general_mem_info_show == 0) {
            int32_t ret = read_specied_len(g_unix_fd, (char *)buf, sizeof(struct gazelle_stack_dfx_data));
            if (ret != GAZELLE_OK) {
                break;
            }
        }
        if (general_mem_info_show != 0) {
            gazelle_print_lstack_mem_general((struct gazelle_stack_dfx_data *)buf, req_msg);
            general_mem_info_show = 0;
        }
        gazelle_print_lstack_stat_memory(buf, req_msg);
        if (((struct gazelle_stat_lstack_total *)buf)->eof) {
            break;
        }
    } while (true);
}

static void gazelle_print_lstack_stat_virtio(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    struct gazelle_stack_dfx_data *stat = (struct gazelle_stack_dfx_data *)buf;
    struct gazelle_stat_lstack_virtio *virtio = &stat->data.virtio;
    printf("\nStatistics of lstack virtio:\n");

    printf("\nlstack_port_id: %u virtio_port_id: %u rx_queue_num: %u tx_queue_num: %u \n",
           virtio->lstack_port_id, virtio->virtio_port_id, virtio->rx_queue_num,
           virtio->tx_queue_num);

    printf("\n%-8s  %-8s  %-8s  %-8s  %-8s\n", "queue_id", "rx_pkg", "rx_drop", "tx_pkg", "tx_drop");
    for (int i = 0; i < virtio->rx_queue_num; i++) {
        printf("%-8d  %-8lu  %-8lu  %-8lu  %-8lu\n", i,
               virtio->rx_pkg[i], virtio->rx_drop[i], virtio->tx_pkg[i], virtio->tx_drop[i]);
    }
    printf("\n");
}

static void gazelle_keepalive_string(char* str, int buff_len, struct gazelle_stat_lstack_conn_info *conn_info)
{
    if (conn_info->keepalive == 0) {
        return;
    }
    int ret = sprintf_s(str, buff_len, "(%u,%u,%u)", (conn_info->keep_idle) / 1000,
        (conn_info->keep_intvl) / 1000, conn_info->keep_cnt);
    if (ret < 0) {
        printf("gazelle_keepalive_string sprintf_s fail ret=%d\n", ret);
        return;
    }
}

static void gazelle_localtime_string(char* str, int buff_len)
{
    struct timeval  time = {0};
    gettimeofday(&time, NULL);
    struct tm* tm;
    time_t t = time.tv_sec;
    tm = localtime(&t);
    int ret = sprintf_s(str, buff_len, "%d-%d-%d %d:%d:%d",
        tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    if (ret < 0) {
        printf("gazelle_localtime_string sprintf_s fail ret=%d\n", ret);
        return;
    }
}

static void gazelle_print_lstack_stat_conn(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    uint32_t i;
    char str_ip[INET6_ADDRSTRLEN] = {0};
    char str_rip[INET6_ADDRSTRLEN] = {0};
    /* ip:port, 6 is the length reserved for port */
    char str_laddr[INET6_ADDRSTRLEN + 6] = {0};
    char str_raddr[INET6_ADDRSTRLEN + 6] = {0};
    struct gazelle_stack_dfx_data *stat = (struct gazelle_stack_dfx_data *)buf;
    struct gazelle_stat_lstack_conn *conn = &stat->data.conn;

    char keepalive_info_str[GAZELLE_KEEPALIVE_STR_LEN] = {0};
    char sys_local_time_str[GAZELLE_TIME_STR_LEN] = {0};
    gazelle_localtime_string(sys_local_time_str, GAZELLE_TIME_STR_LEN);

    printf("Active Internet connections (servers and established)\n");
    do {
        printf("\n------ stack tid: %6u ------time=%s\n", stat->tid, sys_local_time_str);
        printf("No.   Proto lwip_recv recv_ring in_send send_ring cwn      rcv_wnd  snd_wnd   snd_buf   snd_nxt"
            "        lastack        rcv_nxt        events    epoll_ev  evlist fd     Local Address"
            "                                        Foreign Address                                      State"
            "     keep-alive keep-alive(idle,intvl,cnt)\n");
        uint32_t unread_pkts = 0;
        uint32_t unsend_pkts = 0;
        for (i = 0; i < conn->conn_num && i < GAZELLE_LSTACK_MAX_CONN; i++) {
            struct gazelle_stat_lstack_conn_info *conn_info = &conn->conn_list[i];

            uint32_t domain = conn_info->lip.type == GZ_ADDR_TYPE_V4 ? AF_INET : AF_INET6;
            void *lip = (void *)&conn_info->lip;
            void *rip = (void *)&conn_info->rip;

            if ((conn_info->state == GAZELLE_ACTIVE_LIST) || (conn_info->state == GAZELLE_TIME_WAIT_LIST)) {
                inet_ntop(domain, lip, str_ip, sizeof(str_ip));
                inet_ntop(domain, rip, str_rip, sizeof(str_rip));
                
                gazelle_keepalive_string(keepalive_info_str, sizeof(keepalive_info_str)/sizeof(char), conn_info);
                
                sprintf_s(str_laddr, sizeof(str_laddr), "%s:%hu", str_ip, conn_info->l_port);
                sprintf_s(str_raddr, sizeof(str_raddr), "%s:%hu", str_rip, conn_info->r_port);
                printf("%-6utcp   %-10u%-10u%-8u%-10u%-9d%-9d%-10d%-10d%-15u%-15u%-15u%-10x%-10x%-7d%-7d"
                    "%-52s %-52s %s  %-5d %s\n", i, conn_info->recv_cnt, conn_info->recv_ring_cnt, conn_info->in_send,
                    conn_info->send_ring_cnt, conn_info->cwn, conn_info->rcv_wnd, conn_info->snd_wnd,
                    conn_info->snd_buf, conn_info->snd_nxt, conn_info->lastack, conn_info->rcv_nxt, conn_info->events,
                    conn_info->epoll_events, conn_info->eventlist, conn_info->fd,
                    str_laddr, str_raddr, tcp_state_to_str(conn_info->tcp_sub_state),
                    conn_info->keepalive, keepalive_info_str);
            } else if (conn_info->state == GAZELLE_LISTEN_LIST) {
                inet_ntop(domain, lip, str_ip, sizeof(str_ip));
                sprintf_s(str_laddr, sizeof(str_laddr), "%s:%hu", str_ip, conn_info->l_port);
                sprintf_s(str_raddr, sizeof(str_raddr), "%s:*", domain == AF_INET ? "0.0.0.0" : "::0");
                printf("%-6utcp    %-147u%-7d%-52s %-52s LISTEN\n", i, conn_info->recv_cnt,
                    conn_info->fd, str_laddr, str_raddr);
            } else {
                printf("Got unknow tcp conn::%s:%5hu, state:%u\n",
                    inet_ntop(domain, lip, str_ip, sizeof(str_ip)), conn_info->l_port, conn_info->state);
            }
            unread_pkts += conn_info->recv_ring_cnt + conn_info->recv_cnt;
            unsend_pkts += conn_info->send_ring_cnt + conn_info->in_send;
        }
        if (conn->conn_num > 0) {
            printf("Total unread pkts:%u  unsend pkts:%u\n", unread_pkts, unsend_pkts);
        }

        if (i < conn->total_conn_num) {
            printf("...\nTotal connections: %u, display connections: %u\n", conn->total_conn_num, i);
        }

        if (stat->eof != 0) {
            break;
        }
        int32_t ret = dfx_stat_read_from_ltran(buf, sizeof(struct gazelle_stack_dfx_data), req_msg->stat_mode);
        if (ret != GAZELLE_OK) {
            return;
        }
    } while (true);
}

static void show_usage(void)
{
    printf("Usage: gazellectl [-h | help] \n"
           "  or:  gazellectl ltran  {quit | show | set} [LTRAN_OPTIONS] [-u UNIX_PREFIX]\n"
           "  or:  gazellectl lstack {show | set} ip [LSTACK_OPTIONS] [-u UNIX_PREFIX]\n\n"
#ifdef GAZELLE_FAULT_INJECT_ENABLE
           "  or:  gazellectl inject [inject_type] [digit_param_1] [digit_param_2] [inject_rule]\n\n"
#endif /* GAZELLE_FAULT_INJECT_ENABLE */
           "  quit            ltran process exit \n \n"
           "  where  LTRAN_OPTIONS := \n"
           "  show: \n"
           "                  show ltran all statistics \n"
           "  -r, rate        show ltran statistics per second \n"
           "  -i, instance    show ltran instance register info \n"
           "  -b, burst       show ltran NIC packet len per second \n"
           "  -t, table       {socktable | conntable}  show ltran sock or conn table \n"
           "  -l, latency     [time]  show ltran latency \n"
           "  set: \n"
           "  loglevel        {error | info | debug}  set ltran loglevel \n \n"
           "  where  LSTACK_OPTIONS := \n"
           "  show: \n"
           "                  show lstack all statistics \n"
           "  -r, rate        show lstack statistics per second \n"
           "  -s, snmp        show lstack snmp \n"
           "  -v, virtio      show rx_pkg/rx_drop/tx_pkg/tx_drop num of virtio \n"
           "  -c, connect     show lstack connect \n"
           "  -l, latency     [time]   show lstack latency \n"
           "  -x, xstats      show lstack xstats \n"
           "  -k, nic-features     show state of protocol offload and other features \n"
           "  -a, aggregatin  [time]   show lstack send/recv aggregation \n"
           "  -p, protocol    {UDP | TCP | IP | ETHARP | ICMP | IGMP} show lstack protocol statistics \n"
           "  -m, memory      [time] [interval]  show lstack memory usage \n"
           "  set: \n"
           "  loglevel        {error | info | debug}  set lstack loglevel \n"
           "  lowpower        {0 | 1}  set lowpower enable \n"
           "  [time]          measure latency time default 1S, maximum 30mins \n\n"
#ifdef GAZELLE_FAULT_INJECT_ENABLE
           "                                     *inject params*\n"
           " |inject_type    |     digit_param_1      |      digit_param_2     |     inject_rule   |\n"
           " |  delay        |   delay_time(unit: ms) |  delay_range(unit: ms) |       random      |\n"
#endif /* GAZELLE_FAULT_INJECT_ENABLE */
           );
}

static int32_t parse_dfx_ltran_set_args(int32_t argc, char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int32_t cmd_index = 0;
    int32_t ret;

    if (argc < GAZELLE_LTRAN_SET_MINNUM) {
        return cmd_index;
    }

    char *param = argv[GAZELLE_OPTIONS_ARG_IDX];
    if (strcmp(param, "loglevel") == 0) {
        param = argv[GAZELLE_OPTIONS1_ARG_IDX];
        if (strcmp(param, "error") != 0 && strcmp(param, "info") != 0 && strcmp(param, "debug") != 0) {
            return cmd_index;
        }

        ret = strncpy_s(req_msg[cmd_index].data.log_level, GAZELLE_LOG_LEVEL_MAX, argv[GAZELLE_OPTIONS1_ARG_IDX],
            GAZELLE_LOG_LEVEL_MAX - 1);
        if (ret != EOK) {
            return -1;
        }
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_LOG_LEVEL_SET;
    }

    return cmd_index;
}

static int32_t parse_dfx_ltran_show_args(int32_t argc, char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int32_t cmd_index = 0;
    long int delay = 1;

    if (argc == GAZELLE_LTRAN_PARAM_NUM) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_SHOW;
        return cmd_index;
    }

    char *param = argv[GAZELLE_OPTIONS_ARG_IDX];
    if (strcmp(param, "rate") == 0 || strcmp(param, "-r") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_SHOW_RATE;
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_MODE_MAX;
    } else if (strcmp(param, "instance") == 0 || strcmp(param, "-i") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_SHOW_INSTANCE;
    } else if (strcmp(param, "burst") == 0 || strcmp(param, "-b") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_SHOW_BURST;
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_MODE_MAX;
    } else if (strcmp(param, "table") == 0 || strcmp(param, "-t") == 0) {
        if (argc < GAZELLE_OPT_LPM_ARG_IDX1) {
            return cmd_index;
        }
        param = argv[GAZELLE_OPTIONS1_ARG_IDX];
        if (strcmp(param, "socktable") == 0) {
            req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_SHOW_SOCKTABLE;
        }
        if (strcmp(param, "conntable") == 0) {
            req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_SHOW_CONNTABLE;
        }
    } else if (strcmp(param, "latency") == 0 || strcmp(param, "-l") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_START_LATENCY;
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_STOP_LATENCY;
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_SHOW_LATENCY;
        if (argc > GAZELLE_LSTACK_PARAM_NUM) {
            char *end = NULL;
            delay = strtol(argv[GAZELLE_OPTIONS1_ARG_IDX], &end, GAZELLE_DECIMAL);
            if (delay <= 0 || (end == NULL) || (*end != '\0')) {
                return -1;
            }
            if (delay > GAZELLE_MAX_LATENCY_TIME) {
                printf("Exceeds the maximum(30mins) latency time, will be set to maximum(30mins)\n");
                delay = GAZELLE_MAX_LATENCY_TIME;
            }
        }
        g_wait_reply = delay;
    }

    return cmd_index;
}

static void gazelle_print_lstack_aggregate(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    struct gazelle_stack_dfx_data *dfx = (struct gazelle_stack_dfx_data *)buf;
    struct gazelle_stack_aggregate_stats *stats = &dfx->data.pkts.aggregate_stats;
    char *rate_type = NULL;
    double rate;
    int32_t ret = 0;

    do {
        printf("\n================Stack(%d) Aggregate===============\n", dfx->tid);
        rate = rate_convert_type(stats->rx_bytes / g_wait_reply, &rate_type);
        printf("rx throught: %f%s\n", rate, rate_type);
        rate = rate_convert_type(stats->tx_bytes / g_wait_reply, &rate_type);
        printf("tx throught: %f%s\n", rate, rate_type);

        printf("rx_szie_1_64: %u\n", stats->size_1_64[0]);
        printf("rx_size_65_512: %u\n", stats->size_65_512[0]);
        printf("rx_size_513_1460 byte: %u\n", stats->size_513_1460[0]);
        printf("rx_size_1461_8192 byte: %u\n", stats->size_1461_8192[0]);
        printf("rx_size_8193_max byte: %u\n", stats->size_8193_max[0]);

        printf("tx_szie_1_64: %u\n", stats->size_1_64[1]);
        printf("tx_size_65_512: %u\n", stats->size_65_512[1]);
        printf("tx_size_513_1460 byte: %u\n", stats->size_513_1460[1]);
        printf("tx_size_1461_8192 byte: %u\n", stats->size_1461_8192[1]);
        printf("tx_size_8193_max byte: %u\n", stats->size_8193_max[1]);

        printf("app_tx_szie_1_64: %u\n", stats->size_1_64[2]);
        printf("app_tx_size_65_512: %u\n", stats->size_65_512[2]);
        printf("app_tx_size_513_1460 byte: %u\n", stats->size_513_1460[2]);
        printf("app_tx_size_1461_8192 byte: %u\n", stats->size_1461_8192[2]);
        printf("app_tx_size_8193_max byte: %u\n", stats->size_8193_max[2]);

        if ((dfx->eof != 0) || (ret != GAZELLE_OK)) {
            break;
        }
        ret = dfx_stat_read_from_ltran(buf, sizeof(struct gazelle_stack_dfx_data), req_msg->stat_mode);
    } while (true);
}

static int32_t parse_dfx_ltran_args(int32_t argc, char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int32_t num_cmd = 0;

    if (argc < GAZELLE_LTRAN_PARAM_NUM) {
        return num_cmd;
    }

    char *param = argv[GAZELLE_COMMAND_ARG_IDX];
    if (strcmp(param, "quit") == 0) {
        req_msg[num_cmd++].stat_mode = GAZELLE_STAT_LTRAN_QUIT;
    }

    if (strcmp(param, "set") == 0) {
        num_cmd = parse_dfx_ltran_set_args(argc, argv, req_msg);
    }

    if (strcmp(param, "show") == 0) {
        num_cmd = parse_dfx_ltran_show_args(argc, argv, req_msg);
    }

    return num_cmd;
}

static int32_t parse_dfx_lstack_set_args(int32_t argc, char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int32_t cmd_index = 0;
    int32_t ret;

    if (argc < GAZELLE_LSTACK_SET_MINNUM) {
        return cmd_index;
    }

    char *param = argv[GAZELLE_OPTIONS1_ARG_IDX];
    if (strcmp(param, "loglevel") == 0) {
        param = argv[GAZELLE_OPTIONS2_ARG_IDX];
        if (strcmp(param, "error") != 0 && strcmp(param, "info") != 0 && strcmp(param, "debug") != 0) {
            return cmd_index;
        }
        ret = strncpy_s(req_msg[cmd_index].data.log_level, GAZELLE_LOG_LEVEL_MAX, argv[GAZELLE_OPTIONS2_ARG_IDX],
            GAZELLE_LOG_LEVEL_MAX - 1);
        if (ret != EOK) {
            return ret;
        }
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_LOG_LEVEL_SET;
    }

    if (strcmp(param, "lowpower") == 0) {
        char *end = NULL;
        req_msg[cmd_index].data.low_power_mod =
            (uint16_t)strtol(argv[GAZELLE_OPT_LPM_ARG_IDX1], &end, GAZELLE_DECIMAL);
        if (req_msg[cmd_index].data.low_power_mod > 1 || (end == NULL) || (*end != '\0')) {
            printf("low_power_mod input invaild\n");
            return cmd_index;
        }
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_LOW_POWER_MDF;
    }

    return cmd_index;
}

static int parse_delay_arg(int32_t argc, char *argv[], long int delay)
{
    if (argc > GAZELLE_OPTIONS2_ARG_IDX) {
        char *end = NULL;
        delay = strtol(argv[GAZELLE_OPTIONS2_ARG_IDX], &end, GAZELLE_DECIMAL);
        if (delay <= 0 || (end == NULL) || (*end != '\0')) {
            return -1;
        }
        if (delay > GAZELLE_MAX_LATENCY_TIME) {
            printf("Exceeds the maximum(30mins) latency time, will be set to maximum(30mins)\n");
            delay = GAZELLE_MAX_LATENCY_TIME;
        }
    }
    g_wait_reply = delay;
    return 0;
}

static int parse_repeat_arg(int32_t argc, char *argv[])
{
    int32_t time = 0;
    int32_t interval = 1;
    char *end = NULL;
    
    if (argc > GAZELLE_OPTIONS3_ARG_IDX) {
        time = strtol(argv[GAZELLE_OPTIONS2_ARG_IDX], NULL, GAZELLE_DECIMAL);
        if (time > GAZELLE_MAX_LATENCY_TIME) {
            printf("Exceeds the maximum(30mins) repeat time, will be set to maximum(30mins)\n");
            time = GAZELLE_MAX_LATENCY_TIME;
        }
        interval = strtol(argv[GAZELLE_OPTIONS3_ARG_IDX], &end, GAZELLE_DECIMAL);
        if (interval <= 0 || (end == NULL) || (*end != '\0')) {
            return -1;
        }
    }
    g_repeat_time = time;
    g_repeat_interval = interval;
    return 0;
}


static int32_t parse_dfx_lstack_show_proto_args(int32_t argc, char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int32_t cmd_index = 0;
    int32_t ret;

    char *param = argv[GAZELLE_OPTIONS2_ARG_IDX];
    if ((param == NULL) || (strcmp(param, "UDP") != 0 && strcmp(param, "TCP") != 0 && strcmp(param, "IP") &&
        strcmp(param, "ICMP") && strcmp(param, "ETHARP") != 0 && strcmp(param, "IGMP")) != 0) {
        return cmd_index;
    }
    ret = strncpy_s(req_msg[cmd_index].data.protocol, MAX_PROTOCOL_LENGTH, argv[GAZELLE_OPTIONS2_ARG_IDX],
        MAX_PROTOCOL_LENGTH - 1);
    if (ret != EOK) {
        return -1;
    }
    req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_PROTOCOL;
    return cmd_index;
}

static int32_t parse_dfx_lstack_show_args(int32_t argc, char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int32_t cmd_index = 0;
    long int delay = 1;

    if (argc == GAZELLE_LSTACK_PARAM_NUM) {
        req_msg[cmd_index++].stat_mode = g_use_ltran ? GAZELLE_STAT_LTRAN_SHOW_LSTACK : GAZELLE_STAT_LSTACK_SHOW;
        return cmd_index;
    }

    char *param = argv[GAZELLE_OPTIONS1_ARG_IDX];
    if (strcmp(param, "rate") == 0 || strcmp(param, "-r") == 0) {
        if (g_use_ltran) {
            req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_SHOW_LB_RATE;
        } else {
            req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_START_LATENCY;
            req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_STOP_LATENCY;
            req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_RATE;
        }
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_MODE_MAX;
    } else if (strcmp(param, "snmp") == 0 || strcmp(param, "-s") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_SNMP;
    } else if (strcmp(param, "virtio") == 0 || strcmp(param, "-v") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_VIRTIO;
    } else if (strcmp(param, "connect") == 0 || strcmp(param, "-c") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_CONN;
    } else if (strcmp(param, "xstats") == 0 || strcmp(param, "-x") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_XSTATS;
    } else if (strcmp(param, "latency") == 0 || strcmp(param, "-l") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_START_LATENCY;
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_STOP_LATENCY;
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_LATENCY;
        if (g_use_ltran) {
            req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_SHOW_LATENCY;
        }

        if (parse_delay_arg(argc, argv, delay) != 0) {
            return 0;
        }
    } else if (strcmp(param, "aggragate") == 0 || strcmp(param, "-a") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_START_LATENCY;
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_STOP_LATENCY;
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_AGGREGATE;
        if (parse_delay_arg(argc, argv, delay) != 0) {
            return 0;
        }
    } else if (strcmp(param, "-k") == 0 || strcmp(param, "nic-features") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_NIC_FEATURES;
    } else if (strcmp(param, "protocol") == 0 || strcmp(param, "-p") == 0) {
	    cmd_index = parse_dfx_lstack_show_proto_args(argc, argv, req_msg);
    } else if (strcmp(param, "-m") == 0 || strcmp(param, "memory")) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_MEMORY_USAGE;
        if (parse_repeat_arg(argc, argv) != 0) {
            return 0;
        }
    }
    return cmd_index;
}

static int32_t parse_dfx_lstack_args(int32_t argc, char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int32_t num_cmd = 0;
    struct in_addr ip;
    uint32_t pid = 0;

    if (argc < GAZELLE_LSTACK_PARAM_NUM) {
        return num_cmd;
    }

    /* args3 have ',' is ip or is pid */
    char *param = argv[GAZELLE_OPTIONS_ARG_IDX];
    if (strstr(param, ".")) {
        if (inet_aton(param, &ip) == 0) {
            return num_cmd;
        }
    } else {
        char *end = NULL;
        pid = (uint32_t)strtoul(param, &end, 0);
        if (end == NULL || *end != '\0') {
            return num_cmd;
        }
    }

    param = argv[GAZELLE_COMMAND_ARG_IDX];
    if (strcmp(param, "set") == 0) {
        num_cmd = parse_dfx_lstack_set_args(argc, argv, req_msg);
    }

    if (strcmp(param, "show") == 0) {
        num_cmd = parse_dfx_lstack_show_args(argc, argv, req_msg);
    }

    for (int32_t i = 0; i < num_cmd; i++) {
        req_msg[i].ip.s_addr = ip.s_addr;
        req_msg[i].pid = pid;
    }
    return num_cmd;
}

#ifdef GAZELLE_FAULT_INJECT_ENABLE

#define GAZELLE_SET_FAULT_INJECT_PARAM_COUNT    6
#define GAZELLE_UNSET_FAULT_INJECT_PARAM_COUNT  4
#define INJECT_TYPE_INDEX                       2
#define INJECT_DIGITAL_FIRST_INDEX              3
#define INJECT_DIGITAL_SECOND_INDEX             4
#define INJECT_RULE_INDEX                       5
#define INJECT_UNSET_TYPE_INDEX                 3


static void gazelle_print_fault_inject_type_info(struct gazelle_fault_inject_data *inject)
{
    if (!inject->fault_inject_on) {
        return;
    }
    
    if (inject->inject_type == GAZELLE_FAULT_INJECT_PACKET_DELAY) {
        printf("\t| inject_type: delay     | delay_time: %-7d   | delay_range: %-3d             | "
               "inject_rule: random |\n", inject->inject_data.delay.delay_time,
               inject->inject_data.delay.delay_range);
    }
    
#define INJECT_PERCENT                          100
    
    if (inject->inject_type == GAZELLE_FAULT_INJECT_PACKET_LOSS) {
        printf("\t| inject_type: loss      | loss_rate: %-4.1f%%      | loss_single_count: %-3d       | "
               "inject_rule: random |\n", inject->inject_data.loss.loss_rate * INJECT_PERCENT,
               inject->inject_data.loss.loss_sigle_count);
    }
    
    if (inject->inject_type == GAZELLE_FAULT_INJECT_PACKAET_DUPLICATE) {
        printf("\t| inject_type: duplicate | duplicate_rate: %-4.1f%% | duplicate_single_count: %-3d  | "
               "inject_rule: random |\n", inject->inject_data.duplicate.duplicate_rate * INJECT_PERCENT,
               inject->inject_data.duplicate.duplicate_sigle_count);
    }

    if (inject->inject_type == GAZELLE_FAULT_INJECT_PACKET_REORDER) {
        printf("\t| inject_type: reorder   | reorder_rate: %-4.1f%%   | reorder_sigle_count: %-3d     | "
               "inject_rule: random |\n", inject->inject_data.reorder.reorder_rate * INJECT_PERCENT,
               inject->inject_data.reorder.reorder_sigle_count);
    }
    printf("\n");
}

static void gazelle_print_fault_inject_set_status(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    int32_t ret;
    struct gazelle_stack_dfx_data *stat = (struct gazelle_stack_dfx_data *)buf;
    struct gazelle_fault_inject_data *inject = &stat->data.inject;

    printf("\n\n\t\t\t\t\t **** FAULT INJECT INFO **** \n\n");
    do {
        gazelle_print_fault_inject_type_info(inject);
        if (stat->eof != 0) {
            break;
        }
        ret = dfx_stat_read_from_ltran(buf, sizeof(struct gazelle_stack_dfx_data), req_msg->stat_mode);
        if (ret != GAZELLE_OK) {
            return;
        }
    } while (true);
}

static void gazelle_print_fault_inject_unset_status(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    int32_t ret;
    static int32_t inject_enable[GAZELLE_FAULT_INJECT_TYPE_MAX];
    struct gazelle_stack_dfx_data *stat = (struct gazelle_stack_dfx_data *)buf;
    struct gazelle_fault_inject_data *inject = &stat->data.inject;

        printf("\n\t\t\t\t\t **** INJECT ENABLE ITEM **** \n\n");
    do {
        inject_enable[inject->inject_type] = inject->fault_inject_on;
        gazelle_print_fault_inject_type_info(inject);
        if (stat->eof != 0) {
            break;
        }
        ret = dfx_stat_read_from_ltran(buf, sizeof(struct gazelle_stack_dfx_data), req_msg->stat_mode);
        if (ret != GAZELLE_OK) {
            return;
        }
    } while (true);

    printf("\n\n\t\t\t\t\t **** INJECT DISABLE ITEM **** \n\n");
    printf("\tThe currently closed inject types are: ");
    for (int32_t i = 1; i < GAZELLE_FAULT_INJECT_TYPE_MAX; ++i) {
        if (!inject_enable[i]) {
            /* i - 1 means fault inject type mapping inject_type_item name */
            printf("\"%s\" ", inject_type_list[i - 1].inject_type_item);
        }
    }
    printf("\n");
    return;
}

static int32_t parse_inject_packet_delay_digit(char* time, char* range, struct gazelle_stat_msg_request *req_msg)
{
    int32_t parse_success = 0;
    int32_t delay_time = atoi(time);
    if (delay_time <= 0) {
        printf("FAULT INJECT error: delay time error -- %d, need positive integer.\n", delay_time);
        return parse_success;
    }
    req_msg->data.inject.inject_data.delay.delay_time = (uint32_t) delay_time;

    int32_t delay_range = atoi(range);
    if (delay_range < 0) {
        printf("FAULT INJECT error: delay range error -- %d, need positive integer.\n", delay_range);
        return parse_success;
    }
    if (delay_time - delay_range <= 0) {
        printf("FAULT INJECT error: delay range should lower than delay time.\n");
        return parse_success;
    }
    req_msg->data.inject.inject_data.delay.delay_range = delay_range;

    return ++parse_success;
}

#define INJECT_RATE_LOWER                    0.001

static int32_t parse_inject_packet_loss_digit(char *rate, char *count, struct gazelle_stat_msg_request *req_msg)
{
    int32_t parse_success = 0;
    double loss_rate = atof(rate);
    if (loss_rate < INJECT_RATE_LOWER || loss_rate >= 1) {
        printf("FAULT INJECT error: loss rate error, range in [0.001, 1), now is %f\n", loss_rate);
        return parse_success;
    }
    req_msg->data.inject.inject_data.loss.loss_rate = loss_rate;

    int32_t loss_counts = atoi(count);
    if (loss_counts <= 0) {
        printf("FAULT INJECT error: single loss counts wrong --%d, need positive integer.", loss_counts);
        return parse_success;
    }
    req_msg->data.inject.inject_data.loss.loss_sigle_count = loss_counts;

    return ++parse_success;
}

static int32_t parse_inject_packet_duplicate_digit(char *rate, char *count, struct gazelle_stat_msg_request *req_msg)
{
    int32_t parse_success = 0;
    double duplicate_rate = atof(rate);
    if (duplicate_rate < INJECT_RATE_LOWER || duplicate_rate >= 1) {
        printf("FAULT INJECT error: duplicate rate error, range in [0.001, 1), now is %f\n", duplicate_rate);
        return parse_success;
    }
    req_msg->data.inject.inject_data.duplicate.duplicate_rate = duplicate_rate;

    int32_t duplicate_counts = atoi(count);
    if (duplicate_counts <= 0) {
        printf("FAULT INJECT error: single duplicate counts wrong --%d, need positive integer.", duplicate_counts);
        return parse_success;
    }
    req_msg->data.inject.inject_data.duplicate.duplicate_sigle_count = duplicate_counts;

    return ++parse_success;
}

static int32_t parse_inject_packet_reorder_digit(char *rate, char *count, struct gazelle_stat_msg_request *req_msg)
{
    int32_t parse_success = 0;
    double reorder_rate = atof(rate);
    if (reorder_rate < INJECT_RATE_LOWER || reorder_rate >= 1) {
        printf("FAULT INJECT error: reorder rate error, range in [0.001, 1), now is %f\n", reorder_rate);
        return parse_success;
    }
    req_msg->data.inject.inject_data.reorder.reorder_rate = reorder_rate;

    int32_t reorder_counts = atoi(count);
    if (reorder_counts <= 0) {
        printf("FAULT INJECT error: single duplicate counts wrong --%d, need positive integer.", reorder_counts);
        return parse_success;
    }
    req_msg->data.inject.inject_data.reorder.reorder_sigle_count = reorder_counts;

    return ++parse_success;
}

static int32_t parse_fault_inject_digital_data(char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int32_t parse_success = 0;
    int32_t func_count = sizeof(inject_type_list) / sizeof(inject_type_list[0]);
    for (int32_t i = 0; i < func_count; ++i) {
        if (inject_type_list[i].inject_type_parsed == req_msg->data.inject.inject_type) {
            parse_success = inject_type_list[i].parse_digit_func(argv[INJECT_DIGITAL_FIRST_INDEX],
                                                                 argv[INJECT_DIGITAL_SECOND_INDEX], req_msg);
            break;
        }
    }

    return parse_success;
}

static int32_t parse_fault_inject_unset_type(char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int32_t num_cmd = 0;
    
    if (strcmp(argv[INJECT_TYPE_INDEX], "unset") != 0) {
        printf("FAULT_INJECT error: unrecognized input -- %s, should be \"unset\"\n", argv[INJECT_TYPE_INDEX]);
        return num_cmd;
    }
    
    req_msg->data.inject.fault_inject_on = 0; /* unset fault inject */
    req_msg->stat_mode = GAZELLE_STAT_FAULT_INJECT_UNSET;
    
    if (strcmp(argv[INJECT_UNSET_TYPE_INDEX], "all") == 0) {
        req_msg->data.inject.inject_type = GAZELLE_FAULT_INJECT_TYPE_MAX;
        return ++num_cmd;
    }

    int32_t inject_type_count = sizeof(inject_type_list) / sizeof(inject_type_list[0]);
    for (int32_t i = 0; i < inject_type_count; ++i) {
        if (strcmp(inject_type_list[i].inject_type_item, argv[INJECT_UNSET_TYPE_INDEX]) == 0) {
            req_msg->data.inject.inject_type = inject_type_list[i].inject_type_parsed;
            break;
        }
    }
    if (req_msg->data.inject.inject_type == GAZELLE_FAULT_INJECT_TYPE_ERR) {
        printf("FAULT_INJECT error: input inject type is wrong -- %s\n", argv[INJECT_TYPE_INDEX]);
        return num_cmd;
    }

    return ++num_cmd;
}

static int32_t parse_fault_inject_set_type(char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int32_t num_cmd = 0;
    
    req_msg->data.inject.fault_inject_on = 1; /* set fault inject on */
    req_msg->stat_mode = GAZELLE_STAT_FAULT_INJECT_SET;
    
    int32_t inject_type_count = sizeof(inject_type_list) / sizeof(inject_type_list[0]);
    for (int32_t i = 0; i < inject_type_count; ++i) {
        if (strcmp(inject_type_list[i].inject_type_item, argv[INJECT_TYPE_INDEX]) == 0) {
            req_msg->data.inject.inject_type = inject_type_list[i].inject_type_parsed;
            break;
        }
    }
    if (req_msg->data.inject.inject_type == GAZELLE_FAULT_INJECT_TYPE_ERR) {
        printf("FAULT_INJECT error: input inject type is wrong -- %s\n", argv[INJECT_TYPE_INDEX]);
        return num_cmd;
    }

    int32_t inject_rule_count = sizeof(g_gazelle_fault_inject_rule_list) / sizeof(g_gazelle_fault_inject_rule_list[0]);
    for (int32_t i = 0; i < inject_rule_count; ++i) {
        if (strcmp(g_gazelle_fault_inject_rule_list[i].inject_rule_item, argv[INJECT_RULE_INDEX]) == 0 &&
            g_gazelle_fault_inject_rule_list[i].rule_parse_assit == req_msg->data.inject.inject_type) {
            req_msg->data.inject.inject_rule = g_gazelle_fault_inject_rule_list[i].inject_rule_parsed;
            break;
        }
    }
    if (req_msg->data.inject.inject_rule == INJECT_RULE_ERR) {
        printf("FAULT_INJECT error: input inject rule is wrong -- %s\n", argv[INJECT_RULE_INDEX]);
        return num_cmd;
    }

    num_cmd = parse_fault_inject_digital_data(argv, req_msg);
    
    return num_cmd;
}

static int32_t parse_dfx_fault_inject_args(int32_t argc, char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int32_t num_cmd = 0; /* while parse error, num_cmd will return as 0, or num_cmd should be returned as 1. */

    if (argc == GAZELLE_UNSET_FAULT_INJECT_PARAM_COUNT) {
        num_cmd = parse_fault_inject_unset_type(argv, req_msg);
        return num_cmd;
    }
    
    if (argc == GAZELLE_SET_FAULT_INJECT_PARAM_COUNT) {
        num_cmd = parse_fault_inject_set_type(argv, req_msg);
        return num_cmd;
    }
    
    printf("FAULT_INJECT error: Count of params wrong , correct count is 6 or 4, now is %d\n", argc);
    return num_cmd;
}

#endif /* GAZELLE_FAULT_INJECT_ENABLE */

static void parse_unix_arg(int32_t *argc, char *argv[])
{
    int unix_arg = 0;
       for (int i = 1; i < *argc; i++) {
               if (unix_arg == 0) {
                       if (!strcmp(argv[i], "-u")) {
                               unix_arg++;
                       }
               } else if (unix_arg == 1) {
                       g_unix_prefix = argv[i];
                       unix_arg++;
               } else {
                       argv[i - unix_arg] = argv[i];
               }
       }

    argv[*argc - unix_arg] = argv[*argc];
    *argc -= unix_arg;
}

static int32_t parse_dfx_cmd_args(int32_t argc, char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int num_cmd = 0;
    int ret;

    if (argc < GAZELLE_PARAM_MINNUM) {
        return num_cmd;
    }

    parse_unix_arg(&argc, argv);

    char *param = argv[GAZELLE_TARGET_ARG_IDX];
    if (strcmp(param, "ltran") == 0) {
        g_use_ltran = true;
        num_cmd = parse_dfx_ltran_args(argc, argv, req_msg);
    }
    if (strcmp(param, "lstack") == 0) {
        ret = dfx_connect_probe();
        if (ret < 0) {
            exit(-1);
        }
        g_use_ltran = ret;
        num_cmd = parse_dfx_lstack_args(argc, argv, req_msg);
    }
#ifdef GAZELLE_FAULT_INJECT_ENABLE
    if (strcmp(param, "inject") == 0) {
        num_cmd = parse_dfx_fault_inject_args(argc, argv, req_msg);
    }
#endif /* GAZELLE_FAULT_INJECT_ENABLE */
    return num_cmd;
}

int32_t dfx_loop(struct gazelle_stat_msg_request *req_msg, int32_t req_msg_num)
{
    int32_t ret;
    int32_t msg_index = 0;
    int32_t interval = 0;
    struct gazelle_dfx_list *dfx = NULL;
    char recv_buf[GAZELLE_CMD_RESP_BUFFER_SIZE + 1] = {0};

    for (;;) {
        dfx = find_dfx_node(req_msg[msg_index].stat_mode);
        if (dfx == NULL) {
            break;
        }

        if (dfx_stat_conn_to_ltran(&req_msg[msg_index]) != GAZELLE_OK) {
            return -1;
        }

        ret = dfx_stat_read_from_ltran(recv_buf, GAZELLE_CMD_RESP_BUFFER_SIZE + 1, req_msg[msg_index].stat_mode);
        if (ret != GAZELLE_OK) {
            return -1;
        }

        if (dfx->print_func != NULL) {
            dfx->print_func(recv_buf, &req_msg[msg_index]);
        }

        if (g_unix_fd >= 0) {
            close(g_unix_fd);
            g_unix_fd = -1;
        }

        interval++;
        if (interval < g_repeat_interval && g_repeat_time != 0) {
            sleep(g_repeat_time);
            continue;
        }
        msg_index++;
        interval = 0;
        if (msg_index >= req_msg_num) {
            break;
        }

        // stat_mode = GAZELLE_STAT_MODE_MAX need repeat command
        if (req_msg[msg_index].stat_mode == GAZELLE_STAT_MODE_MAX) {
	    if (req_msg[msg_index - 1].stat_mode != GAZELLE_STAT_LSTACK_SHOW_RATE) {
	        sleep(GAZELLE_DFX_REQ_INTERVAL_S);
	    }
	    msg_index = 0;
        }
    }

    return 0;
}

int32_t main(int32_t argc, char *argv[])
{
    struct gazelle_stat_msg_request req_msg[GAZELLE_CMD_MAX] = {0};
    int32_t req_msg_num;

    req_msg_num = parse_dfx_cmd_args(argc, argv, req_msg);
    if (req_msg_num <= 0 || req_msg_num > GAZELLE_CMD_MAX) {
        show_usage();
        return 0;
    }

    return dfx_loop(req_msg, req_msg_num);
}
