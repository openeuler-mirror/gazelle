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
#include <stdint.h>

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

#include "ltran_stat.h"
#include "ltran_base.h"
#include "gazelle_dfx_msg.h"

/* seeing show_usage() */
#define GAZELLE_TARGET_ARG_IDX   1
#define GAZELLE_COMMAND_ARG_IDX  2
#define GAZELLE_OPTIONS_ARG_IDX  3
#define GAZELLE_OPTIONS1_ARG_IDX 4
#define GAZELLE_OPTIONS2_ARG_IDX 5
#define GAZELLE_OPT_LPM_ARG_IDX1 5

#define GAZELLE_PARAM_MINNUM     2
#define GAZELLE_LTRAN_PARAM_NUM  3
#define GAZELLE_LSTACK_PARAM_NUM 4

#define GAZELLE_LTRAN_SET_MINNUM 5
#define GAZELLE_LSTACK_SET_MINNUM 6

#define GAZELLE_CMD_MAX          5

#define GAZELLE_RESULT_LEN       8291
#define GAZELLE_MAX_LATENCY_TIME 1800    // max latency time 30mins

#define GAZELLE_DECIMAL          10

static int32_t g_unix_fd = -1;
static int32_t g_ltran_rate_show_flag = GAZELLE_OFF;    // not show when first get total statistics
static struct gazelle_stat_ltran_total g_last_ltran_total;
static struct gazelle_stat_lstack_total g_last_lstack_total[GAZELLE_MAX_STACK_ARRAY_SIZE];

static bool g_use_ltran = false;

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
static void gazelle_print_ltran_stat_client(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_stat_burst(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_stat_latency(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_wait(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_start_latency(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_total(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_rate(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_snmp(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_conn(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_latency(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_lstack_stat_lpm(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_sock(void *buf, const struct gazelle_stat_msg_request *req_msg);
static void gazelle_print_ltran_conn(void *buf, const struct gazelle_stat_msg_request *req_msg);

static struct gazelle_dfx_list g_gazelle_dfx_tbl[] = {
    {GAZELLE_STAT_LTRAN_SHOW,          sizeof(struct gazelle_stat_ltran_total),  gazelle_print_ltran_stat_total},
    {GAZELLE_STAT_LTRAN_SHOW_RATE,     sizeof(struct gazelle_stat_ltran_total),  gazelle_print_ltran_stat_rate},
    {GAZELLE_STAT_LTRAN_SHOW_INSTANCE, sizeof(struct gazelle_stat_ltran_client), gazelle_print_ltran_stat_client},
    {GAZELLE_STAT_LTRAN_SHOW_BURST,    sizeof(struct gazelle_stat_ltran_total),  gazelle_print_ltran_stat_burst},
    {GAZELLE_STAT_LTRAN_SHOW_LATENCY,  sizeof(struct in_addr),                  gazelle_print_ltran_stat_latency},
    {GAZELLE_STAT_LTRAN_QUIT,          0,                                       gazelle_print_ltran_wait},
    {GAZELLE_STAT_LTRAN_START_LATENCY, 0,                                       gazelle_print_ltran_start_latency},
    {GAZELLE_STAT_LTRAN_STOP_LATENCY,  0,                                       gazelle_print_ltran_wait},
    {GAZELLE_STAT_LTRAN_LOG_LEVEL_SET, 0,                                       gazelle_print_ltran_wait},
    {GAZELLE_STAT_LTRAN_SHOW_SOCKTABLE, sizeof(struct gazelle_stat_forward_table), gazelle_print_ltran_sock},
    {GAZELLE_STAT_LTRAN_SHOW_CONNTABLE, sizeof(struct gazelle_stat_forward_table), gazelle_print_ltran_conn},
    {GAZELLE_STAT_LSTACK_LOG_LEVEL_SET, 0,                                      gazelle_print_ltran_wait},
    {GAZELLE_STAT_LSTACK_SHOW,         sizeof(struct gazelle_stat_lstack_total), gazelle_print_lstack_stat_total},
    {GAZELLE_STAT_LSTACK_SHOW_RATE,    sizeof(struct gazelle_stat_lstack_total), gazelle_print_lstack_stat_rate},
    {GAZELLE_STAT_LSTACK_SHOW_SNMP,    sizeof(struct gazelle_stack_dfx_data),  gazelle_print_lstack_stat_snmp},
    {GAZELLE_STAT_LSTACK_SHOW_CONN,    sizeof(struct gazelle_stack_dfx_data),  gazelle_print_lstack_stat_conn},
    {GAZELLE_STAT_LSTACK_SHOW_LATENCY, sizeof(struct gazelle_stack_dfx_data),  gazelle_print_lstack_stat_latency},
    {GAZELLE_STAT_LSTACK_LOW_POWER_MDF, sizeof(struct gazelle_stack_dfx_data),  gazelle_print_lstack_stat_lpm},
};

static int32_t g_wait_reply = 1;

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

static int32_t dfx_connect_ltran(bool use_ltran, bool probe)
{
    int32_t ret, fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        printf("create socket failed. errno: %d\n", errno);
        return GAZELLE_ERR;
    }

    ret = memset_s(&addr, sizeof(addr), 0, sizeof(struct sockaddr_un));
    if (ret != EOK) {
        printf("%s:%d memset_s fail ret=%d\n", __FUNCTION__, __LINE__, ret);
    }

    addr.sun_family = AF_UNIX;
    if (use_ltran) {
        ret = strncpy_s(addr.sun_path, sizeof(addr.sun_path), GAZELLE_DFX_SOCK_PATHNAME,
            strlen(GAZELLE_DFX_SOCK_PATHNAME) + 1);
        if (ret != EOK) {
            printf("%s:%d strncpy_s fail ret=%d\n", __FUNCTION__, __LINE__, ret);
        }
    } else {
        ret = strncpy_s(addr.sun_path, sizeof(addr.sun_path), GAZELLE_REG_SOCK_PATHNAME,
            strlen(GAZELLE_REG_SOCK_PATHNAME) + 1);
        if (ret != EOK) {
            printf("%s:%d strncpy_s fail ret=%d\n", __FUNCTION__, __LINE__, ret);
        }
    }

    ret = connect(fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    if (ret == -1) {
        if (!probe) {
            printf("connect ltran failed. errno: %d ret=%d\n", errno, ret);
        }
        close(fd);
        return GAZELLE_ERR;
    }

    return fd;
}

static int32_t dfx_stat_conn_to_ltran(struct gazelle_stat_msg_request *req_msg)
{
    int32_t fd = dfx_connect_ltran(g_use_ltran, false);
    if (fd < 0) {
        return fd;
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
        return GAZELLE_ERR;
    }

    if (dfx->recv_size != 0) {
        ret = read_specied_len(fd, tmp_pbuf, dfx->recv_size);
        if (ret == -1) {
            printf("read stat response msg failed ret=%d\n", ret);
            close(fd);
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

static double rate_convert_type(uint64_t bytes, char **type)
{
    static char *rate_type[] = {"B/s", "KB/s", "MB/s", "GB/s"};
    const uint32_t per_unit = 1024; // 1KB=1024B
    double now = bytes;
    uint32_t type_max = sizeof(rate_type) / sizeof(char *);
    uint32_t index = 0;

    while (now > per_unit && index < type_max - 1) {
        now /= per_unit;
        index++;
    }

    *type = rate_type[index];
    return now;
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
    sleep(1); // give ltran time to read cmd
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
    printf("app_get_idlefail: %-11"PRIu64" \n", lstack_stat->data.pkts.wakeup_stat.app_write_idlefail);
    printf("recv_list: %-18"PRIu64" ", lstack_stat->data.pkts.recv_list_cnt);
    printf("send_list: %-18"PRIu64" ", lstack_stat->data.pkts.send_list_cnt);
    printf("conn_num: %-19hu \n", lstack_stat->data.pkts.conn_num);
    printf("wakeup_events: %-14"PRIu64" ", lstack_stat->data.pkts.stack_stat.wakeup_events);
    printf("app_events: %-17"PRIu64" ", lstack_stat->data.pkts.wakeup_stat.app_events);
    printf("read_null: %-18"PRIu64" \n", lstack_stat->data.pkts.wakeup_stat.read_null);
    printf("call_msg: %-19"PRIu64" ", lstack_stat->data.pkts.call_msg_cnt);
    printf("call_alloc_fail: %-12"PRIu64" ", lstack_stat->data.pkts.call_alloc_fail);
    printf("call_null: %-18"PRIu64" \n", lstack_stat->data.pkts.stack_stat.call_null);
    printf("send_self_rpc: %-14"PRIu64" \n", lstack_stat->data.pkts.stack_stat.send_self_rpc);
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
        *pos += sprintf_s(result + *pos, max_len, "%-6"PRIu64"      ", latency->latency_min);
        *pos += sprintf_s(result + *pos, max_len, "%-6"PRIu64"      ", latency->latency_max);
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
    if (record->latency_pkts > 0) {
        *pos += sprintf_s(result + *pos, max_len, "                          total:      ");
        *pos += sprintf_s(result + *pos, max_len, "%-8"PRIu64"    ", record->latency_pkts);
        *pos += sprintf_s(result + *pos, max_len, "%-6"PRIu64"      ", record->latency_min);
        *pos += sprintf_s(result + *pos, max_len, "%-6"PRIu64"      ", record->latency_max);
        *pos += sprintf_s(result + *pos, max_len, "%-6.2f \n\n\n",
            (double)record->latency_total / record->latency_pkts);
    } else {
        *pos += sprintf_s(result + *pos, max_len, "                          total:      0\n\n\n");
    }
}

static void gazelle_print_lstack_stat_latency(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    struct gazelle_stack_dfx_data *stat = (struct gazelle_stack_dfx_data *)buf;
    struct gazelle_stack_latency *latency = &stat->data.latency;
    int32_t ret = GAZELLE_OK;
    int32_t lwip_index = 0;
    int32_t read_index = 0;
    struct stack_latency lwip_record = {0};
    struct stack_latency read_record = {0};
    char str_ip[GAZELLE_SUBNET_LENGTH_MAX] = {0};

    read_record.latency_min = ~((uint64_t)0);
    lwip_record.latency_min = ~((uint64_t)0);

    char *lwip_result = calloc(GAZELLE_RESULT_LEN, sizeof(char));
    if (lwip_result == NULL) {
        return;
    }
    char *read_result = calloc(GAZELLE_RESULT_LEN, sizeof(char));
    if (read_result == NULL) {
        free(lwip_result);
        return;
    }

    do {
        lwip_index += sprintf_s(lwip_result + lwip_index, (size_t)(GAZELLE_RESULT_LEN - lwip_index),
            "ip: %-15s  tid: %-8u    ", inet_ntop(AF_INET, &req_msg->ip, str_ip, sizeof(str_ip)), stat->tid);
        parse_thread_latency_result(&latency->lwip_latency, lwip_result, (size_t)(GAZELLE_RESULT_LEN - lwip_index),
            &lwip_index, &lwip_record);

        read_index += sprintf_s(read_result + read_index, (size_t)(GAZELLE_RESULT_LEN - read_index),
            "ip: %-15s  tid: %-8u    ", inet_ntop(AF_INET, &req_msg->ip, str_ip, sizeof(str_ip)), stat->tid);
        parse_thread_latency_result(&latency->read_latency, read_result, (size_t)(GAZELLE_RESULT_LEN - read_index),
            &read_index, &read_record);

        if ((stat->eof != 0) || (ret != GAZELLE_OK)) {
            break;
        }
        ret = dfx_stat_read_from_ltran(buf, sizeof(struct gazelle_stack_dfx_data), req_msg->stat_mode);
    } while (true);

    parse_latency_total_result(lwip_result, (size_t)(GAZELLE_RESULT_LEN - lwip_index), &lwip_index, &lwip_record);
    parse_latency_total_result(read_result, (size_t)(GAZELLE_RESULT_LEN - read_index), &read_index, &read_record);

    printf("Statistics of lstack latency: t0--->t3 \
        (t0:read form nic  t1:into lstask queue  t2:into app queue t3:app read)\n");
    printf("                                      pkts        min(us)     max(us)     average(us)\n%s",
        read_result);

    printf("Statistics of lstack latency: t0--->t2 \
        (t0:read form nic  t1:into lstask queue  t2:into app queue t3:app read)\n");
    printf("                                      pkts        min(us)     max(us)     average(us)\n%s",
        lwip_result);

    free(read_result);
    free(lwip_result);
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
    uint32_t stack_index;
    char *rate_type = NULL;
    struct gazelle_stat_lstack_total *stats = (struct gazelle_stat_lstack_total *)buf;
    /* not show when first get total statistics */
    static int32_t g_lstack_rate_show_flag[GAZELLE_MAX_STACK_ARRAY_SIZE] = {0};

    do {
        stack_index = stats->index;
        if (stack_index >= GAZELLE_MAX_STACK_ARRAY_SIZE) {
            break;
        }

        if (g_lstack_rate_show_flag[stack_index] == GAZELLE_ON) {
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
            g_lstack_rate_show_flag[stack_index] = GAZELLE_ON;
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
    printf("ip_outnort: %u\n",       snmp->ip_out_discard);
    printf("ip_reasm_ok: %u\n",      snmp->ip_reasm_ok);
    printf("ip_reasm_fail: %u\n",    snmp->ip_reasm_fail);
    printf("ip_frag_ok: %u\n",       snmp->ip_frag_ok);
    printf("ip_frag_fail: %u\n",     snmp->ip_frag_fail);
    printf("ip_frag_create: %u\n",   snmp->ip_frag_create);
    printf("ip_reasm_reqd: %u\n",    snmp->ip_reasm_reqd);
    printf("ip_fw_dgm: %u\n",        snmp->ip_fw_dgm);
    printf("ip_in_recv: %u\n",       snmp->ip_in_recv);

    printf("tcp_act_open: %u\n",     snmp->tcp_act_open);
    printf("tcp_passive_open: %u\n", snmp->tcp_passive_open);
    printf("tcp_attempt_fail: %u\n", snmp->tcp_attempt_fail);
    printf("tcp_estab_rst: %u\n",    snmp->tcp_estab_rst);
    printf("tcp_out_seg: %u\n",      snmp->tcp_out_seg);
    printf("tcp_retran_seg: %u\n",   snmp->tcp_retran_seg);
    printf("tcp_in_seg: %u\n",       snmp->tcp_in_seg);
    printf("tcp_in_err: %u\n",       snmp->tcp_in_err);
    printf("tcp_out_rst: %u\n",      snmp->tcp_out_rst);

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

static void gazelle_print_lstack_stat_conn(void *buf, const struct gazelle_stat_msg_request *req_msg)
{
    uint32_t i;
    struct in_addr rip;
    struct in_addr lip;
    char str_ip[GAZELLE_SUBNET_LENGTH_MAX] = {0};
    char str_rip[GAZELLE_SUBNET_LENGTH_MAX] = {0};
    struct gazelle_stack_dfx_data *stat = (struct gazelle_stack_dfx_data *)buf;
    struct gazelle_stat_lstack_conn *conn = &stat->data.conn;

    printf("Active Internet connections (servers and established)\n");
    do {
        printf("\n------ stack tid: %6u ------\n", stat->tid);
        printf("No.   Proto  recv_cnt  recv_ring  in_send  send_ring  sem_cnt  fd     Local Address  "
            "      Foreign Address    State\n");
        uint32_t unread_pkts = 0;
        uint32_t unsend_pkts = 0;
        for (i = 0; i < conn->conn_num && i < GAZELLE_LSTACK_MAX_CONN; i++) {
            struct gazelle_stat_lstack_conn_info *conn_info = &conn->conn_list[i];

            rip.s_addr = conn_info->rip;
            lip.s_addr = conn_info->lip;
            if ((conn_info->state == GAZELLE_ACTIVE_LIST) || (conn_info->state == GAZELLE_TIME_WAIT_LIST)) {
                printf("%-6utcp    %-10u%-11u%-9u%-11u%-9d%-7d%s:%hu   %s:%hu  %s\n", i, conn_info->recv_cnt,
                    conn_info->recv_ring_cnt, conn_info->in_send, conn_info->send_ring_cnt, conn_info->sem_cnt,
                    conn_info->fd, inet_ntop(AF_INET, &lip, str_ip, sizeof(str_ip)), conn_info->l_port,
                    inet_ntop(AF_INET, &rip, str_rip, sizeof(str_rip)), conn_info->r_port,
                    tcp_state_to_str(conn_info->tcp_sub_state));
            } else if (conn_info->state == GAZELLE_LISTEN_LIST) {
                printf("%-6utcp    %-50u%-7d%s:%hu   0.0.0.0:*          LISTEN\n", i, conn_info->recv_cnt,
                    conn_info->fd, inet_ntop(AF_INET, &lip, str_ip, sizeof(str_ip)), conn_info->l_port);
            } else {
                printf("Got unknow tcp conn::%s:%5hu, state:%u\n",
                    inet_ntop(AF_INET, &lip, str_ip, sizeof(str_ip)), conn_info->l_port, conn_info->state);
            }
            unread_pkts += conn_info->recv_ring_cnt;
            unsend_pkts += conn_info->send_ring_cnt;
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
           "  or:  gazellectl ltran  {quit | show | set} [LTRAN_OPTIONS] \n"
           "  or:  gazellectl lstack {show | set} ip [LSTACK_OPTIONS] \n \n"
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
           "  -c, connect     show lstack connect \n"
           "  -l, latency     [time]   show lstack latency \n"
           "  set: \n"
           "  loglevel        {error | info | debug}  set lstack loglevel \n"
           "  lowpower        {0 | 1}  set lowpower enable \n"
           "  [time]          measure latency time default 1S, maximum 30mins \n");
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
    }
    if (strcmp(param, "instance") == 0 || strcmp(param, "-i") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_SHOW_INSTANCE;
    }
    if (strcmp(param, "burst") == 0 || strcmp(param, "-b") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_SHOW_BURST;
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_MODE_MAX;
    }
    if (strcmp(param, "table") == 0 || strcmp(param, "-t") == 0) {
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
    }
    if (strcmp(param, "latency") == 0 || strcmp(param, "-l") == 0) {
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

static int32_t parse_dfx_lstack_show_args(int32_t argc, char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int32_t cmd_index = 0;
    long int delay = 1;

    if (argc == GAZELLE_LSTACK_PARAM_NUM) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW;
        return cmd_index;
    }

    char *param = argv[GAZELLE_OPTIONS1_ARG_IDX];
    if (strcmp(param, "rate") == 0 || strcmp(param, "-r") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_RATE;
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_MODE_MAX;
    }
    if (strcmp(param, "snmp") == 0 || strcmp(param, "-s") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_SNMP;
    }
    if (strcmp(param, "connect") == 0 || strcmp(param, "-c") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_CONN;
    }
    if (strcmp(param, "latency") == 0 || strcmp(param, "-l") == 0) {
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_START_LATENCY;
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_STOP_LATENCY;
        req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LSTACK_SHOW_LATENCY;
        if (g_use_ltran) {
            req_msg[cmd_index++].stat_mode = GAZELLE_STAT_LTRAN_SHOW_LATENCY;
        }

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

static int32_t parse_dfx_cmd_args(int32_t argc, char *argv[], struct gazelle_stat_msg_request *req_msg)
{
    int32_t num_cmd = 0;

    if (argc < GAZELLE_PARAM_MINNUM) {
        return num_cmd;
    }

    char *param = argv[GAZELLE_TARGET_ARG_IDX];
    if (strcmp(param, "ltran") == 0) {
        num_cmd = parse_dfx_ltran_args(argc, argv, req_msg);
    }
    if (strcmp(param, "lstack") == 0) {
        num_cmd = parse_dfx_lstack_args(argc, argv, req_msg);
    }

    return num_cmd;
}

static int32_t check_cmd_support(struct gazelle_stat_msg_request *req_msg, int32_t req_msg_num)
{
    switch (req_msg[0].stat_mode) {
        case GAZELLE_STAT_LSTACK_LOG_LEVEL_SET:
        case GAZELLE_STAT_LSTACK_SHOW:
        case GAZELLE_STAT_LSTACK_SHOW_SNMP:
        case GAZELLE_STAT_LSTACK_SHOW_CONN:
        case GAZELLE_STAT_LSTACK_SHOW_LATENCY:
        case GAZELLE_STAT_LSTACK_LOW_POWER_MDF:
            return 0;
        default:
            if (req_msg[0].stat_mode == GAZELLE_STAT_LTRAN_START_LATENCY &&
                req_msg[req_msg_num - 1].stat_mode == GAZELLE_STAT_LSTACK_SHOW_LATENCY) {
                return 0;
            }
            /* keep output consistency */
            printf("connect ltran failed. errno: 111 ret=-1\n");
            return -1;
    }
}

int32_t dfx_loop(struct gazelle_stat_msg_request *req_msg, int32_t req_msg_num)
{
    int32_t ret;
    int32_t msg_index = 0;
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

        msg_index++;
        if (msg_index >= req_msg_num) {
            break;
        }

        // stat_mode = GAZELLE_STAT_MODE_MAX need repeat command
        if (req_msg[msg_index].stat_mode == GAZELLE_STAT_MODE_MAX) {
            msg_index--;
            sleep(GAZELLE_DFX_REQ_INTERVAL_S);
        }
    }

    return 0;
}

int32_t main(int32_t argc, char *argv[])
{
    struct gazelle_stat_msg_request req_msg[GAZELLE_CMD_MAX] = {0};
    int32_t req_msg_num, ret;

    int32_t fd = dfx_connect_ltran(true, true);
    if (fd > 0) {
        g_use_ltran = true;
        close(fd);
    }
    req_msg_num = parse_dfx_cmd_args(argc, argv, req_msg);
    if (req_msg_num <= 0 || req_msg_num > GAZELLE_CMD_MAX) {
        show_usage();
        return 0;
    }

    if (!g_use_ltran) {
        g_gazelle_dfx_tbl[GAZELLE_STAT_LSTACK_SHOW].recv_size = sizeof(struct gazelle_stack_dfx_data);
        ret = check_cmd_support(req_msg, req_msg_num);
        if (ret < 0) {
            return -1;
        }
    }

    return dfx_loop(req_msg, req_msg_num);
}
