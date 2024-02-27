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
#include <sys/socket.h>
#include <sys/un.h>
#include <securec.h>

#include <rte_mbuf.h>
#include <rte_flow.h>
#include <rte_jhash.h>
#include <uthash.h>

#include <lwip/posix_api.h>
#include <lwip/tcp.h>
#include <lwip/prot/tcp.h>

#include "dpdk_common.h"
#include "lstack_log.h"
#include "lstack_dpdk.h"
#include "lstack_cfg.h"
#include "lstack_protocol_stack.h"
#include "lstack_flow.h"

#define MAX_PATTERN_NUM                         4
#define MAX_ACTION_NUM                          2
#define FULL_MASK                               0xffffffff /* full mask */
#define EMPTY_MASK                              0x0 /* empty mask */
#define LSTACK_MBUF_LEN                         64
#define TRANSFER_TCP_MUBF_LEN                   (LSTACK_MBUF_LEN + 3)
#define DELETE_FLOWS_PARAMS_NUM                 3
#define DELETE_FLOWS_PARAMS_LENGTH              30
#define CREATE_FLOWS_PARAMS_NUM                 6
#define CREATE_FLOWS_PARAMS_LENGTH              60
#define ADD_OR_DELETE_LISTEN_PORT_PARAMS_LENGTH 25
#define ADD_OR_DELETE_LISTEN_PORT_PARAMS_NUM    3
#define REPLY_LEN                               10
#define SUCCESS_REPLY                           "success"
#define ERROR_REPLY                             "error"

#define GET_LSTACK_NUM                          14
#define GET_LSTACK_NUM_STRING                   "get_lstack_num"

#define SERVER_PATH                             "/var/run/gazelle/server.socket"
#define SPLIT_DELIM                             ","

#define UNIX_TCP_PORT_MAX                       65535

#define INVAILD_PROCESS_IDX 255

#define IPV4_VERSION_OFFSET                     4
#define IPV4_VERSION                            4

static uint8_t g_user_ports[UNIX_TCP_PORT_MAX] = {INVAILD_PROCESS_IDX, };
static uint8_t g_listen_ports[UNIX_TCP_PORT_MAX] = {INVAILD_PROCESS_IDX, };

/* flow rule map */
#define RULE_KEY_LEN  23
struct flow_rule {
    char rule_key[RULE_KEY_LEN];
    struct rte_flow *flow;
    UT_hash_handle hh;
};

static uint16_t g_flow_num = 0;
static struct flow_rule *g_flow_rules = NULL;
static struct flow_rule *find_rule(char *rule_key)
{
    struct flow_rule *fl;
    HASH_FIND_STR(g_flow_rules, rule_key, fl);
    return fl;
}

static void add_rule(char* rule_key, struct rte_flow *flow)
{
    struct flow_rule *rule;
    HASH_FIND_STR(g_flow_rules, rule_key, rule);
    if (rule == NULL) {
        rule = (struct flow_rule*)malloc(sizeof(struct flow_rule));
        strcpy_s(rule->rule_key, RULE_KEY_LEN, rule_key);
        HASH_ADD_STR(g_flow_rules, rule_key, rule);
    }
    rule->flow = flow;
}

static void delete_rule(char* rule_key)
{
    struct flow_rule *rule = NULL;
    HASH_FIND_STR(g_flow_rules, rule_key, rule);
    if (rule != NULL) {
        HASH_DEL(g_flow_rules, rule);
        free(rule);
    }
}

static void init_listen_and_user_ports(void)
{
    memset_s(g_user_ports, sizeof(g_user_ports), INVAILD_PROCESS_IDX, sizeof(g_user_ports));
    memset_s(g_listen_ports, sizeof(g_listen_ports), INVAILD_PROCESS_IDX, sizeof(g_listen_ports));
}

static int transfer_pkt_to_other_process(char *buf, int process_index, int write_len, bool need_reply)
{
    /* other process queue_id */
    struct sockaddr_un serun;
    int sockfd;
    int ret = 0;

    sockfd = posix_api->socket_fn(AF_UNIX, SOCK_STREAM, 0);
    memset_s(&serun, sizeof(serun), 0, sizeof(serun));
    serun.sun_family = AF_UNIX;
    sprintf_s(serun.sun_path, PATH_MAX, "%s%d", SERVER_PATH, process_index);
    int32_t len = offsetof(struct sockaddr_un, sun_path) + strlen(serun.sun_path);
    if (posix_api->connect_fn(sockfd, (struct sockaddr *)&serun, len) < 0) {
        return CONNECT_ERROR;
    }
    posix_api->write_fn(sockfd, buf, write_len);
    if (need_reply) {
        char reply_message[REPLY_LEN];
        int32_t read_result = posix_api->read_fn(sockfd, reply_message, REPLY_LEN);
        if (read_result > 0) {
            if (strcmp(reply_message, SUCCESS_REPLY) == 0) {
                ret = TRANSFER_SUCESS;
            } else if (strcmp(reply_message, ERROR_REPLY) == 0) {
                ret = REPLY_ERROR;
            } else {
                ret = atoi(reply_message);
            }
        } else {
            ret = REPLY_ERROR;
        }
    }
    posix_api->close_fn(sockfd);

    return ret;
}

int32_t check_params_from_primary(void)
{
    struct cfg_params *cfg = get_global_cfg_params();
    if (cfg->is_primary) {
        return 0;
    }
    // check lstack num
    char get_lstack_num[GET_LSTACK_NUM];
    sprintf_s(get_lstack_num, GET_LSTACK_NUM, "%s", GET_LSTACK_NUM_STRING);
    int32_t ret = transfer_pkt_to_other_process(get_lstack_num, 0, GET_LSTACK_NUM, true);
    if (ret != cfg->num_cpu) {
        return -1;
    }
    return 0;
}

static struct rte_flow *create_flow_director(uint16_t port_id, uint16_t queue_id,
                                             uint32_t src_ip, uint32_t dst_ip,
                                             uint16_t src_port, uint16_t dst_port,
                                             struct rte_flow_error *error)
{
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_queue queue = { .index = queue_id };
    struct rte_flow_item_ipv4 ip_spec;
    struct rte_flow_item_ipv4 ip_mask;

    struct rte_flow_item_tcp tcp_spec;
    struct rte_flow_item_tcp tcp_mask;
    int res;

    memset_s(pattern, sizeof(pattern), 0, sizeof(pattern));
    memset_s(action, sizeof(action), 0, sizeof(action));

    /*
     * set the rule attribute.
     * in this case only ingress packets will be checked.
     */
    memset_s(&attr, sizeof(struct rte_flow_attr), 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;

    /*
     * create the action sequence.
     * one action only,  move packet to queue
     */
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    // not limit eth header
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

    // ip header
    memset_s(&ip_spec, sizeof(struct rte_flow_item_ipv4), 0, sizeof(struct rte_flow_item_ipv4));
    memset_s(&ip_mask, sizeof(struct rte_flow_item_ipv4), 0, sizeof(struct rte_flow_item_ipv4));
    ip_spec.hdr.dst_addr = dst_ip;
    ip_mask.hdr.dst_addr = FULL_MASK;
    ip_spec.hdr.src_addr = src_ip;
    ip_mask.hdr.src_addr = FULL_MASK;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = &ip_spec;
    pattern[1].mask = &ip_mask;

    // tcp header, full mask 0xffff
    memset_s(&tcp_spec, sizeof(struct rte_flow_item_tcp), 0, sizeof(struct rte_flow_item_tcp));
    memset_s(&tcp_mask, sizeof(struct rte_flow_item_tcp), 0, sizeof(struct rte_flow_item_tcp));
    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP; // 2: pattern 2 is tcp header
    tcp_spec.hdr.src_port = src_port;
    tcp_spec.hdr.dst_port = dst_port;
    tcp_mask.hdr.src_port = rte_flow_item_tcp_mask.hdr.src_port;
    tcp_mask.hdr.dst_port = rte_flow_item_tcp_mask.hdr.dst_port;
    pattern[2].spec = &tcp_spec;
    pattern[2].mask = &tcp_mask;

    /* the final level must be always type end */
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res) {
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    } else {
        LSTACK_LOG(ERR, LSTACK, "rte_flow_create.rte_flow_validate error, res %d \n", res);
    }

    return flow;
}

static void config_flow_director(uint16_t queue_id, uint32_t src_ip,
                                 uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
    uint16_t port_id = get_protocol_stack_group()->port_id;
    char rule_key[RULE_KEY_LEN] = {0};
    sprintf_s(rule_key, sizeof(rule_key), "%u_%u_%u", src_ip, src_port, dst_port);
    struct flow_rule *fl_exist = find_rule(rule_key);
    if (fl_exist != NULL) {
        return;
    }

    LSTACK_LOG(INFO, LSTACK,
        "config_flow_director, flow queue_id %u, src_ip %u,src_port_ntohs:%u, dst_port_ntohs:%u\n",
        queue_id, src_ip, ntohs(src_port), ntohs(dst_port));

    struct rte_flow_error error;
    struct rte_flow *flow = create_flow_director(port_id, queue_id, src_ip, dst_ip, src_port, dst_port, &error);
    if (!flow) {
        LSTACK_LOG(ERR, LSTACK,"flow can not be created. queue_id %u, src_ip %u, src_port %u,"
                               "dst_port %u, dst_port_ntohs :%u, type %d. message: %s\n",
            queue_id, src_ip, src_port, dst_port, ntohs(dst_port),
            error.type, error.message ? error.message : "(no stated reason)");
        return;
    }
    __sync_fetch_and_add(&g_flow_num, 1);
    add_rule(rule_key, flow);
}

static void delete_flow_director(uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
    uint16_t port_id = get_protocol_stack_group()->port_id;
    char rule_key[RULE_KEY_LEN] = {0};
    sprintf_s(rule_key, RULE_KEY_LEN, "%u_%u_%u",dst_ip, dst_port, src_port);
    struct flow_rule *fl = find_rule(rule_key);

    if(fl != NULL) {
        struct rte_flow_error error;
        int ret = rte_flow_destroy(port_id, fl->flow, &error);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "Flow can't be delete %d message: %s\n",
                       error.type, error.message ? error.message : "(no stated reason)");
        }
        delete_rule(rule_key);
        __sync_fetch_and_sub(&g_flow_num, 1);
    }
}

/* if process 0, delete directly, else transfer 'dst_ip,src_port,dst_port' to process 0. */
void transfer_delete_rule_info_to_process0(uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
    if (get_global_cfg_params()->is_primary) {
        delete_flow_director(dst_ip, src_port, dst_port);
    } else {
        char process_server_path[DELETE_FLOWS_PARAMS_LENGTH];
        sprintf_s(process_server_path, DELETE_FLOWS_PARAMS_LENGTH, "%u%s%u%s%u",
                  dst_ip, SPLIT_DELIM, src_port, SPLIT_DELIM, dst_port);
        int ret = transfer_pkt_to_other_process(process_server_path, 0, DELETE_FLOWS_PARAMS_LENGTH, false);
        if (ret != TRANSFER_SUCESS) {
            LSTACK_LOG(ERR, LSTACK, "error. tid %d. dst_ip %u, src_port: %u, dst_port %u\n",
                       rte_gettid(), dst_ip, src_port, dst_port);
        }
    }
}

// if process 0, add directly, else transfer 'src_ip,dst_ip，src_port，dst_port,queue_id' to process 0.
void transfer_create_rule_info_to_process0(uint16_t queue_id, uint32_t src_ip,
                                           uint32_t dst_ip, uint16_t src_port,
                                           uint16_t dst_port)
{
    char process_server_path[CREATE_FLOWS_PARAMS_LENGTH];
    /* exchage src_ip and dst_ip, src_port and dst_port */
    uint8_t process_idx = get_global_cfg_params()->process_idx;
    sprintf_s(process_server_path, CREATE_FLOWS_PARAMS_LENGTH, "%u%s%u%s%u%s%u%s%u%s%u",
              dst_ip, SPLIT_DELIM, src_ip, SPLIT_DELIM,
              dst_port, SPLIT_DELIM, src_port, SPLIT_DELIM,
              queue_id, SPLIT_DELIM, process_idx);
    int ret = transfer_pkt_to_other_process(process_server_path, 0, CREATE_FLOWS_PARAMS_LENGTH, true);
    if (ret != TRANSFER_SUCESS) {
        LSTACK_LOG(ERR, LSTACK, "error. tid %d. src_ip %u, dst_ip %u, src_port: %u, dst_port %u,"
                                "queue_id %u, process_idx %u\n",
                   rte_gettid(), src_ip, dst_ip, src_port, dst_port, queue_id, process_idx);
    }
}

void transfer_add_or_delete_listen_port_to_process0(uint16_t listen_port, uint8_t process_idx, uint8_t is_add)
{
    char process_server_path[ADD_OR_DELETE_LISTEN_PORT_PARAMS_LENGTH];
    sprintf_s(process_server_path, ADD_OR_DELETE_LISTEN_PORT_PARAMS_LENGTH,
              "%u%s%u%s%u", listen_port, SPLIT_DELIM, process_idx, SPLIT_DELIM, is_add);
    int ret = transfer_pkt_to_other_process(process_server_path, 0, ADD_OR_DELETE_LISTEN_PORT_PARAMS_LENGTH, true);
    if (ret != TRANSFER_SUCESS) {
        LSTACK_LOG(ERR, LSTACK, "error. tid %d. listen_port %u, process_idx %u\n",
                   rte_gettid(), listen_port, process_idx);
    }
}

static int str_to_array(char *args, uint32_t *array, int size)
{
    int val;
    uint16_t cnt = 0;
    char *elem = NULL;
    char *next_token = NULL;

    memset_s(array, sizeof(*array) * size, 0, sizeof(*array) * size);
    elem = strtok_s((char *)args, SPLIT_DELIM, &next_token);
    while (elem != NULL) {
        if (cnt >= size) {
            return -1;
        }
        val = atoi(elem);
        if (val < 0) {
            return -1;
        }
        array[cnt] = (uint32_t)val;
        cnt++;

        elem = strtok_s(NULL, SPLIT_DELIM, &next_token);
    }

    return cnt;
}

static void parse_and_delete_rule(char* buf)
{
    uint32_t array[DELETE_FLOWS_PARAMS_NUM];
    str_to_array(buf, array, DELETE_FLOWS_PARAMS_NUM);
    uint32_t dst_ip = array[0];
    uint16_t src_port = array[1];
    uint16_t dst_port = array[2];
    delete_flow_director(dst_ip, src_port, dst_port);
}

void add_user_process_port(uint16_t dst_port, uint8_t process_idx, enum port_type type)
{
    if (type == PORT_LISTEN) {
        g_listen_ports[dst_port] = process_idx;
    } else {
        g_user_ports[dst_port] = process_idx;
    }
}

void delete_user_process_port(uint16_t dst_port, enum port_type type)
{
    if (type == PORT_LISTEN) {
        g_listen_ports[dst_port] = INVAILD_PROCESS_IDX;
    } else {
        g_user_ports[dst_port] = INVAILD_PROCESS_IDX;
    }
}

static void parse_and_create_rule(char* buf)
{
    uint32_t array[CREATE_FLOWS_PARAMS_NUM];
    str_to_array(buf, array, CREATE_FLOWS_PARAMS_NUM);
    uint32_t src_ip = array[0];
    uint32_t dst_ip = array[1];
    uint16_t src_port = array[2];
    uint16_t dst_port = array[3];
    uint16_t queue_id = array[4];
    uint8_t process_idx = array[5];
    config_flow_director(queue_id, src_ip, dst_ip, src_port, dst_port);
    add_user_process_port(dst_port, process_idx, PORT_CONNECT);
}

static void parse_and_add_or_delete_listen_port(char* buf)
{
    uint32_t array[ADD_OR_DELETE_LISTEN_PORT_PARAMS_NUM];
    str_to_array(buf, array, ADD_OR_DELETE_LISTEN_PORT_PARAMS_NUM);
    uint16_t listen_port = array[0];
    uint8_t process_idx = array[1];
    uint8_t is_add = array[2];
    if (is_add == 1) {
        add_user_process_port(listen_port, process_idx, PORT_LISTEN);
    } else {
        delete_user_process_port(listen_port, PORT_LISTEN);
    }
}

void transfer_arp_to_other_process(struct rte_mbuf *mbuf)
{
    struct cfg_params *cfgs = get_global_cfg_params();

    for (int i = 1; i < cfgs->num_process; i++) {
        char arp_mbuf[LSTACK_MBUF_LEN] = {0};
        sprintf_s(arp_mbuf, sizeof(arp_mbuf), "%lu", mbuf);
        int result = transfer_pkt_to_other_process(arp_mbuf, i, LSTACK_MBUF_LEN, false);
        if (result == CONNECT_ERROR) {
            LSTACK_LOG(INFO, LSTACK,"connect process %d failed, ensure the process is started.\n", i);
        } else if (result == REPLY_ERROR) {
            LSTACK_LOG(ERR, LSTACK,"transfer arp pakages to process %d error. %m\n", i);
        }
    }
}

static void transfer_tcp_to_thread(struct rte_mbuf *mbuf, uint16_t stk_idx)
{
    /* current process queue_id */
    struct protocol_stack *stack = get_protocol_stack_group()->stacks[stk_idx];
    int ret  = -1;
    while (ret != 0) {
        ret = rpc_call_arp(&stack->rpc_queue, mbuf);
        printf("transfer_tcp_to_thread, ret : %d \n", ret);
    }
}

static void parse_arp_and_transefer(char* buf)
{
    struct rte_mbuf *mbuf = (struct rte_mbuf *)atoll(buf);
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    struct rte_mbuf *mbuf_copy = NULL;
    struct protocol_stack *stack = NULL;
    int32_t ret;
    for (int32_t i = 0; i < stack_group->stack_num; i++) {
        stack = stack_group->stacks[i];
        ret = dpdk_alloc_pktmbuf(stack->rxtx_mbuf_pool, &mbuf_copy, 1, false);
        while (ret != 0) {
            ret = dpdk_alloc_pktmbuf(stack->rxtx_mbuf_pool, &mbuf_copy, 1, false);
            stack->stats.rx_allocmbuf_fail++;
        }
        copy_mbuf(mbuf_copy, mbuf);

        ret = rpc_call_arp(&stack->rpc_queue, mbuf_copy);

        while (ret != 0) {
            rpc_call_arp(&stack->rpc_queue, mbuf_copy);
        }
    }
}

static void parse_tcp_and_transefer(char* buf)
{
    char *next_token = NULL;
    char *elem = strtok_s(buf, SPLIT_DELIM, &next_token);
    struct rte_mbuf *mbuf = (struct rte_mbuf *) atoll(elem);
    elem = strtok_s(NULL, SPLIT_DELIM, &next_token);
    uint16_t queue_id = atoll(elem);

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    uint16_t num_queue = get_global_cfg_params()->num_queue;
    uint16_t stk_index = queue_id % num_queue;
    struct rte_mbuf *mbuf_copy = NULL;
    struct protocol_stack *stack = stack_group->stacks[stk_index];

    int32_t ret = dpdk_alloc_pktmbuf(stack->rxtx_mbuf_pool, &mbuf_copy, 1, false);
    while (ret != 0) {
        ret = dpdk_alloc_pktmbuf(stack->rxtx_mbuf_pool, &mbuf_copy, 1, false);
        stack->stats.rx_allocmbuf_fail++;
    }

    copy_mbuf(mbuf_copy,mbuf);
    transfer_tcp_to_thread(mbuf_copy, stk_index);
}

int recv_pkts_from_other_process(int process_index, void* arg)
{
    struct sockaddr_un serun, cliun;
    socklen_t cliun_len;
    int listenfd, connfd, size;
    char buf[132];
    /* socket */
    if ((listenfd = posix_api->socket_fn(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("socket error");
        return -1;
    }
    /* bind */
    memset_s(&serun, sizeof(serun), 0, sizeof(serun));
    serun.sun_family = AF_UNIX;
    char process_server_path[PATH_MAX];
    sprintf_s(process_server_path, sizeof(process_server_path), "%s%d", SERVER_PATH, process_index);
    strcpy_s(serun.sun_path, sizeof(serun.sun_path), process_server_path);
    size = offsetof(struct sockaddr_un, sun_path) + strlen(serun.sun_path);
    unlink(process_server_path);
    if (posix_api->bind_fn(listenfd, (struct sockaddr *)&serun, size) < 0) {
        perror("bind error");
        return -1;
    }
    if (posix_api->listen_fn(listenfd, 20) < 0) { /* 20: max backlog */
        perror("listen error");
        return -1;
    }
    sem_post((sem_t *)arg);
    /* block */
     while (1) {
        cliun_len = sizeof(cliun);
        if ((connfd = posix_api->accept_fn(listenfd, (struct sockaddr *)&cliun, &cliun_len)) < 0) {
            perror("accept error");
            continue;
        }
        while (1) {
            int n = posix_api->read_fn(connfd, buf, sizeof(buf));
            if (n < 0) {
                perror("read error");
                break;
            } else if (n == 0) {
                break;
            }

            if (n == LSTACK_MBUF_LEN) {
                /* arp */
                parse_arp_and_transefer(buf);
            } else if (n == TRANSFER_TCP_MUBF_LEN) {
                /* tcp. lstack_mbuf_queue_id */
                parse_tcp_and_transefer(buf);
            } else if (n == DELETE_FLOWS_PARAMS_LENGTH) {
                /* delete rule */
                parse_and_delete_rule(buf);
            } else if (n == CREATE_FLOWS_PARAMS_LENGTH) {
                /* add rule */
                parse_and_create_rule(buf);
                char reply_buf[REPLY_LEN];
                sprintf_s(reply_buf, sizeof(reply_buf), "%s", SUCCESS_REPLY);
                posix_api->write_fn(connfd, reply_buf, REPLY_LEN);
            } else if (n == GET_LSTACK_NUM) {
                char reply_buf[REPLY_LEN];
                sprintf_s(reply_buf, sizeof(reply_buf), "%d", get_global_cfg_params()->num_cpu);
                posix_api->write_fn(connfd, reply_buf, REPLY_LEN);
            } else {
                /* add port */
                parse_and_add_or_delete_listen_port(buf);
                char reply_buf[REPLY_LEN];
                sprintf_s(reply_buf, sizeof(reply_buf), "%s", SUCCESS_REPLY);
                posix_api->write_fn(connfd, reply_buf, REPLY_LEN);
            }
            
        }
        posix_api->close_fn(connfd);
    }
    posix_api->close_fn(listenfd);
    return 0;
}

void concat_mbuf_and_queue_id(struct rte_mbuf *mbuf, uint16_t queue_id,
                              char* mbuf_and_queue_id, int write_len)
{
    sprintf_s(mbuf_and_queue_id, write_len, "%lu%s%u", mbuf, SPLIT_DELIM, queue_id);
}

static int mbuf_to_idx(struct rte_mbuf *mbuf, uint16_t *dst_port)
{
    struct rte_ether_hdr *ethh = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    u16_t type  = rte_be_to_cpu_16(ethh->ether_type);
    uint32_t index = 0;
    if (type == RTE_ETHER_TYPE_IPV4) {
        struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
        uint8_t ip_version = (iph->version_ihl & 0xf0) >> IPV4_VERSION_OFFSET;
        if (likely(ip_version == IPV4_VERSION)) {
            if (likely(iph->next_proto_id == IPPROTO_TCP)) {
                struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *,
                    sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
                *dst_port = tcp_hdr->dst_port;

                if (unlikely(tcp_hdr->tcp_flags == TCP_SYN)) {
                    uint32_t src_ip = iph->src_addr;
                    uint16_t src_port = tcp_hdr->src_port;
                    index = rte_jhash_3words(src_ip, src_port | ((*dst_port) << 16), 0, 0);
                } else {
                    return -1;
                }
            }
        }
    } else if (type == RTE_ETHER_TYPE_IPV6) {
        struct rte_ipv6_hdr *iph = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, sizeof(struct rte_ether_hdr));
        if (likely(iph->proto == IPPROTO_TCP)) {
            struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *,
                sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr));
            *dst_port = tcp_hdr->dst_port;

            if (unlikely(tcp_hdr->tcp_flags == TCP_SYN)) {
                uint32_t *src_ip = (uint32_t *) &iph->src_addr;
                uint16_t src_port = tcp_hdr->src_port;
                uint32_t v = rte_jhash_3words(src_ip[0], src_ip[1], src_ip[2], 0);
                index = rte_jhash_3words(src_ip[3], src_port | ((*dst_port) << 16), v, 0);
            } else {
                return -1;
            }
        }
    } else {
        return -1;
    }
    return index;
}

int distribute_pakages(struct rte_mbuf *mbuf)
{
    uint16_t dst_port = 0;
    uint32_t index = mbuf_to_idx(mbuf, &dst_port);
    if (index == -1) {
        return TRANSFER_CURRENT_THREAD;
    }

    uint16_t queue_id = 0;
    uint32_t user_process_idx = 0;
    int each_process_queue_num = get_global_cfg_params()->num_queue;
    index = index % each_process_queue_num;
    if (g_listen_ports[dst_port] != INVAILD_PROCESS_IDX) {
        user_process_idx = g_listen_ports[dst_port];
    } else {
        user_process_idx = g_user_ports[dst_port];
    }

    if (user_process_idx == INVAILD_PROCESS_IDX) {
        return TRANSFER_KERNEL;
    }

    if (get_global_cfg_params()->seperate_send_recv) {
        queue_id = user_process_idx * each_process_queue_num + (index / 2) * 2;
    } else {
        queue_id = user_process_idx * each_process_queue_num + index;
    }
    if (queue_id != 0) {
        if (user_process_idx == 0) {
            transfer_tcp_to_thread(mbuf, queue_id);
        } else {
            char mbuf_and_queue_id[TRANSFER_TCP_MUBF_LEN];
            concat_mbuf_and_queue_id(mbuf, queue_id, mbuf_and_queue_id, TRANSFER_TCP_MUBF_LEN);
            transfer_pkt_to_other_process(mbuf_and_queue_id, user_process_idx,
                TRANSFER_TCP_MUBF_LEN, false);
        }
        return TRANSFER_OTHER_THREAD;
    } else {
        return TRANSFER_CURRENT_THREAD;
    }

    return TRANSFER_KERNEL;
}

void gazelle_listen_thread(void *arg)
{
    struct cfg_params *cfg_param = get_global_cfg_params();
    recv_pkts_from_other_process(cfg_param->process_idx, arg);
}

void flow_init(void)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    init_listen_and_user_ports();

    /* run to completion mode does not currently support multiple process */
    if (!use_ltran() && !get_global_cfg_params()->stack_mode_rtc) {
        char name[PATH_MAX];
        sem_init(&stack_group->sem_listen_thread, 0, 0);
        sprintf_s(name, sizeof(name), "%s", "listen_thread");
        struct sys_thread *thread = sys_thread_new(name, gazelle_listen_thread,
            (void*)(&stack_group->sem_listen_thread), 0, 0);
        free(thread);
        sem_wait(&stack_group->sem_listen_thread);
    }
}
