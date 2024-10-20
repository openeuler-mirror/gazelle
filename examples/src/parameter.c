/*
* Copyright (c) 2022-2023. yyangoO.
* gazelle is licensed under the Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*     http://license.coscl.org.cn/MulanPSL2
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
* PURPOSE.
* See the Mulan PSL v2 for more details.
*/


#include "parameter.h"

static int32_t g_inject_delay[INJECT_DELAY_MAX] = {0};
static int32_t g_inject_skip[INJECT_SKIP_MAX];

// program short options
const char prog_short_opts[] = \
    "a:"        // as
    "i:"        // ip
    "p:"        // port
    "s:"        // sport
    "m:"        // model
    "t:"        // thread number
    "c:"        // connect number
    "D:"        // communication domain
    "A:"        // api
    "P:"        // pktlen
    "v"         // verify
    "r"         // ringpmd
    "d"         // debug
    "h"         // help
    "E:"         // epollcreate
    "C:"         // accept
    "g:"        // group address
    "k:"        // tcp keep_alive
    "I:"        // fault inject
    ;

// program long options
const struct ProgramOption prog_long_opts[] = \
{
    {PARAM_NAME_AS, REQUIRED_ARGUMETN, NULL, PARAM_NUM_AS},
    {PARAM_NAME_IP, REQUIRED_ARGUMETN, NULL, PARAM_NUM_IP},
    {PARAM_NAME_PORT, REQUIRED_ARGUMETN, NULL, PARAM_NUM_PORT},
    {PARAM_NAME_SPORT, REQUIRED_ARGUMETN, NULL, PARAM_NUM_SPORT},
    {PARAM_NAME_MODEL, REQUIRED_ARGUMETN, NULL, PARAM_NUM_MODEL},
    {PARAM_NAME_THREAD_NUM, REQUIRED_ARGUMETN, NULL, PARAM_NUM_THREAD_NUM},
    {PARAM_NAME_CONNECT_NUM, REQUIRED_ARGUMETN, NULL, PARAM_NUM_CONNECT_NUM},
    {PARAM_NAME_DOMAIN, REQUIRED_ARGUMETN, NULL, PARAM_NUM_DOMAIN},
    {PARAM_NAME_API, REQUIRED_ARGUMETN, NULL, PARAM_NUM_API},
    {PARAM_NAME_PKTLEN, REQUIRED_ARGUMETN, NULL, PARAM_NUM_PKTLEN},
    {PARAM_NAME_VERIFY, NO_ARGUMENT, NULL, PARAM_NUM_VERIFY},
    {PARAM_NAME_RINGPMD, NO_ARGUMENT, NULL, PARAM_NUM_RINGPMD},
    {PARAM_NAME_DEBUG, NO_ARGUMENT, NULL, PARAM_NUM_DEBUG},
    {PARAM_NAME_HELP, NO_ARGUMENT, NULL, PARAM_NUM_HELP},
    {PARAM_NAME_EPOLLCREATE, REQUIRED_ARGUMETN, NULL, PARAM_NUM_EPOLLCREATE},
    {PARAM_NAME_ACCEPT, REQUIRED_ARGUMETN, NULL, PARAM_NUM_ACCEPT},
    {PARAM_NAME_GROUPIP, REQUIRED_ARGUMETN, NULL, PARAM_NUM_GROUPIP},
    {PARAM_NAME_KEEPALIVE, REQUIRED_ARGUMETN, NULL, PARAM_NUM_KEEPALIVE},
    {PARAM_NAME_INJECT, REQUIRED_ARGUMETN, NULL, PARAM_NUM_INJECT},
};


// get long options
int getopt_long(int argc, char * const argv[], const char *optstring, const struct ProgramOption *long_opts, int *long_idx);
// index [0,7)
uint8_t getbit_num(uint8_t mode, uint8_t index)
{
    return (mode & ((uint8_t)1 << index)) != 0;
}

uint8_t setbitnum_on(uint8_t mode, uint8_t index)
{
    mode |=  ((uint8_t)1 << index);
    return mode;
}

uint8_t setbitnum_off(uint8_t mode, uint8_t index)
{
    mode &=  ~((uint8_t)1 << index);
    return mode;
}

static uint8_t program_set_protocol_mode(uint8_t protocol_mode, char *ipv4, char *ipv6, uint8_t index_v4,
                                         uint8_t index_v6)
{
    uint8_t protocol_mode_temp = protocol_mode;
    if (strcmp(ipv4, PARAM_DEFAULT_IP) != 0) {
        protocol_mode_temp = setbitnum_on(protocol_mode_temp, index_v4);
    }
    if (strcmp(ipv6, PARAM_DEFAULT_IP_V6) != 0) {
        protocol_mode_temp = setbitnum_on(protocol_mode_temp, index_v6);
    }
    return protocol_mode_temp;
}

uint8_t program_get_protocol_mode_by_domain_ip(char* domain, char* ipv4, char* ipv6, char* groupip)
{
    uint8_t protocol_mode = 0;
    char *cur_ptr = NULL;
    char *next_Ptr = NULL;
    cur_ptr = strtok_s(domain, ",", &next_Ptr);
    while (cur_ptr) {
        if (strcmp(cur_ptr, "tcp") == 0) {
            protocol_mode = program_set_protocol_mode(protocol_mode, ipv4, ipv6, V4_TCP, V6_TCP);
        } else if (strcmp(cur_ptr, "udp") == 0) {
            protocol_mode = program_set_protocol_mode(protocol_mode, ipv4, ipv6, V4_UDP, V6_UDP);
        } else if (strcmp(cur_ptr, "unix") == 0) {
            protocol_mode = setbitnum_on(protocol_mode, UNIX);
        }
        cur_ptr = strtok_s(NULL, ",", &next_Ptr);
    }

    if (strcmp(groupip, PARAM_DEFAULT_GROUPIP) != 0) {
        protocol_mode = setbitnum_on(protocol_mode, UDP_MULTICAST);
    }

    return protocol_mode;
}

// set `as` parameter
void program_param_parse_as(struct ProgramParams *params)
{
    if (strcmp(optarg, "server") == 0 || strcmp(optarg, "client") == 0 || strcmp(optarg, "loop") == 0) {
        params->as = optarg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

bool ip_is_v6(const char *cp)
{
    if (cp != NULL) {
        const char *c;
        for (c = cp; *c != 0; c++) {
            if (*c == ':') {
                return 1;
            }
        }
    }
    return 0;
}


static bool program_ipv4_check(char *ipv4)
{
    in_addr_t ip = ntohl(inet_addr(ipv4));
    if (ip == INADDR_NONE) {
        PRINT_ERROR("illigal argument -- %s \n", ipv4);
        return false;
    }
    if ((ip >= ntohl(inet_addr("1.0.0.1"))   && ip <= ntohl(inet_addr("126.255.255.254"))) ||
        (ip >= ntohl(inet_addr("127.0.0.1")) && ip <= ntohl(inet_addr("127.255.255.254"))) ||
        (ip >= ntohl(inet_addr("128.0.0.1")) && ip <= ntohl(inet_addr("191.255.255.254"))) ||
        (ip >= ntohl(inet_addr("192.0.0.1")) && ip <= ntohl(inet_addr("223.255.255.254"))) ||
        (ip >= ntohl(inet_addr("224.0.0.1")) && ip <= ntohl(inet_addr("224.255.255.255"))) ) { // Broadcast IP
        return true;
    }

    PRINT_ERROR("illigal argument -- %s \n", ipv4);
    return false;
}

static void program_param_parse_ipv4_addr(char* v4ip_addr, struct ProgramParams *params)
{
    struct in6_addr ip_tmp;
    params->addr_family = AF_INET;
    if (inet_pton(params->addr_family, v4ip_addr, &ip_tmp) > 0 && program_ipv4_check(v4ip_addr) == true) {
        params->ip = v4ip_addr;
    } else {
        PRINT_ERROR("illegal ipv4 addr -- %s \n", v4ip_addr);
        exit(PROGRAM_ABORT);
    }
}

static void program_param_parse_ipv6_addr(char* v6ip_add, struct ProgramParams *params)
{
    struct in6_addr ip_tmp;
    params->addr_family = AF_INET6;
    if (inet_pton(AF_INET6, v6ip_add, &ip_tmp) > 0) {
        params->ipv6 = v6ip_add;
    } else {
        PRINT_ERROR("illegal ipv6 addr -- %s \n", v6ip_add);
        exit(PROGRAM_ABORT);
    }
}
// set `ip` parameter,支持同时配置 ipv4 和 ipv6 地址，格式为 ipv4,ipv6
void program_param_parse_ip(struct ProgramParams *params)
{
    char *cur_ptr = NULL;
    char *next_ptr = NULL;

    cur_ptr = strtok_s(optarg, ",", &next_ptr);
    while (cur_ptr) {
        if (ip_is_v6(cur_ptr)) {
            program_param_parse_ipv6_addr(cur_ptr, params);
        } else {
            program_param_parse_ipv4_addr(cur_ptr, params);
        }
        cur_ptr = strtok_s(NULL, ",", &next_ptr);
    }
}

// set `port` parameter
void program_param_parse_port(struct ProgramParams *params)
{
    char* port_list = optarg;
    char* token = NULL;
    int32_t port_arg = 0;
    params->port[PARAM_DEFAULT_PORT] = 0;

    while ((token = strtok_r(port_list, ",", &port_list))) {
        port_arg = strtol(token, NULL, 0);
        if (CHECK_VAL_RANGE(port_arg, UNIX_TCP_PORT_MIN, UNIX_TCP_PORT_MAX) == true) {
            params->port[port_arg] = 1;
        } else {
            PRINT_ERROR("illigal argument -- %s \n", optarg);
            exit(PROGRAM_ABORT);
        }
    }
}

// set `sport` parameter
void program_param_parse_sport(struct ProgramParams *params)
{
    char* port_list = optarg;
    char* token = NULL;
    int32_t port_arg = 0;

    while ((token = strtok_r(port_list, ",", &port_list))) {
        port_arg = strtol(token, NULL, 0);
        if (CHECK_VAL_RANGE(port_arg, UNIX_TCP_PORT_MIN, UNIX_TCP_PORT_MAX) == true) {
            params->sport[port_arg] = 1;
        } else {
            PRINT_ERROR("illigal argument -- %s \n", optarg);
            exit(PROGRAM_ABORT);
        }
    }
}

// set `model` parameter
void program_param_parse_model(struct ProgramParams *params)
{
    if (strcmp(optarg, "mum") == 0 || strcmp(optarg, "mud") == 0) {
        params->model = optarg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `connect_num` parameter
void program_param_parse_connectnum(struct ProgramParams *params)
{
    int32_t connectnum_arg = strtol(optarg, NULL, 0);
    if (connectnum_arg > 0) {
        params->connect_num = (uint32_t)connectnum_arg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `thread_num` parameter
void program_param_parse_threadnum(struct ProgramParams *params)
{
    int32_t threadnum_arg = strtol(optarg, NULL, 0);
    if (CHECK_VAL_RANGE(threadnum_arg, THREAD_NUM_MIN, THREAD_NUM_MAX) == true) {
        params->thread_num = (uint32_t)threadnum_arg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `domain` parameter
void program_param_parse_domain(struct ProgramParams *params)
{
    char temp[100] = {0};
    int32_t ret = strcpy_s(temp, sizeof(temp) / sizeof(char), optarg);
    if (ret != 0) {
        PRINT_ERROR("strcpy_s fail ret=%d \n", ret);
        exit(PROGRAM_ABORT);
    }
    char *cur_ptr = temp;
    char *next_ptr = NULL;
    cur_ptr = strtok_s(cur_ptr, ",", &next_ptr);
    while (cur_ptr) {
        if (strcmp(cur_ptr, "tcp") != 0 && strcmp(cur_ptr, "udp") != 0 && strcmp(cur_ptr, "unix") != 0) {
            PRINT_ERROR("illigal argument -- %s \n", cur_ptr);
            exit(PROGRAM_ABORT);
        }
        cur_ptr = strtok_s(NULL, ",", &next_ptr);
    }
    params->domain = optarg;
}

// set `api` parameter
void program_param_parse_api(struct ProgramParams *params)
{
    const char *valid_apis[] = {
        "readwrite",
        "readvwritev",
        "recvsend",
        "recvsendmsg",
        "recvfromsendto",
        "recvfrom"
    };

    size_t num_apis = sizeof(valid_apis) / sizeof(valid_apis[0]);
    bool valid = false;

    for (size_t i = 0; i < num_apis; i++) {
        if (strcmp(optarg, valid_apis[i]) == 0) {
            params->api = optarg;
            valid = true;
            break;
        }
    }

    if (!valid) {
        PRINT_ERROR("Illegal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `pktlen` parameter
void program_param_parse_pktlen(struct ProgramParams *params)
{
    int32_t pktlen_arg = strtol(optarg, NULL, 0);
    if (CHECK_VAL_RANGE(pktlen_arg, MESSAGE_PKTLEN_MIN, MESSAGE_PKTLEN_MAX) == true) {
        params->pktlen = (uint32_t)pktlen_arg;
        if (strstr(params->domain, "udp") && params->pktlen > UDP_PKTLEN_MAX) {
            PRINT_WARNNING("udp message too long, change it to %d \n", UDP_PKTLEN_MAX);
        }
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `epollcreate` parameter
void program_param_parse_epollcreate(struct ProgramParams *params)
{
    if (strcmp(optarg, "ec") == 0 || strcmp(optarg, "ec1") == 0) {
        params->epollcreate = optarg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `accept` parameter
void program_param_parse_accept(struct ProgramParams *params)
{
    if (strcmp(optarg, "ac") == 0 || strcmp(optarg, "ac4") == 0) {
        params->accept = optarg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `tcp_keepalive_idle` parameter
void program_param_parse_keepalive(struct ProgramParams *params)
{
    char *token = NULL;
    char *next_token = NULL;
    token = strtok_s(optarg, ",", &next_token);
    if (token == NULL) {
        PRINT_ERROR("parse keep_alive idle null, illigal argument(%s) \n", optarg);
        exit(PROGRAM_ABORT);
    }

    int32_t keep_alive_idle = strtol(optarg, NULL, 0);
    if (keep_alive_idle > 0 && keep_alive_idle <= TCP_KEEPALIVE_IDLE_MAX) {
        params->tcp_keepalive_idle = keep_alive_idle;
    } else {
        PRINT_ERROR("keep_alive_idle=%d,illigal argument -- %s \n", keep_alive_idle, optarg);
        exit(PROGRAM_ABORT);
    }

    token = strtok_s(NULL, ",", &next_token);
    if (token == NULL) {
        PRINT_ERROR("parse keep_alive interval null, illigal argument(%s) \n", optarg);
        exit(PROGRAM_ABORT);
    }
    int32_t keep_alive_interval = strtol(token, NULL, 0);
    if (keep_alive_interval > 0 && keep_alive_interval <= TCP_KEEPALIVE_IDLE_MAX) {
        params->tcp_keepalive_interval = keep_alive_interval;
    } else {
        PRINT_ERROR("keep_alive_interval=%d,illigal argument -- %s \n", keep_alive_interval, optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `group ip` parameter
void program_param_parse_groupip(struct ProgramParams *params)
{
    char *cur_ptr = NULL;
    char *next_ptr = NULL;

    cur_ptr = strtok_s(optarg, ",", &next_ptr);
    if (program_ipv4_check(cur_ptr) == false) {
        PRINT_ERROR("illigal argument -- %s \n", cur_ptr);
        exit(PROGRAM_ABORT);
    }

    in_addr_t ip = ntohl(inet_addr(cur_ptr));
    if (ip != INADDR_NONE && ip >= ntohl(inet_addr("224.0.0.0")) && ip <= ntohl(inet_addr("239.255.255.255"))) {
        params->groupip = cur_ptr;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", cur_ptr);
        exit(PROGRAM_ABORT);
    }

    if (*next_ptr) {
        if (program_ipv4_check(next_ptr)) {
            params->groupip_interface = next_ptr;
        } else {
            PRINT_ERROR("illigal argument -- %s \n", next_ptr);
            exit(PROGRAM_ABORT);
        }
    }
}

void fault_inject_delay(delay_type type)
{
    if (g_inject_delay[type]) {
        printf("FAULT INJECT: Delay begin, sleep %d seconds.\n", g_inject_delay[type]);
        sleep(g_inject_delay[type]);
        g_inject_delay[type] = 0;
        printf("FAULT INJECT: Delay finished.\n");
    }
}


// apply fault inject type of delay
static void delay_param_parse(struct ProgramParams *params)
{
    int32_t time = 0;
    if (params->inject[INJECT_TIME_IDX] != NULL) {
        time = atoi(params->inject[INJECT_TIME_IDX]);
    }
    if (time <= 0) {
        PRINT_ERROR("FAULT INJECT: delay time input error! receive: \"%s\"\n", params->inject[INJECT_TIME_IDX]);
        exit(PROGRAM_ABORT);
    }
    
    char *location = params->inject[INJECT_LOCATION_IDX];
    if (location == NULL) {
        PRINT_ERROR("FAULT INJECT: Lack param for delay fault inject, The location is not appointed.\n");
        exit(PROGRAM_ABORT);
    }
    
    if (strcmp("before_accept", location) == 0) {
        g_inject_delay[INJECT_DELAY_ACCEPT] = time;
        return;
    }
    if (strcmp("before_read", location) == 0) {
        g_inject_delay[INJECT_DELAY_READ] = time;
        return;
    }
    if (strcmp("before_write", location) == 0) {
        g_inject_delay[INJECT_DELAY_WRITE] = time;
        return;
    }
    if (strcmp("before_read_and_write", location) == 0) {
        g_inject_delay[INJECT_DELAY_READ] = time;
        g_inject_delay[INJECT_DELAY_WRITE] = time;
        return;
    }

    PRINT_ERROR("FAULT INJECT: Unidentified fault inject location -- %s \n", location);
    exit(PROGRAM_ABORT);
}

// apply fault inject type of skip
static void skip_param_parse(struct ProgramParams *params)
{
    char* location = params->inject[INJECT_SKIP_IDX];
    if (location == NULL) {
        PRINT_ERROR("FAULT INJECT: Lack param for skip fault inject, location is not appointed.\n");
        exit(PROGRAM_ABORT);
    }

    if (strcmp("read", location) == 0) {
        g_inject_skip[INJECT_SKIP_READ] = 1;
        return;
    }
    if (strcmp("write", location) == 0) {
        g_inject_skip[INJECT_SKIP_WRITE] = 1;
        return;
    }
    if (strcmp("read_and_write", location) == 0) {
        g_inject_skip[INJECT_SKIP_READ] = 1;
        g_inject_skip[INJECT_SKIP_WRITE] = 1;
        return;
    }

    PRINT_ERROR("FAULT INJECT: Unidentified fault inject location -- %s \n", location);
    exit(PROGRAM_ABORT);
}

// judge if need skip fault inject
int32_t get_g_inject_skip(skip_type type)
{
    return g_inject_skip[type];
}

// check legitimacy of fault injection and apply it.
static void apply_fault_inject(struct ProgramParams *params)
{
    char *inject_type = params->inject[INJECT_TYPE_IDX];
    if (strcmp("delay", inject_type) == 0) {
        delay_param_parse(params);
        return;
    }
    if (strcmp("skip", inject_type) == 0) {
        skip_param_parse(params);
        return;
    }
    
    PRINT_ERROR("FAULT INJCET: Unidentified fault inject -- %s \n", inject_type);
    exit(PROGRAM_ABORT);
}

// set `fault injection` parameter
static void program_param_parse_inject(struct ProgramParams *params)
{
    int32_t inject_idx = 0;
    char *inject_input = strdup(optarg);
    if (inject_input == NULL) {
        PRINT_ERROR("FAULT INJCET: Insufficient memory, strdup failed.\n");
        exit(PROGRAM_ABORT);
    }
    
    char *context = NULL;
    char *elem = strtok_s(inject_input, " ", &context);
    if (elem == NULL) {
        PRINT_ERROR("FAULT INJECT: Input error. -- %s \n", inject_input);
        exit(PROGRAM_ABORT);
    }
    while (elem != NULL) {
        if (inject_idx == FAULT_INJECT_PARA_COUNT) {
            PRINT_ERROR("FAULT INJECT: Exceed the max count (3) of fault inject params. -- %s\n", optarg);
            exit(PROGRAM_ABORT);
        }
        params->inject[inject_idx++] = elem;
        elem = strtok_s(NULL, " ", &context);
    }

    apply_fault_inject(params);
}

// initialize the parameters
void program_params_init(struct ProgramParams *params)
{
    params->as = PARAM_DEFAULT_AS;
    params->ip = PARAM_DEFAULT_IP;
    params->ipv6 = PARAM_DEFAULT_IP_V6;
    params->addr_family = PARAM_DEFAULT_ADDR_FAMILY;
    memset_s(params->port, sizeof(bool)*UNIX_TCP_PORT_MAX, 0, sizeof(bool)*UNIX_TCP_PORT_MAX);
    memset_s(params->sport, sizeof(bool)*UNIX_TCP_PORT_MAX, 0, sizeof(bool)*UNIX_TCP_PORT_MAX);
    (params->port)[PARAM_DEFAULT_PORT] = 1;
    params->model = PARAM_DEFAULT_MODEL;
    params->thread_num = PARAM_DEFAULT_THREAD_NUM;
    params->connect_num = PARAM_DEFAULT_CONNECT_NUM;
    params->domain = PARAM_DEFAULT_DOMAIN;
    params->api = PARAM_DEFAULT_API;
    params->pktlen = PARAM_DEFAULT_PKTLEN;
    params->verify = PARAM_DEFAULT_VERIFY;
    params->ringpmd = PARAM_DEFAULT_RINGPMD;
    params->debug = PARAM_DEFAULT_DEBUG;
    params->epollcreate = PARAM_DEFAULT_EPOLLCREATE;
    params->accept = PARAM_DEFAULT_ACCEPT;
    params->groupip = PARAM_DEFAULT_GROUPIP;
    params->groupip_interface = PARAM_DEFAULT_GROUPIP;
    params->tcp_keepalive_idle = PARAM_DEFAULT_KEEPALIVEIDLE;
    params->tcp_keepalive_interval = PARAM_DEFAULT_KEEPALIVEIDLE;
}

// print program helps
void program_params_help(void)
{
    printf("\n");
    printf("-a, --as [server | client | loop]: set programas server, client or loop. \n");
    printf("    server: as server. \n");
    printf("    client: as client. \n");
    printf("    loop: as server and client. \n");
    printf("-i, --ip [???.???.???.???]: set ip address. \n");
    printf("-g, --groupip [???.???.???.???]: set group ip address. \n");
    printf("-p, --port [????]: set port number in range of %d - %d. \n", UNIX_TCP_PORT_MIN, UNIX_TCP_PORT_MAX);
    printf("-s, --sport [????]: set sport number in range of %d - %d. \n", UNIX_TCP_PORT_MIN, UNIX_TCP_PORT_MAX);
    printf("-m, --model [mum | mud]: set the network model. \n");
    printf("    mum: multi thread, unblock, multiplexing IO network model. \n");
    printf("    mud: multi thread, unblock, dissymmetric network model. \n");
    printf("-t, --threadnum [???]: set thread number in range of %d - %d. \n", THREAD_NUM_MIN, THREAD_NUM_MAX);
    printf("-c, --connectnum [???]: set connection number of each thread. \n");
    printf("-D, --domain [unix | tcp | udp]: set domain type is server or client. \n");
    printf("    unix: use unix's api. \n");
    printf("    tcp: use tcp api. \n");
    printf("    udp: use udp api. \n");
    printf("-A, --api [readwrite | recvsend | recvsendmsg | recvfromsendto | recvfrom]: set api type is server or client. \n");
    printf("    readwrite: use `read` and `write`. \n");
    printf("    recvsend: use `recv and `send`. \n");
    printf("    recvsendmsg: use `recvmsg` and `sendmsg`. \n");
    printf("    recvfromsendto: use `recvfrom` and `sendto`. \n");
    printf("    recvfrom: just use `recvfrom`, used by the server to receive group messages. \n");
    printf("-P, --pktlen [????]: set packet length in range of %d - %d. \n", MESSAGE_PKTLEN_MIN, MESSAGE_PKTLEN_MAX);
    printf("-v, --verify: set to verifying the message packet. \n");
    printf("-r, --ringpmd: set to use ringpmd. \n");
    printf("-d, --debug: set to print the debug information. \n");
    printf("-h, --help: see helps. \n");
    printf("-E, --epollcreate [ec | ec1]: epoll_create method. \n");
    printf("-C, --accept [ac | ac4]: accept method. \n");
    printf("-k, --keep_alive [keep_alive_idle:keep_alive_interval]: set tcp-alive info in range of %d-%d. \n",
           PARAM_DEFAULT_KEEPALIVEIDLE, TCP_KEEPALIVE_IDLE_MAX);
    printf("-I, --inject [\"fault_inject_param0 fault_inject_param1 fault_inject_param2\"]: fault inject\n");
    printf("    for example: \"delay 20 before_accept\"\n");
    printf("                 \"delay 20 before_read\"\n");
    printf("                 \"delay 20 before_write\"\n");
    printf("                 \"delay 20 before_read_and_write\"\n");
    printf("                 \"skip read\"\n");
    printf("                 \"skip write\"\n");
    printf("                 \"skip read_and_write\"\n");
    printf("\n");
}

// parse the parameters
int32_t program_params_parse(struct ProgramParams *params, uint32_t argc, char *argv[])
{
    int32_t c;

    while (true) {
        int32_t opt_idx = 0;

        c = getopt_long(argc, argv, prog_short_opts, prog_long_opts, &opt_idx);

        if (c == -1) {
            break;
        }

        switch (c) {
            case (PARAM_NUM_AS):
                program_param_parse_as(params);
                break;
            case (PARAM_NUM_IP):
                program_param_parse_ip(params);
                break;
            case (PARAM_NUM_PORT):
                program_param_parse_port(params);
                break;
            case (PARAM_NUM_SPORT):
                program_param_parse_sport(params);
                break;
            case (PARAM_NUM_MODEL):
                program_param_parse_model(params);
                break;
            case (PARAM_NUM_CONNECT_NUM):
                program_param_parse_connectnum(params);
                break;
            case (PARAM_NUM_THREAD_NUM):
                program_param_parse_threadnum(params);
                break;
            case (PARAM_NUM_DOMAIN):
                program_param_parse_domain(params);
                break;
            case (PARAM_NUM_API):
                program_param_parse_api(params);
                break;
            case (PARAM_NUM_PKTLEN):
                program_param_parse_pktlen(params);
                break;
            case (PARAM_NUM_VERIFY):
                params->verify = true;
                break;
            case (PARAM_NUM_RINGPMD):
                params->ringpmd = true;
                break;
            case (PARAM_NUM_DEBUG):
                params->debug = true;
                break;
            case (PARAM_NUM_EPOLLCREATE):
                program_param_parse_epollcreate(params);
                break;
            case (PARAM_NUM_ACCEPT):
                program_param_parse_accept(params);
                break;
            case (PARAM_NUM_GROUPIP):
                program_param_parse_groupip(params);
                break;
            case (PARAM_NUM_KEEPALIVE):
                program_param_parse_keepalive(params);
                break;
            case (PARAM_NUM_INJECT):
                program_param_parse_inject(params);
                break;
            case (PARAM_NUM_HELP):
                program_params_help();
                return PROGRAM_ABORT;
            case ('?'):
                return PROGRAM_ABORT;
            default:
                program_params_help();
                return PROGRAM_ABORT;
        }
    }

    return PROGRAM_OK;
}

// print the parameters
void program_params_print(struct ProgramParams *params)
{
    printf("\n");
    printf("[program parameters]: \n");
    printf("--> [as]:                       %s \n", params->as);
    if (strcmp(params->groupip, PARAM_DEFAULT_GROUPIP) != 0) {
        if (strcmp(params->as, "server") == 0) {
            printf("--> [server group ip]:          %s \n", params->groupip);
            printf("--> [server groupip_interface]: %s \n", params->groupip_interface);
        } else {
            printf("--> [client group ip]:          %s \n", params->groupip);
            printf("--> [client groupip_interface]: %s \n", params->groupip_interface);
        }
    }
    printf("--> [server ip]:                %s \n", params->ip);
    if (strcmp(params->ipv6, PARAM_DEFAULT_IP_V6) != 0) {
        printf("--> [server ipv6]:              %s \n", params->ipv6);
    }

    printf("--> [server port]:              ");
    uint32_t comma = 0;
    uint32_t sport = 0;

    /* use comma to print port list */
    for (uint32_t i = UNIX_TCP_PORT_MIN; i < UNIX_TCP_PORT_MAX; i++) {
        if ((params->port)[i]) {
            printf("%s%u", comma?",":"", i);
            comma = 1;
        }
        if ((params->sport)[i]) {
            sport = i;
        }
    }
    printf(" \n");

    /* use comma to print sport list */
    if (sport && strcmp(params->as, "client") == 0) {
        printf("--> [client sport]:             ");
        comma = 0;
        for (uint32_t i = UNIX_TCP_PORT_MIN; i < sport + 1; i++) {
            if ((params->sport)[i]) {
                printf("%s%u", comma?",":"", i);
                comma = 1;
            }
        }
        printf(" \n");
    }

    if (strcmp(params->as, "server") == 0) {
        printf("--> [model]:                    %s \n", params->model);
    }
    if ((strcmp(params->as, "server") == 0 && strcmp(params->model, "mum") == 0) || strcmp(params->as, "client") == 0) {
        printf("--> [thread number]:            %u \n", params->thread_num);
    }
    if (strcmp(params->as, "client") == 0) {
        printf("--> [connection number]:        %u \n", params->connect_num);
    }
    printf("--> [domain]:                   %s \n", params->domain);
    if (strcmp(params->api, "readwrite") == 0) {
        printf("--> [api]:                      read & write \n");
    } else if (strcmp(params->api, "recvsend") == 0) {
        printf("--> [api]:                      recv & send \n");
    } else if (strcmp(params->api, "recvsendmsg") == 0) {
        printf("--> [api]:                      recvmsg & sendmsg \n");
    } else if (strcmp(params->api, "recvfromsendto") == 0) {
        printf("--> [api]:                      recvfrom & sendto \n");
    } else {
        printf("--> [api]:                      recvfrom \n");
    }
    printf("--> [packet length]:            %u \n", params->pktlen);
    printf("--> [verify]:                   %s \n", (params->verify == true) ? "on" : "off");
    printf("--> [ringpmd]:                  %s \n", (params->ringpmd == true) ? "on" : "off");
    printf("--> [debug]:                    %s \n", (params->debug == true) ? "on" : "off");
    printf("--> [epoll create]:             %s \n", params->epollcreate);
    printf("--> [accept]:                   %s \n", params->accept);
    printf("--> [inject]:                   ");
    if (params->inject[INJECT_TYPE_IDX] == NULL) {
        printf("none \n");
    } else {
        for (int32_t i = 0; i < FAULT_INJECT_PARA_COUNT; ++i) {
            if (params->inject[i] != NULL) {
                printf("%s ", params->inject[i]);
            }
        }
	printf("\n");
    }
    printf("\n");
}
