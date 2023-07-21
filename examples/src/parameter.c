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
    "E"         // epollcreate
    "C"         // accept
    "g:"        // group address
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
};


// get long options
int getopt_long(int argc, char * const argv[], const char *optstring, const struct ProgramOption *long_opts, int *long_idx);


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

// set `ip` parameter
void program_param_parse_ip(struct ProgramParams *params)
{
    if (inet_addr(optarg) != INADDR_NONE) {
        params->ip = optarg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
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
    if (strcmp(optarg, "unix") == 0 || strcmp(optarg, "tcp") == 0 || strcmp(optarg, "udp") == 0) {
        params->domain = optarg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `api` parameter
void program_param_parse_api(struct ProgramParams *params)
{
    printf("aaaaaa %s\n", optarg);
    if (strcmp(optarg, "readwrite") == 0 || strcmp(optarg, "readvwritev") == 0 || strcmp(optarg, "recvsend") == 0 || strcmp(optarg, "recvsendmsg") == 0 || strcmp(optarg, "recvfromsendto") == 0 || strcmp(optarg, "recvfrom") == 0) {
        params->api = optarg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `pktlen` parameter
void program_param_parse_pktlen(struct ProgramParams *params)
{
    int32_t pktlen_arg = strtol(optarg, NULL, 0);
    if (CHECK_VAL_RANGE(pktlen_arg, MESSAGE_PKTLEN_MIN, MESSAGE_PKTLEN_MAX) == true) {
        params->pktlen = (uint32_t)pktlen_arg;
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

// set `group ip` parameter
void program_param_parse_groupip(struct ProgramParams *params)
{
    in_addr_t ip = inet_addr(optarg);
    if (ip != INADDR_NONE && ip >= inet_addr("224.0.0.0") && ip <= inet_addr("239.255.255.255")) {
        params->groupip = optarg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// initialize the parameters
void program_params_init(struct ProgramParams *params)
{
    params->as = PARAM_DEFAULT_AS;
    params->ip = PARAM_DEFAULT_IP;
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

    if (strcmp(params->domain, "tcp") != 0) {
        params->connect_num = 1;
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
            printf("--> [server ip]:                %s \n", params->ip);
            printf("--> [server group ip]:          %s \n", params->groupip);
        } else {
            printf("--> [server ip]:                %s \n", params->groupip);
            printf("--> [client send ip]:           %s \n", params->ip);
        }
    } else {
        printf("--> [server ip]:                %s \n", params->ip);
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
	for (uint32_t i = UNIX_TCP_PORT_MIN; i < sport; i++) {
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
    printf("\n");
}
