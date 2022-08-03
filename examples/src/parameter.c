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
    "m:"        // model
    "t:"        // thread number
    "c:"        // connect number
    "A:"        // api
    "P:"        // pktlen
    "v"         // verify
    "r"         // ringpmd
    "d"         // debug
    "h"         // help
    ;

// program long options
const struct ProgramOption prog_long_opts[] = \
{
    {PARAM_NAME_AS, REQUIRED_ARGUMETN, NULL, PARAM_NUM_AS},
    {PARAM_NAME_IP, REQUIRED_ARGUMETN, NULL, PARAM_NUM_IP},
    {PARAM_NAME_PORT, REQUIRED_ARGUMETN, NULL, PARAM_NUM_PORT},
    {PARAM_NAME_MODEL, REQUIRED_ARGUMETN, NULL, PARAM_NUM_MODEL},
    {PARAM_NAME_THREAD_NUM, REQUIRED_ARGUMETN, NULL, PARAM_NUM_THREAD_NUM},
    {PARAM_NAME_CONNECT_NUM, REQUIRED_ARGUMETN, NULL, PARAM_NUM_CONNECT_NUM},
    {PARAM_NAME_API, REQUIRED_ARGUMETN, NULL, PARAM_NUM_API},
    {PARAM_NAME_PKTLEN, REQUIRED_ARGUMETN, NULL, PARAM_NUM_PKTLEN},
    {PARAM_NAME_VERIFY, NO_ARGUMENT, NULL, PARAM_NUM_VERIFY},
    {PARAM_NAME_RINGPMD, NO_ARGUMENT, NULL, PARAM_NUM_RINGPMD},
    {PARAM_DEFAULT_DEBUG, NO_ARGUMENT, NULL, PARAM_NUM_DEBUG},
    {PARAM_NAME_HELP, NO_ARGUMENT, NULL, PARAM_NUM_HELP},
};


// get long options
int getopt_long(int argc, char * const argv[], const char *optstring, const struct ProgramOption *long_opts, int *long_idx);


// set `as` parameter
void program_param_prase_as(struct ProgramParams *params)
{
    if (strcmp(optarg, "server") == 0 || strcmp(optarg, "client") == 0) {
        params->as = optarg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `ip` parameter
void program_param_prase_ip(struct ProgramParams *params)
{
    if (inet_addr(optarg) != INADDR_NONE) {
        params->ip = optarg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `port` parameter
void program_param_prase_port(struct ProgramParams *params)
{
    int32_t port_arg = atoi(optarg);
    if (CHECK_VAL_RANGE(port_arg, UNIX_TCP_PORT_MIN, UNIX_TCP_PORT_MAX) == true) {
        params->port = (uint32_t)port_arg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `model` parameter
void program_param_prase_model(struct ProgramParams *params)
{
    if (strcmp(optarg, "mum") == 0 || strcmp(optarg, "mud") == 0) {
        params->model = optarg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `connect_num` parameter
void program_param_prase_connectnum(struct ProgramParams *params)
{
    int32_t connectnum_arg = atoi(optarg);
    if (connectnum_arg > 0) {
        params->connect_num = (uint32_t)connectnum_arg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `thread_num` parameter
void program_param_prase_threadnum(struct ProgramParams *params)
{
    int32_t threadnum_arg = atoi(optarg);
    if (CHECK_VAL_RANGE(threadnum_arg, THREAD_NUM_MIN, THREAD_NUM_MAX) == true) {
        params->thread_num = (uint32_t)threadnum_arg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `api` parameter
void program_param_prase_api(struct ProgramParams *params)
{
    if (strcmp(optarg, "unix") == 0 || strcmp(optarg, "posix") == 0) {
        params->api = optarg;
    } else {
        PRINT_ERROR("illigal argument -- %s \n", optarg);
        exit(PROGRAM_ABORT);
    }
}

// set `pktlen` parameter
void program_param_prase_pktlen(struct ProgramParams *params)
{
    int32_t pktlen_arg = atoi(optarg);
    if (CHECK_VAL_RANGE(pktlen_arg, MESSAGE_PKTLEN_MIN, MESSAGE_PKTLEN_MAX) == true) {
        params->pktlen = (uint32_t)pktlen_arg;
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
    params->port = PARAM_DEFAULT_PORT;
    params->model = PARAM_DEFAULT_MODEL;
    params->thread_num = PARAM_DEFAULT_THREAD_NUM;
    params->connect_num = PARAM_DEFAULT_CONNECT_NUM;
    params->api = PARAM_DEFAULT_API;
    params->pktlen = PARAM_DEFAULT_PKTLEN;
    params->verify = PARAM_DEFAULT_VERIFY;
    params->ringpmd = PARAM_DEFAULT_RINGPMD;
}

// print program helps
void program_params_help(void)
{
    printf("\n");
    printf("-a, --as [server | client]: set programas server or client. \n");
    printf("    server: as server. \n");
    printf("    client: as client. \n");
    printf("-i, --ip [xxx.xxx.xxx.xxx]: set ip address. \n");
    printf("-p, --port [xxxx]: set port number in range of %d - %d. \n", UNIX_TCP_PORT_MIN, UNIX_TCP_PORT_MAX);
    printf("-m, --model [mum | mud]: set the network model. \n");
    printf("    mum: multi thread, unblock, multiplexing IO network model. \n");
    printf("    mud: multi thread, unblock, dissymmetric network model. \n");
    printf("-t, --threadnum [xxxx]: set thread number in range of %d - %d. \n", THREAD_NUM_MIN, THREAD_NUM_MAX);
    printf("-c, --connectnum [xxxx]: set thread number of connection. \n");
    printf("-A, --api [unix | posix]: set api type is server or client. \n");
    printf("    unix: use unix's api. \n");
    printf("    posix: use posix api. \n");
    printf("-P, --pktlen [xxxx]: set packet length in range of %d - %d. \n", MESSAGE_PKTLEN_MIN, MESSAGE_PKTLEN_MAX);
    printf("-v, --verify: set to verifying the message packet. \n");
    printf("-r, --ringpmd: set to use ringpmd. \n");
    printf("-d, --debug: set to print the debug information. \n");
    printf("-h, --help: see helps. \n");
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
                program_param_prase_as(params);
                break;
            case (PARAM_NUM_IP):
                program_param_prase_ip(params);
                break;
            case (PARAM_NUM_PORT):
                program_param_prase_port(params);
                break;
            case (PARAM_NUM_MODEL):
                program_param_prase_model(params);
                break;
            case (PARAM_NUM_CONNECT_NUM):
                program_param_prase_connectnum(params);
                break;
            case (PARAM_NUM_THREAD_NUM):
                program_param_prase_threadnum(params);
                break;
            case (PARAM_NUM_API):
                program_param_prase_api(params);
                break;
            case (PARAM_NUM_PKTLEN):
                program_param_prase_pktlen(params);
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
    printf("--> [ip]:                       %s \n", params->ip);
    printf("--> [port]:                     %u \n", params->port);
    printf("--> [model]:                    %s \n", params->model);
    printf("--> [thread number]:            %u \n", params->thread_num);
    printf("--> [connection number]:        %u \n", params->connect_num);
    printf("--> [api]:                      %s \n", params->api);
    printf("--> [packet length]:            %u \n", params->pktlen);
    printf("--> [verify]:                   %s \n", (params->verify == true) ? "on" : "off");
    printf("--> [ringpmd]:                  %s \n", (params->ringpmd == true) ? "on" : "off");
    printf("--> [debug]:                    %s \n", (params->debug == true) ? "on" : "off");
    printf("\n");
}
