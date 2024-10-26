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


#include "param.h"

/* Display the help message */
void debug_help(void)
{
    printf("Usage: %s [options]\n", "gztrace");
    printf("Options:\n");
    printf("  -h, --help                 : Show this help message\n");
    printf("  -l, --list                 : List POSIX APIs that Gazelle supports\n");
    printf("  -t, --trace <cmd>          : Trace executable's (network) POSIX API\n");
    printf("      --pid_trace <pid>      : Trace a specific PID's (network) POSIX API\n");
    printf("  -r, --record <cmd>         :"
           " Capture and record executable's call stack information for performance analysis\n");
    printf("      --pid_record <pid>     : "
           "Capture and record a PID's call stack information for performance analysis\n");
    printf("  -m, --multiplex <cmd>      : Monitor IO multiplexing mechanisms in the target application\n");
    printf("      --pid_multiplex <pid>  : Monitor IO multiplexing mechanisms in the target PID\n");
}

/* Parse command-line arguments */
void parse_arguments(int32_t argc, char *argv[], param_t *params)
{
    // Initialize params to zero
    memset(params, 0, sizeof(param_t));

    int32_t opt;
    int32_t option_index = 0;
    static struct option long_options[] = {
        {"help",           no_argument,       0, 'h'},
        {"list",           no_argument,       0, 'l'},
        {"trace",          required_argument, 0, 't'},
        {"pid_trace",      required_argument, 0,  0 },
        {"record",         required_argument, 0, 'r'},
        {"pid_record",     required_argument, 0,  0 },
        {"multiplex",      required_argument, 0, 'm'},
        {"pid_multiplex",  required_argument, 0,  0 },
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "hlt:r:m:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h': {
                params->show_help = 1;
                break;
            }case 'l': {
                params->list = 1;
                break;
            }case 't': {
                params->trace_cmd = optarg;
                break;
            }case 0: {
                if (strcmp("pid_trace", long_options[option_index].name) == 0) {
                    params->trace_pid = atoi(optarg);
                } else if (strcmp("pid_record", long_options[option_index].name) == 0) {
                    params->record_pid = atoi(optarg);
                } else if (strcmp("pid_multiplex", long_options[option_index].name) == 0) {
                    params->multiplex_pid = atoi(optarg);
                }
                break;
            }case 'r': {
                params->record_cmd = optarg;
                break;
            }case 'm': {
                params->multiplex_cmd = optarg;
                break;
            }default: {
                debug_help();
                exit(EXIT_FAILURE);
            }
        }
    }
}
