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

/*
 * main.c
 *
 * Entry point of the program.
 */

#include "param.h"

int main(int argc, char *argv[])
{
    param_t params;

    /* Parse command-line arguments */
    parse_arguments(argc, argv, &params);

    /* Execute functions based on parsed arguments */
    if (params.show_help) {
        debug_help();
        exit(EXIT_SUCCESS);
    }

    if (params.list) {
        list_api();
    }

    if (params.trace_cmd) {
        trace(params.trace_cmd);
    }

    if (params.trace_pid) {
        pid_trace(params.trace_pid);
    }

    if (params.record_cmd || params.record_pid) {
        is_perf_installed();
        if (params.record_cmd) {
            record(params.record_cmd, 0);
        } else if (params.record_pid) {
            record(NULL, params.record_pid);
        }
        run_perf_script();
    }

    if (params.multiplex_cmd) {
        multiplex(params.multiplex_cmd);
    }

    if (params.multiplex_pid) {
        pid_multiplex(params.multiplex_pid);
    }

    return 0;
}

