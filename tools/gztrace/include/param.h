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
 * param.h
 *
 * Features included:
 * - Parses command-line arguments and stores them in a struct.
 */

#ifndef GZTRACE_PARAM_H
#define GZTRACE_PARAM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h> // For pid_t
#include <string.h>

#include "trace.h"
#include "record.h"

/* Displays the help message */
void debug_help(void);

/* Structure to store parsed command-line arguments */
typedef struct {
    int show_help;
    int list;
    char *record_cmd;
    pid_t record_pid;
} param_t;

/* Parses command-line arguments */
void parse_arguments(int32_t argc, char *argv[], param_t *params);

#endif /* GZTRACE_PARAM_H */

