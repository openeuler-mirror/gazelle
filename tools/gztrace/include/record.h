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
 * record.h
 *
 * Features included:
 * - Records the execution process of target applications or processes.
 * - Ensures that 'perf' is installed and provides functions to run perf scripts.
 * - Retrieves the IO multiplexing mechanisms supported by the target application.
 */

#ifndef GZTRACE_RECORD_H
#define GZTRACE_RECORD_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

/* Records the execution process of the target application or process */
void record(const char *cmd, pid_t pid);

/* Executes the perf script and redirects output to a file */
void run_perf_script();

/* Checks if perf is installed on the system */
void is_perf_installed();

#endif /* GZTRACE_RECORD_H */
