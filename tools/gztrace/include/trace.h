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
 * trace.h
 *
 * Features included:
 * - Prints the POSIX interfaces supported by Gazelle.
 * - Implements (network-related) system call tracing and parameter parsing using the ptrace library.
 * - Retrieves the IO multiplexing mechanisms supported by the target application.
 */

#ifndef GZTRACE_TRACE_H
#define GZTRACE_TRACE_H

#include <time.h>
#include "syscall.h"

#define API_LIST_MD_PATH "../../../doc/support_en.md"
#define MAX_LINE_LENGTH 1024
#define CMD_INDEX 2  // The index in the argv array where the command string is assigned for execution

/* Lists the supported APIs by reading from a markdown file under a specific title */
void list_api();
/* Handle specific POSIX API calls */
bool handle_specific_syscall(pid_t pid, struct user_regs_struct *regs, long syscall);
/* Generic function to handle system calls */
bool handle_syscall(pid_t pid, struct user_regs_struct *regs, bool *tracing, int *status);
/* Function to handle IO multiplexing system calls */
void handle_multiplex_syscall(long syscall, int *select_detected, int *poll_detected, int *epoll_wait_detected);
/* Traces POSIX API calls of the target executable */
void trace(const char *cmd);

/* Traces POSIX API calls of the target PID */
void pid_trace(pid_t pid);

/* Traces IO multiplexing mechanisms used by the target executable */
void multiplex(const char *cmd);

/* Traces IO multiplexing mechanisms used by the target PID */
void pid_multiplex(pid_t pid);

#endif /* GZTRACE_TRACE_H */
