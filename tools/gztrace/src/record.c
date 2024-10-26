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

#include "record.h"

/* Checks if perf is installed by verifying its presence in standard paths */
void is_perf_installed()
{
    /* Check if perf is executable in /usr/bin or /bin */
    if (access("/usr/bin/perf", X_OK) == 0 || access("/bin/perf", X_OK) == 0) {
        return; /* perf is installed */
    }

    /* perf is not installed; print error message and exit */
    int ret = fprintf(stderr, "Error: perf is not installed. Please install perf using:\n");
    if (ret < 0) {
        perror("Error writing to stderr");
        exit(EXIT_FAILURE);
    }

    ret = fprintf(stderr, "sudo dnf install perf\n");
    if (ret < 0) {
        perror("Error writing to stderr");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_FAILURE);
}

/* Executes the perf script and redirects output to out.perf */
void run_perf_script()
{
    /* Define the perf script command with output redirection */
    const char *perf_script_command = "sudo perf script > out.perf";

    /* Execute the command using system */
    int status = system(perf_script_command);
    if (status == -1) {
        perror("system failed");
    } else {
        printf("perf script exited with status: %d\n", WEXITSTATUS(status));
    }
}

/* Records the execution process of the target application or process */
void record(const char *cmd, pid_t pid)
{
    is_perf_installed(); /* Ensure perf is installed */

    char command[1024];

    if (cmd != NULL) {
        /* If a command is provided, record the target application */
        const char *perf_command = "sudo perf record -F 99 -a -g -- ";
        snprintf(command, sizeof(command), "%s%s", perf_command, cmd);
    } else if (pid > 0) {
        /* If a PID is provided, record the target process */
        const char *perf_command = "sudo perf record -F 99 -g -p ";
        snprintf(command, sizeof(command), "%s%d", perf_command, pid);
    } else {
        /* If neither command nor PID is provided, print error and exit */
        fprintf(stderr, "Error: You must provide either a command to execute or a process ID.\n");
        exit(EXIT_FAILURE);
    }

    /* Optional: Print the command being executed for debugging */
    printf("Executing: %s\n", command);
    /* Execute the perf record command */
    int result = system(command);
    /* Check the result of the command execution */
    if (result == -1) {
        perror("Error executing perf record command");
    } else {
        printf("Command executed successfully with exit status: %d\n", WEXITSTATUS(result));
    }
}
