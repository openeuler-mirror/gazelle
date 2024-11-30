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

#include <fcntl.h>
#include <sys/time.h>
#include <execinfo.h>

#include "lstack_cfg.h"
#include "lstack_log.h"

#define DUMP_COMMAND_TIMEOUT_MS 2000
#define DUMP_COMMAND_INTERVAL_MS 1
#define DUMP_BUF_SZ 1024
#define DUMP_BACKTRACE_SIZE 64

static const char *dump_command[] = {
    "gazellectl lstack show 1",
    "gazellectl lstack show 1 -s",
    "gazellectl lstack show 1 -x",
    "gazellectl lstack show 1 -p UDP",
    "gazellectl lstack show 1 -p TCP",
    "gazellectl lstack show 1 -p ICMP",
    "gazellectl lstack show 1 -p IP",
    "gazellectl lstack show 1 -p ETHARP",
    "gazellectl lstack show 1 -c"
};

static int dump_lstack_check(void)
{
    /* In ltran mode, dump commands maybe illegal */
    if (use_ltran()) {
        LSTACK_LOG(ERR, LSTACK, "ltran mode doesn't support lstack info dump.\n");
        return -1;
    }

    LSTACK_LOG(INFO, LSTACK, "Dump lstack check passed. Dumping information:\n");
    return 0;
}

#define US_PER_MS (MS_PER_S)
static long timeval_diff_ms(struct timeval *end, struct timeval *begin)
{
    struct timeval result;
    long result_ms;

    result.tv_sec = end->tv_sec - begin->tv_sec;
    result.tv_usec = end->tv_usec - begin->tv_usec;

    result_ms = result.tv_sec * MS_PER_S + result.tv_usec / US_PER_MS;
    return result_ms;
}

static int dump_command_excute(const char *command)
{
    FILE *fp;
    int flags, fd;
    char buffer[DUMP_BUF_SZ];
    struct timeval start, now;
    long elapsed;

    if ((fp = popen(command, "r")) == NULL) {
        LSTACK_LOG(ERR, LSTACK, "popen() failed, command \"%s\" didn't excute.\n", command);
        return -1;
    }

    fd = fileno(fp);
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    gettimeofday(&start, NULL);

    /* Loop to print command output while checking for timeout. */
    while (1) {
        gettimeofday(&now, NULL);
        elapsed = timeval_diff_ms(&now, &start);

        /* check timeout */
        if (elapsed > DUMP_COMMAND_TIMEOUT_MS) {
            LSTACK_LOG(ERR, LSTACK, "Command timeout: %s\n", command);
            pclose(fp);
            return -1;
        }

        /* get and print command output */
        if (fgets(buffer, sizeof(buffer), fp) != NULL) {
            LSTACK_LOG(INFO, LSTACK, "\r        %s", buffer);
        } else if (feof(fp)) {
            break;
        } else {
            usleep(DUMP_COMMAND_INTERVAL_MS * US_PER_MS); // 1ms
        }
    }

    pclose(fp);
    return 0;
}

void dump_lstack(void)
{
    int ret, command_count;

    ret = dump_lstack_check();
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "lstack dump check failed, dump process exited!\n");
        return;
    }

    command_count = sizeof(dump_command) / sizeof(dump_command[0]);
    for (int i = 0; i < command_count; ++i) {
        LSTACK_LOG(INFO, LSTACK, "Dump command: \"%s\"\n", dump_command[i]);

        ret = dump_command_excute(dump_command[i]);
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "Dump command: \"%s\" excute failed.\n", dump_command[i]);
        }
    }
}

void dump_stack(void)
{
    char **stack_trace = NULL;
    void *stack_array[DUMP_BACKTRACE_SIZE];
    int stack_num = backtrace(stack_array, DUMP_BACKTRACE_SIZE);

    stack_trace = (char**)backtrace_symbols(stack_array, stack_num);
    if (stack_trace == NULL) {
        LSTACK_LOG(ERR, LSTACK, "Error in backtrace_symbols, errno %d\n", errno);
        return;
    }

    for (int i = 0; i < stack_num; i++) {
        LSTACK_LOG(ERR, LSTACK, "%s\n", stack_trace[i]);
    }
    free(stack_trace);
}
