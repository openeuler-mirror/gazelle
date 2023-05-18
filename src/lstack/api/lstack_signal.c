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

#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <execinfo.h>
#include <unistd.h>
#include <lwip/lwipsock.h>
#include <lwip/posix_api.h>

#include "lstack_cfg.h"
#include "common/dpdk_common.h"
#include "lstack_log.h"
#include "lstack_control_plane.h"

static int g_hijack_signal[] = { SIGTERM, SIGINT, SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGKILL};
#define HIJACK_SIGNAL_COUNT (sizeof(g_hijack_signal) / sizeof(g_hijack_signal[0]))
#define BACKTRACE_SIZE 64
static void dump_stack(void)
{
    char **stack_trace = NULL;
    void *stack_array[BACKTRACE_SIZE];
    int stack_num = backtrace(stack_array, BACKTRACE_SIZE);

    stack_trace = (char**)backtrace_symbols(stack_array, stack_num);
    if (stack_trace == NULL) {
        perror("backtrace_symbols");
        return;
    }

    for (int i = 0; i < stack_num; i++) {
        LSTACK_LOG(ERR, LSTACK, "%s\n", stack_trace[i]);
    }
    free(stack_trace);
}
static inline bool match_hijack_signal(int sig)
{
    unsigned int i;
    for (i = 0; i < HIJACK_SIGNAL_COUNT; i++) {
        if (sig == g_hijack_signal[i]) {
            return 1;
        }
    }
    return 0;
}

static void lstack_sig_default_handler(int sig)
{
    LSTACK_LOG(ERR, LSTACK, "lstack dumped，caught signal：%d\n", sig);
    if (get_global_cfg_params() && get_global_cfg_params()->is_primary) {
        delete_primary_path();
    }
    if (!use_ltran()) {
        dpdk_kni_release();
    }
    control_fd_close();
    dump_stack();
    lwip_exit();
    (void)kill(getpid(), sig);
}

void lstack_signal_init(void)
{
    unsigned int i;
    struct sigaction action;

    sigemptyset(&action.sa_mask);
    action.sa_flags = (int)(SA_NODEFER | SA_RESETHAND);
    action.sa_handler = lstack_sig_default_handler;
    for (i = 0; i < HIJACK_SIGNAL_COUNT; i++) {
        posix_api->sigaction_fn(g_hijack_signal[i], &action, NULL);
    }
}

int lstack_sigaction(int sig_num, const struct sigaction *action, struct sigaction *old_action)
{
    struct sigaction new_action;

    if ((match_hijack_signal(sig_num) != 0) && (action && action->sa_handler == SIG_DFL)) {
        new_action = *action;
        new_action.sa_flags |= SA_RESETHAND;
        new_action.sa_handler = lstack_sig_default_handler;
        return posix_api->sigaction_fn(sig_num, &new_action, old_action);
    }
    return posix_api->sigaction_fn(sig_num, action, old_action);
}
