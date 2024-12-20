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
#include <sys/socket.h>

#include <lwip/lwipgz_sock.h>
#include <lwip/lwipgz_posix_api.h>

#include "lstack_unistd.h"
#include "common/gazelle_base_func.h"
#include "lstack_log.h"
#include "lstack_cfg.h"
#include "lstack_control_plane.h"
#include "lstack_dump.h"

static int g_hijack_signal[] = { SIGTERM, SIGINT, SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGKILL};
#define HIJACK_SIGNAL_COUNT (sizeof(g_hijack_signal) / sizeof(g_hijack_signal[0]))

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
    LSTACK_LOG(ERR, LSTACK, "lstack dumped, caught signal: %d\n", sig);

    /* When operations such as pressing Ctrl+C or Kill, the call stack exit is not displayed. */
    if (sig != SIGINT && sig != SIGTERM && sig != SIGKILL) {
        /* dump stack info */
        dump_stack();

        /* dump internal information of lstack */
        dump_lstack();
    }

    if (get_global_cfg_params() && get_global_cfg_params()->is_primary) {
        delete_primary_path();
    }

    control_fd_close();

    lwip_exit();
    gazelle_exit();
    (void)kill(getpid(), sig);
}

static void pthread_block_sig(int sig)
{
    sigset_t mask;

    sigemptyset(&mask);
    sigaddset(&mask, sig);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);
}

static void pthread_unblock_sig(int sig)
{
    sigset_t mask;

    sigemptyset(&mask);
    sigaddset(&mask, sig);
    pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
}

int lstack_signal_init(void)
{
    unsigned int i;
    struct sigaction action;

    /* to prevent crash, just ignore SIGPIPE when socket is closed */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        return -1;
    }
    pthread_block_sig(SIGUSR1);
    pthread_block_sig(SIGUSR2);

    sigemptyset(&action.sa_mask);
    action.sa_flags = (int)(SA_NODEFER | SA_RESETHAND);
    action.sa_handler = lstack_sig_default_handler;
    for (i = 0; i < HIJACK_SIGNAL_COUNT; i++) {
        posix_api->sigaction_fn(g_hijack_signal[i], &action, NULL);
    }

    return 0;
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

    /* SA_INTERRUPT is deprecated, use SA_RESETHAND instead. */
    if ((match_hijack_signal(sig_num) != 0) && (action && action->sa_flags == SA_INTERRUPT)) {
        new_action = *action;
        new_action.sa_flags |= SA_RESETHAND;
        return posix_api->sigaction_fn(sig_num, &new_action, old_action);
    }

    return posix_api->sigaction_fn(sig_num, action, old_action);
}

pid_t lstack_fork(void)
{
    pid_t pid;

    pid = posix_api->fork_fn();
    /* child not support lwip */
    if (pid == 0) {
        pthread_unblock_sig(SIGUSR1);
        pthread_unblock_sig(SIGUSR2);
        posix_api->use_kernel = 1;
    }
    return pid;
}
