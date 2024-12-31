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

static struct sigaction g_register_sigactions[NSIG]; // NSIG is the signal counts of system, normally equal 65 in Linux.
static void lstack_sig_default_handler(int sig);

static bool sig_is_registered(int sig)
{
    if (g_register_sigactions[sig].sa_handler != NULL &&
        g_register_sigactions[sig].sa_handler != (void *) lstack_sig_default_handler) {
        return true;
    }
    return false;
}

static inline bool match_hijack_signal(int sig)
{
    unsigned int i;
    for (i = 0; i < HIJACK_SIGNAL_COUNT; i++) {
        if (sig == g_hijack_signal[i]) {
            return true;
        }
    }
    return false;
}

/* When operations such as pressing Ctrl+C or Kill are executed, we don't need to dump the stack. */
bool sig_need_dump(int sig)
{
    if (sig == SIGINT || sig == SIGTERM || sig == SIGKILL) {
        return false;
    }
    return true;
}

static void lstack_sigaction_default_handler(int sig, siginfo_t *info, void *context)
{
    static bool skip_process_exit = false;

    /* avoiding sig function being executed twice. */
    if (!skip_process_exit) {
        skip_process_exit = true;
    } else {
        return;
    }

    LSTACK_LOG(ERR, LSTACK, "lstack dumped, caught signal: %d\n", sig);

    stack_stop();

    if (sig_need_dump(sig)) {
        /* dump stack info */
        dump_stack();

        /* dump internal information of lstack */
        dump_lstack();
    }

    if (sig_is_registered(sig)) {
        if (g_register_sigactions[sig].sa_flags & SA_SIGINFO) {
            g_register_sigactions[sig].sa_sigaction(sig, info, context);
        } else {
            g_register_sigactions[sig].sa_handler(sig);
        }
    }

    if (get_global_cfg_params() && get_global_cfg_params()->is_primary) {
        delete_primary_path();
    }

    control_fd_close();

    stack_exit();
    lwip_exit();
    gazelle_exit();
    (void)kill(getpid(), sig);
}

static void lstack_sig_default_handler(int sig)
{
    lstack_sigaction_default_handler(sig, NULL, NULL);
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

    if (match_hijack_signal(sig_num) && action != NULL) {
        new_action = *action;

        if (action->sa_handler == SIG_DFL) {
            new_action = *action;
            new_action.sa_flags |= SA_RESETHAND;
            new_action.sa_handler = lstack_sig_default_handler;
            return posix_api->sigaction_fn(sig_num, &new_action, old_action);
        }

        /* SA_INTERRUPT is deprecated, use SA_RESETHAND instead. */
        if (action->sa_flags == SA_INTERRUPT) {
            new_action = *action;
            new_action.sa_flags |= SA_RESETHAND;
            return posix_api->sigaction_fn(sig_num, &new_action, old_action);
        }

        if (sig_need_dump(sig_num)) {
            g_register_sigactions[sig_num] = new_action;

            /* If SA_SIGINFO is setted, we use sa_sigaction. */
            if (action->sa_flags & SA_SIGINFO) {
                new_action.sa_sigaction = lstack_sigaction_default_handler;
            } else {
                new_action.sa_handler = lstack_sig_default_handler;
            }
            return posix_api->sigaction_fn(sig_num, &new_action, old_action);
        }
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
