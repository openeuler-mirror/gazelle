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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

void signal_handler(int signo)
{
    exit(signo);
}

__attribute__((constructor)) void signal_reg(void)
{
    int sigs[] = {
        SIGILL, SIGFPE, SIGABRT, SIGBUS,
        SIGSEGV, SIGHUP, SIGINT, SIGQUIT,
        SIGTERM
    };
    int i;
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        if (sigaction(sigs[i], &sa, NULL) == -1) {
            perror("Could not set signal handler");
        }
    }
}
