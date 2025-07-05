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

#ifndef _GAZELLE_UNISTD_H_
#define _GAZELLE_UNISTD_H_

#include <unistd.h>
#include <signal.h>

void pthread_block_sig(int sig);
void pthread_unblock_sig(int sig);

int lstack_signal_init(void);
int lstack_sigaction(int sig_num, const struct sigaction *action, struct sigaction *old_action);
pid_t lstack_fork(void);

#endif /* _GAZELLE_UNISTD_H_ */
