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

#ifndef LIBOS_UNISTD_H
#define LIBOS_UNISTD_H

#include "lstack_fork.h"
#ifdef __cplusplus
extern "C" {
#endif

int lstack_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);

#ifdef __cplusplus
}
#endif

#endif /* LIBOS_UNISTD_H */
