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

#ifndef _LSTACK_SOCKIO_H_
#define _LSTACK_SOCKIO_H_

#include <lwip/lwipgz_posix_api.h>
#include <lwip/lwipgz_sock.h>

void sockio_api_init(posix_api_t *api);
bool sockio_mbox_pending(struct lwip_sock *sock);

/* just for lwip */
int do_lwip_init_sock(int fd);
void do_lwip_clean_sock(int fd);

#endif /* _LSTACK_SOCKIO_H_ */
