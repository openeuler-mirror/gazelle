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

#ifndef _GAZELLE_EPOLL_H_
#define _GAZELLE_EPOLL_H_

#include <lwip/lwipgz_posix_api.h>
#include <lwip/lwipgz_sock.h>

#include "lstack_wait.h"

struct sock_wait *poll_construct_wait(int nfds);
void poll_destruct_wait(void);

int lstack_epoll_close(int epfd);
void epoll_api_init(posix_api_t *api);
int epoll_ctl_kernel_event(int epfd, int op, int fd, struct epoll_event *event, 
    struct sock_wait *sk_wait);
int poll_ctl_kernel_event(int epfd, int fds_id, int old_fd, const struct pollfd *new_fds);

bool sock_event_wait(struct lwip_sock *sock, enum netconn_evt evt, bool noblocking);

#endif /* _GAZELLE_EPOLL_H_ */
