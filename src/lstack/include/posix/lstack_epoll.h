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

#ifdef __cplusplus
extern "C" {
#endif

int32_t lstack_epoll_create(int32_t size);
int32_t lstack_epoll_ctl(int32_t epfd, int32_t op, int32_t fd, struct epoll_event *event);
int32_t lstack_epoll_wait(int32_t epfd, struct epoll_event *events, int32_t maxevents, int32_t timeout);
int32_t lstack_poll(struct pollfd *fds, nfds_t nfds, int32_t timeout);

#ifdef __cplusplus
}
#endif

#endif /* _GAZELLE_EPOLL_H_ */
