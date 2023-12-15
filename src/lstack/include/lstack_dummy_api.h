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

#ifndef _LSTACK_DUMMY_API_H_
#define _LSTACK_DUMMY_API_H_

int dummy_socket(int domain, int type, int protocol);
ssize_t dummy_write(int s, const void *mem, size_t size);
ssize_t dummy_writev(int s, const struct iovec *iov, int iovcnt);
ssize_t dummy_sendmsg(int s, const struct msghdr *message, int flags);
ssize_t dummy_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t dummy_sendto(int sockfd, const void *buf, size_t len, int flags,
                     const struct sockaddr *addr, socklen_t addrlen);
#endif /* __LSTACK_DUMMY_API_H_  */
