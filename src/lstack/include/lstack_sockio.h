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

ssize_t sockio_recvfrom(int fd, void *mem, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
ssize_t sockio_recvmsg(int fd, struct msghdr *msg, int flags);
ssize_t sockio_sendto(int fd, const void *mem, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);
ssize_t sockio_sendmsg(int fd, const struct msghdr *msg, int flags);

ssize_t sockio_read(int fd, void *mem, size_t len);
ssize_t sockio_write(int fd, const void *mem, size_t len);

ssize_t sockio_recv(int fd, void *mem, size_t len, int flags);
ssize_t sockio_send(int fd, const void *mem, size_t len, int flags);

ssize_t sockio_readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t sockio_writev(int fd, const struct iovec *iov, int iovcnt);


void sockio_ops_init(void);
bool sockio_mbox_pending(struct lwip_sock *sock);

/* just for lwip */
int do_lwip_init_sock(int fd);
void do_lwip_clean_sock(int fd);

#endif /* _LSTACK_SOCKIO_H_ */
