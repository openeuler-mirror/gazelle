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

#ifndef _LSTACK_RTW_API_H_
#define _LSTACK_RTW_API_H_

#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>

int rtw_socket(int domain, int type, int protocol);
int rtw_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int rtw_accept4(int s, struct sockaddr *addr, socklen_t *addrlen, int flags);
int rtw_bind(int s, const struct sockaddr *name, socklen_t namelen);
int rtw_listen(int s, int backlog);
int rtw_connect(int s, const struct sockaddr *name, socklen_t namelen);
int rtw_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen);
int rtw_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen);
int rtw_getpeername(int s, struct sockaddr *name, socklen_t *namelen);
int rtw_getsockname(int s, struct sockaddr *name, socklen_t *namelen);
ssize_t rtw_read(int s, void *mem, size_t len);
ssize_t rtw_readv(int s, const struct iovec *iov, int iovcnt);
ssize_t rtw_write(int s, const void *mem, size_t size);
ssize_t rtw_writev(int s, const struct iovec *iov, int iovcnt);
ssize_t rtw_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t rtw_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t rtw_recvmsg(int s, const struct msghdr *message, int flags);
ssize_t rtw_sendmsg(int s, const struct msghdr *message, int flags);
ssize_t rtw_recvfrom(int sockfd, void *buf, size_t len, int flags,
                     struct sockaddr *addr, socklen_t *addrlen);
ssize_t rtw_sendto(int sockfd, const void *buf, size_t len, int flags,
                   const struct sockaddr *addr, socklen_t addrlen);
int rtw_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout);
int rtw_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int rtw_close(int s);
int rtw_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int rtw_epoll_create1(int flags);
int rtw_epoll_create(int flags);
int rtw_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);

#endif /* _LSTACK_RTW_API_H_ */
