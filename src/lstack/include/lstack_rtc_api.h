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

#ifndef _LSTACK_RTC_API_H_
#define _LSTACK_RTC_API_H_
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>

/* don't include lwip/sockets.h, conflict with sys/socket.h */
/* extern lwip_api here */
extern int lwip_fcntl(int s, int cmd, int val);
extern int lwip_ioctl(int s, long cmd, ...);
extern int lwip_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
extern int lwip_accept4(int s, struct sockaddr *addr, socklen_t *addrlen, int flags);
extern int lwip_bind(int s, const struct sockaddr *name, socklen_t namelen);
extern int lwip_shutdown(int s, int how);
extern int lwip_getpeername(int s, struct sockaddr *name, socklen_t *namelen);
extern int lwip_getsockname(int s, struct sockaddr *name, socklen_t *namelen);
extern int lwip_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen);
extern int lwip_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen);
extern int lwip_close(int s);
extern int lwip_connect(int s, const struct sockaddr *name, socklen_t namelen);
extern int lwip_listen(int s, int backlog);
extern ssize_t lwip_recv(int s, void *mem, size_t len, int flags);
extern ssize_t lwip_read(int s, void *mem, size_t len);
extern ssize_t lwip_readv(int s, const struct iovec *iov, int iovcnt);
extern ssize_t lwip_recvfrom(int s, void *mem, size_t len, int flags,
                             struct sockaddr *from, socklen_t *fromlen);
extern ssize_t lwip_recvmsg(int s, const struct msghdr *message, int flags);
extern ssize_t lwip_send(int s, const void *dataptr, size_t size, int flags);
extern ssize_t lwip_sendmsg(int s, const struct msghdr *message, int flags);
extern ssize_t lwip_sendto(int s, const void *dataptr, size_t size, int flags,
                           const struct sockaddr *to, socklen_t tolen);
extern int lwip_socket(int domain, int type, int protocol);
extern ssize_t lwip_write(int s, const void *dataptr, size_t size);
extern ssize_t lwip_writev(int s, const struct iovec *iov, int iovcnt);

int rtc_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int rtc_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout);
int rtc_socket(int domain, int type, int protocol);
int rtc_close(int s);
int rtc_epoll_create(int flags);
int rtc_epoll_create1(int flags);
int rtc_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int rtc_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);

#endif /* __LSTACK_RTC_API_H_  */
