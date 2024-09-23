/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Huawei Technologies
 *
 */

#ifndef __LWIPGZ_POSIX_API_H__
#define __LWIPGZ_POSIX_API_H__

// #include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

typedef struct {
    void *handle;
    int use_kernel;

    /* API */
    int (*shutdown_fn)(int fd, int how);
    int (*close_fn)(int fd);

    int (*socket_fn)(int domain, int type, int protocol);
    int (*connect_fn)(int fd, const struct sockaddr *name, socklen_t namelen);
    int (*bind_fn)(int fd, const struct sockaddr*, socklen_t);
    int (*listen_fn)(int fd, int backlog);
    int (*accept_fn)(int fd, struct sockaddr*, socklen_t*);
    int (*accept4_fn)(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags);

    int (*getpeername_fn)(int fd, struct sockaddr *name, socklen_t *namelen);
    int (*getsockname_fn)(int fd, struct sockaddr *name, socklen_t *namelen);
    int (*getsockopt_fn)(int fd, int level, int optname, void *optval, socklen_t *optlen);
    int (*setsockopt_fn)(int fd, int level, int optname, const void *optval, socklen_t optlen);

    ssize_t (*read_fn)(int fd, void *mem, size_t len);
    ssize_t (*write_fn)(int fd, const void *data, size_t len);
    ssize_t (*readv_fn)(int fd, const struct iovec *iov, int iovcnt);
    ssize_t (*writev_fn)(int fd, const struct iovec *iov, int iovcnt);
    ssize_t (*recv_fn)(int fd, void *buf, size_t len, int flags);
    ssize_t (*send_fn)(int fd, const void *buf, size_t len, int flags);
    ssize_t (*recvmsg_fn)(int fd, const struct msghdr *msg, int flags);
    ssize_t (*sendmsg_fn)(int fd, const struct msghdr *msg, int flags);
    ssize_t (*recvfrom_fn)(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
    ssize_t (*sendto_fn)(int fd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

    int (*select_fn)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
    int (*poll_fn)(struct pollfd *fds, nfds_t nfds, int timeout);
    int (*epoll_create_fn)(int size);
    int (*epoll_create1_fn)(int size);
    int (*epoll_ctl_fn)(int epfd, int op, int fd, struct epoll_event *event);
    int (*epoll_wait_fn)(int epfd, struct epoll_event *events, int maxevents, int timeout);
    int (*epoll_close_fn)(int epfd);
    int (*eventfd_fn)(unsigned int initval, int flags);

    int (*ioctl_fn)(int fd, int cmd, ...);
    int (*fcntl_fn)(int fd, int cmd, ...);
    int (*fcntl64_fn)(int fd, int cmd, ...);

    int (*sigaction_fn)(int signum, const struct sigaction *act, struct sigaction *oldact);
    pid_t (*fork_fn)(void);
} posix_api_t;

extern posix_api_t *posix_api;
int posix_api_init(void);

#endif /* __LWIPGZ_POSIX_API_H__ */
