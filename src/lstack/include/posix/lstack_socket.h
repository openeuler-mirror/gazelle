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

#ifndef _GAZELLE_SOCKET_H_
#define _GAZELLE_SOCKET_H_

#ifdef __cplusplus
extern "C" {
#endif

int lwip_socket(int domain, int type, int protocol);
int lwip_bind(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_connect(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_listen(int s, int backlog);
int lwip_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int lwip_close(int s);
int lwip_getpeername(int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockname(int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen);
int lwip_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen);

ssize_t lwip_write(int s, const void *dataptr, size_t size);
ssize_t lwip_send(int s, const void *data, size_t size, int flags);
ssize_t lwip_recvmsg(int s, struct msghdr *message, int flags);
ssize_t lwip_sendmsg(int s, const struct msghdr *message, int flags);
ssize_t lwip_read(int s, void *mem, size_t len);
ssize_t lwip_recvfrom(int s, void *mem, size_t len, int flags, void *from, void *fromlen);
ssize_t lwip_recv(int s, void *mem, size_t len, int flags);

int lwip_fcntl(int s, int cmd, int val);
int lwip_ioctl(int s, int cmd, ...);

#ifdef __cplusplus
}
#endif

#endif /* _GAZELLE_SOCKET_H_ */
