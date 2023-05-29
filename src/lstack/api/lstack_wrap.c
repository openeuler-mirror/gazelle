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

#include <dlfcn.h>
#include <string.h>

#include <signal.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <net/if.h>
#include <securec.h>

#include <lwip/gazelle_posix_api.h>
#include <lwip/lwipsock.h>
#include <lwip/tcp.h>

#include "posix/lstack_epoll.h"
#include "posix/lstack_unistd.h"
#include "posix/lstack_socket.h"
#include "lstack_log.h"
#include "lstack_cfg.h"
#include "lstack_lwip.h"
#include "lstack_protocol_stack.h"
#include "common/gazelle_base_func.h"
#include "lstack_thread_rpc.h"

#ifndef SOCK_TYPE_MASK
#define SOCK_TYPE_MASK 0xf
#endif

enum KERNEL_LWIP_PATH {
    PATH_KERNEL = 0,
    PATH_LWIP,
    PATH_UNKNOW,
};

static inline enum KERNEL_LWIP_PATH select_path(int fd, struct lwip_sock **socket)
{
    if (unlikely(posix_api == NULL)) {
        /*
	 * posix api maybe call before gazelle init
	 * So, we must call posix_api_init at the head of select_path
	 */
        if (posix_api_init() != 0) {
            LSTACK_PRE_LOG(LSTACK_ERR, "posix_api_init failed\n");
        }
        return PATH_KERNEL;
    }

    if (unlikely(posix_api->use_kernel)) {
        return PATH_KERNEL;
    }

    struct lwip_sock *sock = lwip_get_socket_nouse(fd);

    /* AF_UNIX case */
    if (!sock || !sock->conn || POSIX_IS_TYPE(sock, POSIX_KERNEL)) {
        return PATH_KERNEL;
    }

    if (likely(POSIX_IS_TYPE(sock, POSIX_LWIP))) {
        if (socket) {
            *socket = sock;
        }
        return PATH_LWIP;
    }

    if (NETCONN_IS_UDP(sock)) {
        if (socket) {
            *socket = sock;
        }
        return PATH_LWIP;
    } else {
        struct tcp_pcb *pcb = sock->conn->pcb.tcp;
        /* after lwip connect, call send immediately, pcb->state is SYN_SENT, need return PATH_LWIP */
        /* pcb->state default value is CLOSED when call socket, need return PATH_UNKNOW */
        if (pcb != NULL && pcb->state <= ESTABLISHED && pcb->state >= LISTEN) {
            if (socket) {
                *socket = sock;
            }
            return PATH_LWIP;
        }
    }

    return PATH_UNKNOW;
}

static inline int32_t do_epoll_create1(int32_t flags)
{
    if (posix_api == NULL) {
        /* posix api maybe call before gazelle init */
        if (posix_api_init() != 0) {
            LSTACK_PRE_LOG(LSTACK_ERR, "posix_api_init failed\n");
        }
        return posix_api->epoll_create1_fn(flags);
    }

    if (unlikely(posix_api->use_kernel)) {
        return posix_api->epoll_create1_fn(flags);
    }

    return lstack_epoll_create1(flags);
}

static inline int32_t do_epoll_create(int32_t size)
{
    if (posix_api == NULL) {
        /* posix api maybe call before gazelle init */
        if (posix_api_init() != 0) {
            LSTACK_PRE_LOG(LSTACK_ERR, "posix_api_init failed\n");
        }
        return posix_api->epoll_create_fn(size);
    }

    if (unlikely(posix_api->use_kernel)) {
        return posix_api->epoll_create_fn(size);
    }

    return lstack_epoll_create(size);
}

static inline int32_t do_epoll_ctl(int32_t epfd, int32_t op, int32_t fd, struct epoll_event* event)
{
    if (unlikely(posix_api->use_kernel)) {
        return posix_api->epoll_ctl_fn(epfd, op, fd, event);
    }

    return lstack_epoll_ctl(epfd, op, fd, event);
}

static inline int32_t do_epoll_wait(int32_t epfd, struct epoll_event* events, int32_t maxevents, int32_t timeout)
{
    if (unlikely(posix_api->use_kernel)) {
        return posix_api->epoll_wait_fn(epfd, events, maxevents, timeout);
    }

    if (epfd < 0) {
        GAZELLE_RETURN(EBADF);
    }

    if ((events == NULL) || (timeout < -1) || (maxevents <= 0)) {
        GAZELLE_RETURN(EINVAL);
    }

    return lstack_epoll_wait(epfd, events, maxevents, timeout);
}

static inline int32_t do_accept(int32_t s, struct sockaddr *addr, socklen_t *addrlen)
{
    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) == PATH_KERNEL) {
        return posix_api->accept_fn(s, addr, addrlen);
    }

    int32_t fd = stack_broadcast_accept(s, addr, addrlen);
    if (fd >= 0) {
        return fd;
    }

    return posix_api->accept_fn(s, addr, addrlen);
}

static int32_t do_accept4(int32_t s, struct sockaddr *addr, socklen_t *addrlen, int32_t flags)
{
    if (addr == NULL || addrlen == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) == PATH_KERNEL) {
        return posix_api->accept4_fn(s, addr, addrlen, flags);
    }

    int32_t fd = stack_broadcast_accept4(s, addr, addrlen, flags);
    if (fd >= 0) {
        return fd;
    }

    return posix_api->accept4_fn(s, addr, addrlen, flags);
}

#define SIOCGIFADDR        0x8915
static int get_addr(struct sockaddr_in *sin, char *interface)
{
    int sockfd = 0;
    struct ifreq ifr;

    if ((sockfd = posix_api->socket_fn(AF_INET, SOCK_STREAM, 0)) < 0) return -1;

    memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr));
    snprintf_s(ifr.ifr_name, sizeof(ifr.ifr_name), (sizeof(ifr.ifr_name) - 1), "%s", interface);

    if (posix_api->ioctl_fn(sockfd, SIOCGIFADDR, &ifr) < 0) {
        posix_api->close_fn(sockfd);
        return -1;
    }
    posix_api->close_fn(sockfd);

    memcpy_s(sin, sizeof(struct sockaddr_in), &ifr.ifr_addr, sizeof(struct sockaddr_in));

    return 0;
}

static int32_t do_bind(int32_t s, const struct sockaddr *name, socklen_t namelen)
{
    if (name == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) == PATH_KERNEL) {
        return posix_api->bind_fn(s, name, namelen);
    }

    int32_t ret = posix_api->bind_fn(s, name, namelen);
    if (ret < 0) {
        /* ip is not lstack, just return */
        if (!match_host_addr(((struct sockaddr_in *)name)->sin_addr.s_addr)) {
            return ret;
        }
    }

    return rpc_call_bind(s, name, namelen);
}

bool is_dst_ip_localhost(const struct sockaddr *addr)
{
    struct sockaddr_in *servaddr = (struct sockaddr_in *) addr;
    FILE *ifh = fopen("/proc/net/dev", "r");
    char *line = NULL;
    char *p;
    size_t linel = 0;
    int linenum = 0;
    struct sockaddr_in* sin = malloc(sizeof(struct sockaddr_in));

    while (getdelim(&line, &linel, '\n', ifh) > 0) {
        /* 2: skip the first two lines, which are not nic name */
        if (linenum++ < 2) {
            continue;
        }

        p = line;
        while (isspace(*p)) {
            ++p;
        }
        int n = strcspn(p, ": \t");

        char interface[20] = {0}; /* 20: nic name len */
        strncpy_s(interface, sizeof(interface), p, n);

        memset_s(sin, sizeof(struct sockaddr_in), 0, sizeof(struct sockaddr_in));
        int ret = get_addr(sin, interface);
        if (ret == 0) {
            if (sin->sin_addr.s_addr == servaddr->sin_addr.s_addr) {
                return 1;
            }
        }
    }
    free(sin);

    return 0;
}

static int32_t do_connect(int32_t s, const struct sockaddr *name, socklen_t namelen)
{
    if (name == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) == PATH_KERNEL) {
        return posix_api->connect_fn(s, name, namelen);
    }

    sock = lwip_get_socket_nouse(s);
    if (sock == NULL) {
        return posix_api->connect_fn(s, name, namelen);
    }

    if (!netconn_is_nonblocking(sock->conn)) {
        GAZELLE_RETURN(EINVAL);
    }

    int32_t ret = 0;
    char listen_ring_name[RING_NAME_LEN];
    int remote_port = htons(((struct sockaddr_in *)name)->sin_port);
    snprintf_s(listen_ring_name, sizeof(listen_ring_name), sizeof(listen_ring_name) - 1,
        "listen_rx_ring_%d", remote_port);
    if (is_dst_ip_localhost(name) && rte_ring_lookup(listen_ring_name) == NULL) {
        ret = posix_api->connect_fn(s, name, namelen);
        POSIX_SET_TYPE(sock, POSIX_KERNEL);
    } else {
        ret = rpc_call_connect(s, name, namelen);
        POSIX_SET_TYPE(sock, POSIX_LWIP);
    }

    return ret;
}

static inline int32_t do_listen(int32_t s, int32_t backlog)
{
    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) == PATH_KERNEL) {
        return posix_api->listen_fn(s, backlog);
    }

    int32_t ret;
    if (!get_global_cfg_params()->tuple_filter &&
        !get_global_cfg_params()->listen_shadow) {
        ret = stack_single_listen(s, backlog);
    } else {
        ret = stack_broadcast_listen(s, backlog);
    }
    if (ret != 0) {
        return ret;
    }

    return posix_api->listen_fn(s, backlog);
}

static inline int32_t do_getpeername(int32_t s, struct sockaddr *name, socklen_t *namelen)
{
    if (name == NULL || namelen == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) == PATH_LWIP) {
        return rpc_call_getpeername(s, name, namelen);
    }

    return posix_api->getpeername_fn(s, name, namelen);
}

static inline int32_t do_getsockname(int32_t s, struct sockaddr *name, socklen_t *namelen)
{
    if (name == NULL || namelen == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) == PATH_LWIP) {
        return rpc_call_getsockname(s, name, namelen);
    }

    return posix_api->getsockname_fn(s, name, namelen);
}

static bool unsupport_optname(int32_t optname)
{
    if (optname == SO_BROADCAST ||
        optname == SO_PROTOCOL  ||
        optname == TCP_QUICKACK ||
        optname == SO_SNDTIMEO  ||
        optname == SO_RCVTIMEO) {
        return true;
    }
    return false;
}

static inline int32_t do_getsockopt(int32_t s, int32_t level, int32_t optname, void *optval, socklen_t *optlen)
{
    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) == PATH_LWIP && !unsupport_optname(optname)) {
        return rpc_call_getsockopt(s, level, optname, optval, optlen);
    }

    return posix_api->getsockopt_fn(s, level, optname, optval, optlen);
}

static inline int32_t do_setsockopt(int32_t s, int32_t level, int32_t optname, const void *optval, socklen_t optlen)
{
    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) == PATH_KERNEL || unsupport_optname(optname)) {
        return posix_api->setsockopt_fn(s, level, optname, optval, optlen);
    }

    /* we both set kernel and lwip */
    int32_t ret = posix_api->setsockopt_fn(s, level, optname, optval, optlen);
    if (ret != 0) {
        return ret;
    }

    return rpc_call_setsockopt(s, level, optname, optval, optlen);
}

static inline int32_t do_socket(int32_t domain, int32_t type, int32_t protocol)
{
    if ((domain != AF_INET && domain != AF_UNSPEC)
        || posix_api->use_kernel) {
        return posix_api->socket_fn(domain, type, protocol);
    }

    return rpc_call_socket(domain, type, protocol);
}

static inline ssize_t do_recv(int32_t sockfd, void *buf, size_t len, int32_t flags)
{
    if (buf == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    if (len == 0) {
        return 0;
    }

    struct lwip_sock *sock = NULL;
    if (select_path(sockfd, &sock) == PATH_LWIP) {
        return read_stack_data(sockfd, buf, len, flags, NULL, NULL);
    }

    return posix_api->recv_fn(sockfd, buf, len, flags);
}

static inline ssize_t do_read(int32_t s, void *mem, size_t len)
{
    if (mem == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    if (len == 0) {
        return 0;
    }

    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) == PATH_LWIP) {
        return read_stack_data(s, mem, len, 0, NULL, NULL);
    }
    return posix_api->read_fn(s, mem, len);
}

static inline ssize_t do_readv(int32_t s, const struct iovec *iov, int iovcnt)
{
    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) != PATH_LWIP) {
        return posix_api->readv_fn(s, iov, iovcnt);
    }

    struct msghdr msg;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = LWIP_CONST_CAST(struct iovec *, iov);
    msg.msg_iovlen = iovcnt;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    ssize_t result = recvmsg_from_stack(s, &msg, 0);
    if (result == -1 && errno == EAGAIN) {
        errno = 0;
        return 0;
    }
    return result;
}

static inline ssize_t do_send(int32_t sockfd, const void *buf, size_t len, int32_t flags)
{
    struct lwip_sock *sock = NULL;
    if (select_path(sockfd, &sock) != PATH_LWIP) {
        return posix_api->send_fn(sockfd, buf, len, flags);
    }

    return gazelle_send(sockfd, buf, len, flags, NULL, 0);
}

static inline ssize_t do_write(int32_t s, const void *mem, size_t size)
{
    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) != PATH_LWIP) {
        return posix_api->write_fn(s, mem, size);
    }

    return gazelle_send(s, mem, size, 0, NULL, 0);
}

static inline ssize_t do_writev(int32_t s, const struct iovec *iov, int iovcnt)
{
    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) != PATH_LWIP) {
        return posix_api->writev_fn(s, iov, iovcnt);
    }

    struct msghdr msg;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = LWIP_CONST_CAST(struct iovec *, iov);
    msg.msg_iovlen = iovcnt;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    return sendmsg_to_stack(sock, s, &msg, 0);
}

static inline ssize_t do_recvmsg(int32_t s, struct msghdr *message, int32_t flags)
{
    if (message == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) == PATH_LWIP) {
        return recvmsg_from_stack(s, message, flags);
    }

    return posix_api->recvmsg_fn(s, message, flags);
}

static inline ssize_t do_sendmsg(int32_t s, const struct msghdr *message, int32_t flags)
{
    if (message == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) == PATH_LWIP) {
        return sendmsg_to_stack(sock, s, message, flags);
    }

    return posix_api->sendmsg_fn(s, message, flags);
}

static inline ssize_t do_recvfrom(int32_t sockfd, void *buf, size_t len, int32_t flags,
                                  struct sockaddr *addr, socklen_t *addrlen)
{
    if (buf == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    if (len == 0) {
        return 0;
    }

    struct lwip_sock *sock = NULL;
    if (select_path(sockfd, &sock) == PATH_LWIP) {
        return read_stack_data(sockfd, buf, len, flags, addr, addrlen);
    }

    return posix_api->recvfrom_fn(sockfd, buf, len, flags, addr, addrlen);
}

static inline ssize_t do_sendto(int32_t sockfd, const void *buf, size_t len, int32_t flags,
                                const struct sockaddr *addr, socklen_t addrlen)
{
    struct lwip_sock *sock = NULL;
    if (select_path(sockfd, &sock) != PATH_LWIP) {
        return posix_api->sendto_fn(sockfd, buf, len, flags, addr, addrlen);
    }

    return gazelle_send(sockfd, buf, len, flags, addr, addrlen);
}

static inline int32_t do_close(int32_t s)
{
    struct lwip_sock *sock = NULL;
    if (select_path(s, &sock) == PATH_KERNEL) {
        /* we called lwip_socket, even if kernel fd */
        if (posix_api != NULL && !posix_api->use_kernel &&
            /* contain posix_api->close_fn if success */
            stack_broadcast_close(s) == 0) {
            return 0;
        } else {
            return posix_api->close_fn(s);
        }
    }
    if (sock && sock->wakeup && sock->wakeup->epollfd == s) {
        return lstack_epoll_close(s);
    }
    return stack_broadcast_close(s);
}

static int32_t do_poll(struct pollfd *fds, nfds_t nfds, int32_t timeout)
{
    if (unlikely(posix_api->use_kernel) || fds == NULL || nfds == 0) {
        return posix_api->poll_fn(fds, nfds, timeout);
    }

    return lstack_poll(fds, nfds, timeout);
}

static int32_t do_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask)
{
    int32_t ready;
    int32_t timeout;

    if (fds == NULL || tmo_p == NULL) {
        GAZELLE_RETURN(EINVAL);
    }

    // s * 1000 and ns / 1000000 -> ms
    timeout = (tmo_p == NULL) ? -1 : (tmo_p->tv_sec * 1000 + tmo_p->tv_nsec / 1000000);
    ready = do_poll(fds, nfds, timeout);

    return ready;
}

typedef int32_t (*sigaction_fn)(int32_t signum, const struct sigaction *act, struct sigaction *oldact);
static int32_t do_sigaction(int32_t signum, const struct sigaction *act, struct sigaction *oldact)
{
    if (posix_api == NULL) {
        sigaction_fn sf = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");
        if (sf == NULL) {
            return -1;
        }
        return sf(signum, act, oldact);
    }

    return lstack_sigaction(signum, act, oldact);
}

#define POSIX_VA_PARAM(fd, cmd, type, lwip_fn, kernel_fn) \
    do { \
        unsigned long __val;    \
        va_list __ap;           \
        va_start(__ap, cmd);    \
        __val = va_arg(__ap, typeof(__val)); \
        va_end(__ap);           \
                                \
        int __ret = kernel_fn(fd, cmd, __val); \
        if (__ret == -1 || select_path(fd, NULL) == PATH_KERNEL) \
            return __ret;         \
        return lwip_fn(fd, cmd, (type)__val); \
    } while (0)

/*  --------------------------------------------------------
 *  -------  LD_PRELOAD mode replacement interface  --------
 *  --------------------------------------------------------
 */
int32_t epoll_create1(int32_t flags)
{
    return do_epoll_create1(flags);
}
int32_t epoll_create(int32_t size)
{
    return do_epoll_create(size);
}
int32_t epoll_ctl(int32_t epfd, int32_t op, int32_t fd, struct epoll_event* event)
{
    return do_epoll_ctl(epfd, op, fd, event);
}
int32_t epoll_wait(int32_t epfd, struct epoll_event* events, int32_t maxevents, int32_t timeout)
{
    return do_epoll_wait(epfd, events, maxevents, timeout);
}
int32_t fcntl64(int32_t s, int32_t cmd, ...)
{
    POSIX_VA_PARAM(s, cmd, int, lwip_fcntl, posix_api->fcntl64_fn);
}
int32_t fcntl(int32_t s, int32_t cmd, ...)
{
    POSIX_VA_PARAM(s, cmd, int, lwip_fcntl, posix_api->fcntl_fn);
}
int32_t ioctl(int32_t s, int32_t cmd, ...)
{
    POSIX_VA_PARAM(s, cmd, void*, lwip_ioctl, posix_api->ioctl_fn);
}
int32_t accept(int32_t s, struct sockaddr *addr, socklen_t *addrlen)
{
    return do_accept(s, addr, addrlen);
}
int32_t accept4(int32_t s, struct sockaddr *addr, socklen_t *addrlen, int32_t flags)
{
    return do_accept4(s, addr, addrlen, flags);
}
int32_t bind(int32_t s, const struct sockaddr *name, socklen_t namelen)
{
    return do_bind(s, name, namelen);
}
int32_t connect(int32_t s, const struct sockaddr *name, socklen_t namelen)
{
    return do_connect(s, name, namelen);
}
int32_t listen(int32_t s, int32_t backlog)
{
    return do_listen(s, backlog);
}
int32_t getpeername(int32_t s, struct sockaddr *name, socklen_t *namelen)
{
    return do_getpeername(s, name, namelen);
}
int32_t getsockname(int32_t s, struct sockaddr *name, socklen_t *namelen)
{
    return do_getsockname(s, name, namelen);
}
int32_t getsockopt(int32_t s, int32_t level, int32_t optname, void *optval, socklen_t *optlen)
{
    return do_getsockopt(s, level, optname, optval, optlen);
}
int32_t setsockopt(int32_t s, int32_t level, int32_t optname, const void *optval, socklen_t optlen)
{
    return do_setsockopt(s, level, optname, optval, optlen);
}
int32_t socket(int32_t domain, int32_t type, int32_t protocol)
{
    return do_socket(domain, type, protocol);
}
ssize_t read(int32_t s, void *mem, size_t len)
{
    return do_read(s, mem, len);
}
ssize_t readv(int32_t s, const struct iovec *iov, int iovcnt)
{
    return do_readv(s, iov, iovcnt);
}
ssize_t write(int32_t s, const void *mem, size_t size)
{
    return do_write(s, mem, size);
}
ssize_t writev(int32_t s, const struct iovec *iov, int iovcnt)
{
    return do_writev(s, iov, iovcnt);
}
ssize_t __wrap_write(int32_t s, const void *mem, size_t size)
{
    return do_write(s, mem, size);
}
ssize_t __wrap_writev(int32_t s, const struct iovec *iov, int iovcnt)
{
    return do_writev(s, iov, iovcnt);
}
ssize_t recv(int32_t sockfd, void *buf, size_t len, int32_t flags)
{
    return do_recv(sockfd, buf, len, flags);
}
ssize_t send(int32_t sockfd, const void *buf, size_t len, int32_t flags)
{
    return do_send(sockfd, buf, len, flags);
}
ssize_t recvmsg(int32_t s, struct msghdr *message, int32_t flags)
{
    return do_recvmsg(s, message, flags);
}
ssize_t sendmsg(int32_t s, const struct msghdr *message, int32_t flags)
{
    return do_sendmsg(s, message, flags);
}
ssize_t recvfrom(int32_t sockfd, void *buf, size_t len, int32_t flags,
                 struct sockaddr *addr, socklen_t *addrlen)
{
    return do_recvfrom(sockfd, buf, len, flags, addr, addrlen);
}
ssize_t sendto(int32_t sockfd, const void *buf, size_t len, int32_t flags,
               const struct sockaddr *addr, socklen_t addrlen)
{
    return do_sendto(sockfd, buf, len, flags, addr, addrlen);
}
int32_t close(int32_t s)
{
    return do_close(s);
}
int32_t poll(struct pollfd *fds, nfds_t nfds, int32_t timeout)
{
    return do_poll(fds, nfds, timeout);
}
int32_t ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask)
{
    return do_ppoll(fds, nfds, tmo_p, sigmask);
}
int32_t sigaction(int32_t signum, const struct sigaction *act, struct sigaction *oldact)
{
    return do_sigaction(signum, act, oldact);
}
pid_t fork(void)
{
    return lstack_fork();
}

/*  --------------------------------------------------------
 *  -------  Compile mode replacement interface  -----------
 *  --------------------------------------------------------
 */

int32_t __wrap_epoll_create1(int32_t size)
{
    return do_epoll_create1(size);
}
int32_t __wrap_epoll_create(int32_t size)
{
    return do_epoll_create(size);
}
int32_t __wrap_epoll_ctl(int32_t epfd, int32_t op, int32_t fd, struct epoll_event* event)
{
    return do_epoll_ctl(epfd, op, fd, event);
}
int32_t __wrap_epoll_wait(int32_t epfd, struct epoll_event* events, int32_t maxevents, int32_t timeout)
{
    return do_epoll_wait(epfd, events, maxevents, timeout);
}
int32_t __wrap_fcntl64(int32_t s, int32_t cmd, ...)
{
    POSIX_VA_PARAM(s, cmd, int, lwip_fcntl, posix_api->fcntl64_fn);
}
int32_t __wrap_fcntl(int32_t s, int32_t cmd, ...)
{
    POSIX_VA_PARAM(s, cmd, int, lwip_fcntl, posix_api->fcntl_fn);
}
int32_t __wrap_ioctl(int32_t s, int32_t cmd, ...)
{
    POSIX_VA_PARAM(s, cmd, void*, lwip_ioctl, posix_api->ioctl_fn);
}

int32_t __wrap_accept(int32_t s, struct sockaddr *addr, socklen_t *addrlen)
{
    return do_accept(s, addr, addrlen);
}
int32_t __wrap_accept4(int32_t s, struct sockaddr *addr, socklen_t *addrlen, int32_t flags)
{
    return do_accept4(s, addr, addrlen, flags);
}
int32_t __wrap_bind(int32_t s, const struct sockaddr *name, socklen_t namelen)
{
    return do_bind(s, name, namelen);
}
int32_t __wrap_connect(int32_t s, const struct sockaddr *name, socklen_t namelen)
{
    return do_connect(s, name, namelen);
}
int32_t __wrap_listen(int32_t s, int32_t backlog)
{
    return do_listen(s, backlog);
}
int32_t __wrap_getpeername(int32_t s, struct sockaddr *name, socklen_t *namelen)
{
    return do_getpeername(s, name, namelen);
}
int32_t __wrap_getsockname(int32_t s, struct sockaddr *name, socklen_t *namelen)
{
    return do_getsockname(s, name, namelen);
}
int32_t __wrap_getsockopt(int32_t s, int32_t level, int32_t optname, void *optval, socklen_t *optlen)
{
    return do_getsockopt(s, level, optname, optval, optlen);
}
int32_t __wrap_setsockopt(int32_t s, int32_t level, int32_t optname, const void *optval, socklen_t optlen)
{
    return do_setsockopt(s, level, optname, optval, optlen);
}
int32_t __wrap_socket(int32_t domain, int32_t type, int32_t protocol)
{
    return do_socket(domain, type, protocol);
}
ssize_t __wrap_read(int32_t s, void *mem, size_t len)
{
    return do_read(s, mem, len);
}
ssize_t __wrap_readv(int32_t s, const struct iovec *iov, int iovcnt)
{
    return do_readv(s, iov, iovcnt);
}
ssize_t __wrap_recv(int32_t sockfd, void *buf, size_t len, int32_t flags)
{
    return do_recv(sockfd, buf, len, flags);
}
ssize_t __wrap_send(int32_t sockfd, const void *buf, size_t len, int32_t flags)
{
    return do_send(sockfd, buf, len, flags);
}
ssize_t __wrap_recvmsg(int32_t s, struct msghdr *message, int32_t flags)
{
    return do_recvmsg(s, message, flags);
}
ssize_t __wrap_sendmsg(int32_t s, const struct msghdr *message, int32_t flags)
{
    return do_sendmsg(s, message, flags);
}
ssize_t __wrap_recvfrom(int32_t sockfd, void *buf, size_t len, int32_t flags,
                        struct sockaddr *addr, socklen_t *addrlen)
{
    return do_recvfrom(sockfd, buf, len, flags, addr, addrlen);
}
ssize_t __wrap_sendto(int32_t sockfd, const void *buf, size_t len, int32_t flags,
                      const struct sockaddr *addr, socklen_t addrlen)
{
    return do_sendto(sockfd, buf, len, flags, addr, addrlen);
}
int32_t __wrap_close(int32_t s)
{
    return do_close(s);
}
int32_t __wrap_poll(struct pollfd *fds, nfds_t nfds, int32_t timeout)
{
    return do_poll(fds, nfds, timeout);
}
int32_t __wrap_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask)
{
    return do_ppoll(fds, nfds, tmo_p, sigmask);
}
int32_t __wrap_sigaction(int32_t signum, const struct sigaction *act, struct sigaction *oldact)
{
    return do_sigaction(signum, act, oldact);
}
pid_t __wrap_fork(void)
{
    return lstack_fork();
}
