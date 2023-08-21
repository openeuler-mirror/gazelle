<img src="images/logo.png" alt=Gazelle style="zoom:20%"> 

# Gazelle支持posix接口列表
- int32_t epoll_create1(int32_t flags)
- int32_t epoll_create(int32_t size)
- int32_t epoll_ctl(int32_t epfd, int32_t op, int32_t fd, struct epoll_event* event)
- int32_t epoll_wait(int32_t epfd, struct epoll_event* events, int32_t maxevents, int32_t timeout)
- int32_t fcntl64(int32_t s, int32_t cmd, ...)
- int32_t fcntl(int32_t s, int32_t cmd, ...)
- int32_t ioctl(int32_t s, int32_t cmd, ...)
- int32_t accept(int32_t s, struct sockaddr *addr, socklen_t *addrlen)
- int32_t accept4(int32_t s, struct sockaddr *addr, socklen_t *addrlen, int32_t flags)
- int32_t bind(int32_t s, const struct sockaddr *name, socklen_t namelen)
- int32_t connect(int32_t s, const struct sockaddr *name, socklen_t namelen)
- int32_t listen(int32_t s, int32_t backlog)
- int32_t getpeername(int32_t s, struct sockaddr *name, socklen_t *namelen)
- int32_t getsockname(int32_t s, struct sockaddr *name, socklen_t *namelen)
- int32_t getsockopt(int32_t s, int32_t level, int32_t optname, void *optval, socklen_t *optlen)
- int32_t setsockopt(int32_t s, int32_t level, int32_t optname, const void *optval, socklen_t optlen)
- int32_t socket(int32_t domain, int32_t type, int32_t protocol)
- ssize_t read(int32_t s, void *mem, size_t len)
- ssize_t readv(int32_t s, const struct iovec *iov, int iovcnt)
- ssize_t write(int32_t s, const void *mem, size_t size)
- ssize_t writev(int32_t s, const struct iovec *iov, int iovcnt)
- ssize_t recv(int32_t sockfd, void *buf, size_t len, int32_t flags)
- ssize_t send(int32_t sockfd, const void *buf, size_t len, int32_t flags)
- ssize_t recvmsg(int32_t s, struct msghdr *message, int32_t flags)
- ssize_t sendmsg(int32_t s, const struct msghdr *message, int32_t flags)
- int32_t close(int32_t s)
- int32_t poll(struct pollfd *fds, nfds_t nfds, int32_t timeout)
- int32_t ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask)
- int32_t sigaction(int32_t signum, const struct sigaction *act, struct sigaction *oldact)
- pid_t fork(void)

# Gazelle支持应用列表
- mysql 8.0.20
- ceph client 14.2.8