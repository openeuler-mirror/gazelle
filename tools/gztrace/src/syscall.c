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

#include "syscall.h"

/* Returns the name of the system call as a string */
const char* net_syscall_name(long call)
{
    switch (call) {
        case SYS_socket:
            return "socket";
        case SYS_bind:
            return "bind";
        case SYS_connect:
            return "connect";
        case SYS_listen:
            return "listen";
        case SYS_accept:
            return "accept";
        case SYS_accept4:
            return "accept4";
        case SYS_getsockname:
            return "getsockname";
        case SYS_getpeername:
            return "getpeername";
        case SYS_socketpair:
            return "socketpair";
        case SYS_sendto:
            return "sendto";
        case SYS_recvfrom:
            return "recvfrom";
        case SYS_sendmsg:
            return "sendmsg";
        case SYS_recvmsg:
            return "recvmsg";
        case SYS_shutdown:
            return "shutdown";
            // case SYS_close: return "close";
        case SYS_setsockopt:
            return "setsockopt";
        case SYS_getsockopt:
            return "getsockopt";
            // case SYS_ioctl: return "ioctl";
            // case SYS_send: return "send";
            // case SYS_recv: return "recv";
        default:
            return NULL;
    }
}

/* Returns a string description of the socket domain */
const char* format_domain(int domain)
{
    switch (domain) {
        case AF_INET:
            return "AF_INET";  /* IPv4 Internet protocols */
        case AF_INET6:
            return "AF_INET6"; /* IPv6 Internet protocols */
        case AF_UNIX:
            return "AF_UNIX";  /* Local communication */
        case AF_UNSPEC:
            return "AF_UNSPEC"; /* Unspecified */
        case AF_PACKET:
            return "AF_PACKET"; /* Packet interface on Linux */
        case AF_NETLINK:
            return "AF_NETLINK"; /* Netlink protocol */
        case AF_X25:
            return "AF_X25"; /* ITU-T X.25 / ISO-8208 protocol */
        case AF_AX25:
            return "AF_AX25"; /* Amateur radio AX.25 protocol */
        case AF_ATMPVC:
            return "AF_ATMPVC"; /* ATM PVCs */
        case AF_APPLETALK:
            return "AF_APPLETALK"; /* AppleTalk protocol */
        case AF_BRIDGE:
            return "AF_BRIDGE"; /* Multiprotocol bridge */
        case AF_BLUETOOTH:
            return "AF_BLUETOOTH"; /* Bluetooth protocol */
        case AF_CAN:
            return "AF_CAN"; /* Controller Area Network protocol */
        case AF_DECnet:
            return "AF_DECnet"; /* DECnet protocol */
        case AF_IEEE802154:
            return "AF_IEEE802154"; /* IEEE 802.15.4 WPAN */
        case AF_ALG:
            return "AF_ALG"; /* Linux CryptoAPI */
        case AF_NFC:
            return "AF_NFC"; /* Near Field Communication protocol */
        case AF_IRDA:
            return "AF_IRDA"; /* IrDA protocol */
        case AF_PPPOX:
            return "AF_PPPOX"; /* PPPoX protocol */
        case AF_TIPC:
            return "AF_TIPC"; /* TIPC protocol */
        case AF_SMC:
            return "AF_SMC"; /* SMC-R protocol */
        case AF_QIPCRTR:
            return "AF_QIPCRTR"; /* Qualcomm IPC router */
        case AF_VSOCK:
            return "AF_VSOCK"; /* VSOCK protocol */
        default:
            return "UNKNOWN"; /* Unknown domain */
    }
}

/* Returns a string description of the socket type */
const char* format_type(int type)
{
    switch (type) {
        case SOCK_STREAM:
            return "SOCK_STREAM"; /* Provides sequenced, reliable, two-way, connection-based byte streams (e.g., TCP) */
        case SOCK_DGRAM:
            return "SOCK_DGRAM"; /* Supports datagrams */
        case SOCK_RAW:
            return "SOCK_RAW"; /* Provides raw network protocol access */
        case SOCK_RDM:
            return "SOCK_RDM"; /* Provides a reliable datagram layer that does not guarantee ordering */
        case SOCK_SEQPACKET:
            return "SOCK_SEQPACKET"; /* Provides a sequenced, reliable, two-way
 * connection-based data transmission path for datagrams of fixed maximum length */
        case SOCK_DCCP:
            return "SOCK_DCCP"; /* Datagram Congestion Control Protocol sockets */
        case SOCK_PACKET:
            return "SOCK_PACKET"; /* Obsolete, used to be for direct packet interface  */
        default:
            return "UNKNOWN"; /* Unknown type */
    }
}

/* Returns a string description of the protocol */
const char* format_protocol(int protocol)
{
    switch (protocol) {
        case IPPROTO_IP:
            return "IPPROTO_IP";
        case IPPROTO_TCP:
            return "IPPROTO_TCP";
        case IPPROTO_UDP:
            return "IPPROTO_UDP";
        case IPPROTO_IPV6:
            return "IPPROTO_IPV6";
        default:
            return "UNKNOWN_PROTOCOL";
    }
}

/* Returns a string description of the socket option level */
const char* format_socket_level(int level)
{
    switch (level) {
        case SOL_SOCKET:
            return "SOL_SOCKET"; /* Socket level */
        case IPPROTO_TCP:
            return "SOL_TCP"; /* TCP level */
        case IPPROTO_UDP:
            return "SOL_UDP"; /* UDP level */
        case IPPROTO_IP:
            return "SOL_IP"; /* IP level */
        case IPPROTO_IPV6:
            return "SOL_IPV6"; /* IPv6 level */
        case IPPROTO_RAW:
            return "SOL_RAW"; /* Raw IP packets */
        case IPPROTO_IGMP:
            return "SOL_IGMP"; /* Internet Group Management Protocol */
        case IPPROTO_SCTP:
            return "SOL_SCTP"; /* Stream Control Transmission Protocol */
        default:
            return "UNKNOWN"; /* Unknown level */
    }
}

/* Returns a string description of socket options at SOL_SOCKET level */
const char* format_sol_socket_option(int optname)
{
    switch (optname) {
        case SO_KEEPALIVE:
            return "SO_KEEPALIVE";
        case SO_REUSEADDR:
            return "SO_REUSEADDR";
        case SO_BROADCAST:
            return "SO_BROADCAST";
        case SO_LINGER:
            return "SO_LINGER";
        case SO_RCVBUF:
            return "SO_RCVBUF";
        case SO_SNDBUF:
            return "SO_SNDBUF";
        case SO_RCVTIMEO:
            return "SO_RCVTIMEO";
        case SO_SNDTIMEO:
            return "SO_SNDTIMEO";
        case SO_ERROR:
            return "SO_ERROR";
        case SO_REUSEPORT:
            return "SO_REUSEPORT";
        case SO_OOBINLINE:
            return "SO_OOBINLINE";
        default:
            return "UNKNOWN_SOL_SOCKET";
    }
}

/* Returns a string description of socket options at IPPROTO_TCP level */
const char* format_tcp_option(int optname)
{
    switch (optname) {
        case TCP_NODELAY:
            return "TCP_NODELAY";
        case TCP_KEEPIDLE:
            return "TCP_KEEPIDLE";
        case TCP_KEEPINTVL:
            return "TCP_KEEPINTVL";
        case TCP_KEEPCNT:
            return "TCP_KEEPCNT";
        case TCP_SYNCNT:
            return "TCP_SYNCNT";
        case TCP_LINGER2:
            return "TCP_LINGER2";
        case TCP_DEFER_ACCEPT:
            return "TCP_DEFER_ACCEPT";
        case TCP_WINDOW_CLAMP:
            return "TCP_WINDOW_CLAMP";
        default:
            return "UNKNOWN_TCP";
    }
}

/* Returns a string description of socket options at IPPROTO_IP level */
const char* format_ip_option(int optname)
{
    switch (optname) {
        case IP_TTL:
            return "IP_TTL";
        case IP_MULTICAST_TTL:
            return "IP_MULTICAST_TTL";
        case IP_MULTICAST_LOOP:
            return "IP_MULTICAST_LOOP";
        case IP_ADD_MEMBERSHIP:
            return "IP_ADD_MEMBERSHIP";
        case IP_DROP_MEMBERSHIP:
            return "IP_DROP_MEMBERSHIP";
        default:
            return "UNKNOWN_IP";
    }
}

/* Returns a string description of socket options at IPPROTO_IPV6 level */
const char* format_ipv6_option(int optname)
{
    switch (optname) {
        case IPV6_V6ONLY:
            return "IPV6_V6ONLY";
        case IPV6_RECVPKTINFO:
            return "IPV6_RECVPKTINFO";
        case IPV6_PKTINFO:
            return "IPV6_PKTINFO";
        case IPV6_RECVHOPLIMIT:
            return "IPV6_RECVHOPLIMIT";
        default:
            return "UNKNOWN_IPV6";
    }
}

/* Main function to format socket options based on the level */
const char* format_socket_option(int level, int optname)
{
    if (level == SOL_SOCKET) {
        return format_sol_socket_option(optname);
    } else if (level == IPPROTO_TCP) {
        return format_tcp_option(optname);
    } else if (level == IPPROTO_IP) {
        return format_ip_option(optname);
    } else if (level == IPPROTO_IPV6) {
        return format_ipv6_option(optname);
    }
    return "UNKNOWN";
}


/* Converts flags to their string representations */
const char* flags_to_string(int flags)
{
    static char buffer[256];
    buffer[0] = '\0';

    if (flags == 0) {
        strcpy(buffer, "0");
        return buffer;
    }

    int first = 1;

    check_flag(MSG_OOB, "MSG_OOB", &flags, &first, buffer);
    check_flag(MSG_PEEK, "MSG_PEEK", &flags, &first, buffer);
    check_flag(MSG_DONTROUTE, "MSG_DONTROUTE", &flags, &first, buffer);
    check_flag(MSG_CTRUNC, "MSG_CTRUNC", &flags, &first, buffer);
    check_flag(MSG_PROXY, "MSG_PROXY", &flags, &first, buffer);
    check_flag(MSG_TRUNC, "MSG_TRUNC", &flags, &first, buffer);
    check_flag(MSG_DONTWAIT, "MSG_DONTWAIT", &flags, &first, buffer);
    check_flag(MSG_EOR, "MSG_EOR", &flags, &first, buffer);
    check_flag(MSG_WAITALL, "MSG_WAITALL", &flags, &first, buffer);
    check_flag(MSG_FIN, "MSG_FIN", &flags, &first, buffer);
    check_flag(MSG_SYN, "MSG_SYN", &flags, &first, buffer);
    check_flag(MSG_CONFIRM, "MSG_CONFIRM", &flags, &first, buffer);
    check_flag(MSG_RST, "MSG_RST", &flags, &first, buffer);
    check_flag(MSG_ERRQUEUE, "MSG_ERRQUEUE", &flags, &first, buffer);
    check_flag(MSG_NOSIGNAL, "MSG_NOSIGNAL", &flags, &first, buffer);
    check_flag(MSG_MORE, "MSG_MORE", &flags, &first, buffer);
    check_flag(MSG_WAITFORONE, "MSG_WAITFORONE", &flags, &first, buffer);
    check_flag(MSG_BATCH, "MSG_BATCH", &flags, &first, buffer);
    check_flag(MSG_FASTOPEN, "MSG_FASTOPEN", &flags, &first, buffer);
    check_flag(MSG_CMSG_CLOEXEC, "MSG_CMSG_CLOEXEC", &flags, &first, buffer);

    if (flags != 0) {
        if (!first) {
            strcat(buffer, "|");
        }
        char unknown[32];
        snprintf(unknown, sizeof(unknown), "0x%x", flags);
        strcat(buffer, unknown);
    }

    return buffer;
}


/* Handles the socket system call and outputs call details */
void handle_socket(pid_t pid, const struct user_regs_struct *regs)
{
    printf("socket(%s, %s, %s) = ",
           format_domain((int)regs->rdi),
           format_type((int)regs->rsi),
           format_protocol((int)regs->rdx));
}

/* Handles the connect system call and outputs call details */
void handle_connect(pid_t pid, const struct user_regs_struct *regs)
{
    struct sockaddr_in addr;
    char ip[INET_ADDRSTRLEN];
    long addr_data = ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rsi, NULL);
    if (errno) {
        perror("Failed to read sockaddr_in structure from target process");
        return;
    }
    memcpy(&addr, &addr_data, sizeof(addr));

    if (inet_ntop(AF_INET, &(addr.sin_addr), ip, INET_ADDRSTRLEN) == NULL) {
        perror("inet_ntop failed");
        return;
    }

    printf("connect(%d, {sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, %lld) = ",
           (int)regs->rdi,
           ntohs(addr.sin_port),
           ip,
           (long long)regs->rdx);
}

/* Handles the setsockopt system call and outputs call details */
void handle_setsockopt(pid_t pid, const struct user_regs_struct *regs)
{
    long optval_ptr = regs->r10;
    socklen_t optlen = (socklen_t)regs->r8;
    int optval;

    if (optlen == sizeof(int)) {
        optval = (int)ptrace(PTRACE_PEEKDATA, pid, (void*)optval_ptr, NULL);
        if (errno) {
            perror("Failed to read optval from target process");
            return;
        }
    } else {
        optval = 0; /* Default value; more complex logic may be needed to handle different optval types */
    }

    printf("setsockopt(%d, %s, %s, [%d], %d) = ",
           (int)regs->rdi,
           format_socket_level((int)regs->rsi),
           format_socket_option((int)regs->rsi, (int)regs->rdx),
           optval,
           optlen);
}

/* Handles the bind system call and outputs call details */
void handle_bind(pid_t pid, const struct user_regs_struct *regs)
{
    struct sockaddr_in addr;
    long addr_ptr = (long)regs->rsi;
    socklen_t addrlen = (socklen_t)regs->rdx;
    char ip[INET_ADDRSTRLEN];

    ptrace(PTRACE_PEEKDATA, pid, (void*)addr_ptr, &addr);
    if (errno) {
        perror("Failed to read sockaddr from target process");
        return;
    }

    if (inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN) == NULL) {
        perror("inet_ntop failed");
        return;
    }

    printf("bind(%d, {sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, %d) = ",
           (int)regs->rdi,
           ntohs(addr.sin_port),
           ip,
           addrlen);
}

/* Handles the getsockopt system call and outputs call details */
void handle_getsockopt(pid_t pid, const struct user_regs_struct *regs)
{
    int optval;
    socklen_t optlen;
    long optval_ptr = regs->r10;
    long optlen_ptr = regs->r8;

    optval = (int)ptrace(PTRACE_PEEKDATA, pid, (void*)optval_ptr, NULL);
    optlen = (socklen_t)ptrace(PTRACE_PEEKDATA, pid, (void*)optlen_ptr, NULL);
    if (errno) {
        perror("Failed to read optval or optlen from target process");
        return;
    }

    printf("getsockopt(%d, %s, %s, [%d], [%d]) = ",
           (int)regs->rdi,
           format_socket_level((int)regs->rsi),
           format_socket_option((int)regs->rsi, (int)regs->rdx),
           optval,
           optlen);
}


void handle_getpeername(pid_t pid, const struct user_regs_struct *regs)
{
    int sockfd = regs->rdi;
    char *addr_ptr = (char *)regs->rsi;
    char *addrlen_ptr = (char *)regs->rdx;

    /* Read initial addrlen value before the system call */
    errno = 0;
    socklen_t initial_addrlen = ptrace(PTRACE_PEEKDATA, pid, addrlen_ptr, NULL);
    if (errno != 0) {
        perror("ptrace PEEKDATA addrlen (before)");
        return;
    }

    /* Execute the system call */
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
        perror("ptrace PTRACE_SYSCALL");
        return;
    }

    /* Wait for the system call to complete */
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        return;
    }

    /* Get the return value */
    struct user_regs_struct regs_after;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs_after) == -1) {
        perror("ptrace GETREGS");
        return;
    }
    long retval = regs_after.rax;

    /* Read the updated addrlen value */
    errno = 0;
    socklen_t final_addrlen = ptrace(PTRACE_PEEKDATA, pid, addrlen_ptr, NULL);
    if (errno != 0) {
        perror("ptrace PEEKDATA addrlen (after)");
        return;
    }

    /* Read the sockaddr_storage from the child process's memory */
    struct sockaddr_storage addr_storage;
    read_sockaddr_from_child(pid, addr_ptr, final_addrlen, &addr_storage);

    /* Print the system call and its parameters */
    printf("getpeername(%d, ", sockfd);
    print_sockaddr(&addr_storage, final_addrlen);
    printf(", [%d => %d]) = ", (int)initial_addrlen, (int)final_addrlen);

    /* Print the return value */
    if (retval < 0) {
        int err = -retval;
        printf("-1 %s (%s)\n", strerrorname_np(err), strerror(err));
    } else {
        printf("0\n");
    }
}

/* Handles the accept system call and outputs call details */
void handle_accept(pid_t pid, const struct user_regs_struct *regs)
{
    int sockfd = regs->rdi;
    char *addr_ptr = (char *)regs->rsi;
    char *addrlen_ptr = (char *)regs->rdx;

    /* Read initial addrlen value before the system call */
    errno = 0;
    socklen_t initial_addrlen = ptrace(PTRACE_PEEKDATA, pid, addrlen_ptr, NULL);
    if (errno != 0) {
        perror("ptrace PEEKDATA addrlen (before)");
        return;
    }

    /* Execute the system call */
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
        perror("ptrace PTRACE_SYSCALL");
        return;
    }

    /* Wait for the system call to complete */
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        return;
    }

    /* Get the return value */
    struct user_regs_struct regs_after;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs_after) == -1) {
        perror("ptrace GETREGS");
        return;
    }
    long retval = regs_after.rax;

    /* Read the updated addrlen value */
    errno = 0;
    socklen_t final_addrlen = ptrace(PTRACE_PEEKDATA, pid, addrlen_ptr, NULL);
    if (errno != 0) {
        perror("ptrace PEEKDATA addrlen (after)");
        return;
    }

    /* Read the sockaddr_storage from the child process's memory */
    struct sockaddr_storage addr_storage;
    size_t addrlen = final_addrlen < sizeof(addr_storage) ? final_addrlen : sizeof(addr_storage);
    read_sockaddr_from_child(pid, addr_ptr, addrlen, &addr_storage);

    /* Print the system call and its parameters */
    printf("accept(%d, ", sockfd);
    print_sockaddr(&addr_storage, final_addrlen);
    printf(", [%d => %d]) = ", (int)initial_addrlen, (int)final_addrlen);

    /* Print the return value */
    if (retval < 0) {
        int err = -retval;
        printf("-1 %s (%s)\n", strerrorname_np(err), strerror(err));
    } else {
        printf("%ld\n", retval);
    }
}
/* Handles the socketpair system call and outputs call details */
void handle_socketpair(pid_t pid, const struct user_regs_struct *regs)
{
    int fds[2];
    long fds_ptr = regs->r10;

    fds[0] = (int)ptrace(PTRACE_PEEKDATA, pid, (void*)fds_ptr, NULL);
    fds[1] = (int)ptrace(PTRACE_PEEKDATA, pid, (void*)(fds_ptr + sizeof(int)), NULL);
    if (errno) {
        perror("Failed to read file descriptors from target process");
        return;
    }

    printf("socketpair(%s, %s, %d, [%d, %d]) = ",
           format_domain((int)regs->rdi),
           format_type((int)regs->rsi),
           (int)regs->rdx,
           fds[0],
           fds[1]);
}

/* Handles the getsockname system call and outputs call details */
void handle_getsockname(pid_t pid, const struct user_regs_struct *regs)
{
    struct sockaddr_in addr;
    long addr_ptr = (long)regs->rsi;
    socklen_t addrlen;
    char ip[INET_ADDRSTRLEN];

    /* Read the address length */
    long addrlen_ptr = (long)regs->rdx;
    long addrlen_val = ptrace(PTRACE_PEEKDATA, pid, (void*)addrlen_ptr, NULL);
    if (errno) {
        perror("Failed to read sockaddr length from target process");
        return;
    }
    addrlen = (socklen_t)addrlen_val;

    /* Read the entire sockaddr structure */
    errno = 0;
    ptrace(PTRACE_PEEKDATA, pid, (void*)addr_ptr, &addr);
    if (errno) {
        perror("Failed to read sockaddr structure from target process");
        return;
    }

    /* Convert IP address to string format */
    if (inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN) == NULL) {
        perror("inet_ntop failed");
        return;
    }

    /* Print the getsockname result, ensuring the printed length matches the actual socklen_t value */
    printf("getsockname(%d, {sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, [%d => %d]) = ",
           (int)regs->rdi,
           ntohs(addr.sin_port),
           ip,
           addrlen,
           sizeof(addr));
}

/* Reads data from child process memory */
size_t read_data_from_child(pid_t pid, char *remote_addr, size_t len, char *local_buffer, size_t buffer_size)
{
    size_t bytes_to_read = len < buffer_size ? len : buffer_size - 1;
    size_t i = 0;
    errno = 0;
    while (i < bytes_to_read) {
        long word = ptrace(PTRACE_PEEKDATA, pid, (char *)remote_addr + i, NULL);
        if (errno != 0) {
            perror("ptrace PEEKDATA");
            break;
        }
        size_t copy_size = ((bytes_to_read - i) < sizeof(long)) ? (bytes_to_read - i) : sizeof(long);
        memcpy(local_buffer + i, &word, copy_size);
        i += sizeof(long);
    }
    local_buffer[bytes_to_read] = '\0';
    return bytes_to_read;
}
/* Prints buffer content with special character handling */
void print_buffer(const char *buffer, size_t length)
{
    printf("\"");
    for (size_t i = 0; i < length && buffer[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)buffer[i];
        if (isprint(c)) {
            putchar(c);
        } else if (c == '\n') {
            printf("\\n");
        } else if (c == '\r') {
            printf("\\r");
        } else if (c == '\t') {
            printf("\\t");
        } else {
            unsigned int uc = (unsigned int)c;
            printf("\\x%02x", uc);
        }
    }
    printf("\"");
}
/* Reads sockaddr structure from child process memory */
void read_sockaddr_from_child(pid_t pid, char *remote_addr, socklen_t addrlen,
                              struct sockaddr_storage *local_addr_storage)
{
    memset(local_addr_storage, 0, sizeof(struct sockaddr_storage));
    size_t bytes_to_read = addrlen < sizeof(struct sockaddr_storage) ? addrlen : sizeof(struct sockaddr_storage);
    size_t i = 0;
    errno = 0;
    while (i < bytes_to_read) {
        long word = ptrace(PTRACE_PEEKDATA, pid, (char *)remote_addr + i, NULL);
        if (errno != 0) {
            perror("ptrace PEEKDATA sockaddr");
            break;
        }
        size_t copy_size = ((bytes_to_read - i) < sizeof(long)) ? (bytes_to_read - i) : sizeof(long);
        memcpy((char *)local_addr_storage + i, &word, copy_size);
        i += sizeof(long);
    }
}
/* Prints sockaddr information */
void print_sockaddr(const struct sockaddr_storage *addr_storage, socklen_t addrlen)
{
    char addr_str[INET6_ADDRSTRLEN] = "";
    if (addr_storage->ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr_storage;
        inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
        printf("{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, %u",
               ntohs(sin->sin_port),
               addr_str,
               addrlen);
    } else if (addr_storage->ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr_storage;
        inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
        printf("{sa_family=AF_INET6, sin6_port=htons(%d), sin6_addr=\"%s\"}, %u",
               ntohs(sin6->sin6_port),
               addr_str,
               addrlen);
    } else {
        printf("{sa_family=%d, ...}, %u", addr_storage->ss_family, addrlen);
    }
}
/* Handle sendto system call and output call details */
void handle_sendto(pid_t pid, struct user_regs_struct *regs)
{
    /* Retrieve parameters of the sendto call */
    int sockfd = regs->rdi;
    void *buf = (void *)regs->rsi;
    size_t len = regs->rdx;
    int flags = regs->r10;
    struct sockaddr *dest_addr = (struct sockaddr *)regs->r8;
    socklen_t addrlen = regs->r9;

    /* Read buffer content from child process memory */
    char buffer[SENDTO_BUFFER_SIZE];
    size_t bytes_to_read = len < SENDTO_BUFFER_SIZE ? len : SENDTO_BUFFER_SIZE - 1;
    bytes_to_read = bytes_to_read < SENDTO_BUFFER_SHOW ? bytes_to_read : SENDTO_BUFFER_SHOW;
    bytes_to_read = read_data_from_child(pid, buf, bytes_to_read, buffer, SENDTO_BUFFER_SIZE);

    /* Print parameters of the sendto call */
    printf("sendto(%d, ", sockfd);
    /* Print buffer content */
    print_buffer(buffer, bytes_to_read);
    printf("...");

    /* Print remaining parameters */
    const char *flags_str = flags_to_string(flags);
    printf(", %zu, %s, ", len, flags_str);

    /* Print target address information */
    if (dest_addr && addrlen > 0) {
        struct sockaddr_storage addr_storage;
        read_sockaddr_from_child(pid, dest_addr, addrlen, &addr_storage);
        print_sockaddr(&addr_storage, addrlen);
    } else {
        printf("NULL, 0");
    }

    printf(") = ");
    /* Return value will be retrieved and printed in the main loop */
}
/* Handles the recvfrom system call and outputs call details */
void handle_recvfrom(pid_t pid, struct user_regs_struct *regs)
{
    /* Retrieve recvfrom call parameters */
    int sockfd = regs->rdi;
    void *buf = (void *)regs->rsi;
    size_t len = regs->rdx;
    int flags = regs->r10;
    struct sockaddr *src_addr = (struct sockaddr *)regs->r8;
    socklen_t *addrlen_ptr = (socklen_t *)regs->r9;

    /* Execute the system call */
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
        perror("ptrace PTRACE_SYSCALL");
        return;
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        return;
    }

    /* Get the return value */
    struct user_regs_struct regs_out;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs_out);
    long retval = regs_out.rax; /* System call return value */

    /* Print the recvfrom call parameters */
    printf("recvfrom(%d, ", sockfd);

    /* Print buffer content (second parameter) */
    if (retval > 0) {
        char buffer[RECVFROM_BUFFER_SIZE];
        /* Determine the length of buffer content to display */
        size_t bytes_to_read = retval < RECVFROM_BUFFER_SIZE ? retval : RECVFROM_BUFFER_SIZE - 1;
        bytes_to_read = bytes_to_read < RECVFROM_BUFFER_SHOW ? bytes_to_read : RECVFROM_BUFFER_SHOW;
        read_data_from_child(pid, buf, bytes_to_read, buffer, RECVFROM_BUFFER_SIZE);
        print_buffer(buffer, bytes_to_read);
        printf(", %zu, ", len);
    } else {
        printf("%p, %zu, ", buf, len);
    }

    /* Print flags */
    printf("%d, ", flags);

    /* Read source address and address length from the child process */
    if (src_addr && addrlen_ptr) {
        socklen_t addrlen_val = 0;
        errno = 0;
        addrlen_val = ptrace(PTRACE_PEEKDATA, pid, addrlen_ptr, NULL);
        if (errno != 0) {
            perror("ptrace PEEKDATA addrlen");
            addrlen_val = 0;
        }

        if (addrlen_val > 0 && addrlen_val <= sizeof(struct sockaddr_storage)) {
            struct sockaddr_storage addr_storage;
            read_sockaddr_from_child(pid, src_addr, addrlen_val, &addr_storage);
            print_sockaddr(&addr_storage, addrlen_val);
        } else {
            printf("NULL, 0");
        }
    } else {
        printf("NULL, 0");
    }

    /* Print the return value */
    printf(") = %ld\n", retval);
}


/* Generic system call handler that outputs any system call's parameters and results */
void handle_generic_syscall(const char *name, const struct user_regs_struct *regs)
{
    printf("%s(%lld, %lld, %lld) = ",
           name,
           (long long)regs->rdi,
           (long long)regs->rsi,
           (long long)regs->rdx);
}
