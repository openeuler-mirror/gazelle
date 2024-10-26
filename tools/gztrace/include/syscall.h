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

/*
 * syscall.h
 *
 * This header file includes a series of utility functions for formatting and
 * outputting detailed information about various system calls.
 *
 * Features included:
 * - Parsing system call names.
 * - Formatting and outputting socket-related parameters (e.g., domain, type, options).
 * - Handling specific system calls by printing their detailed parameters and execution results.
 *
 * These functionalities are especially useful for developing network monitoring tools
 * or performing system call analysis.
 */

#ifndef GZTRACE_SYSCALL_H
#define GZTRACE_SYSCALL_H

#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <netinet/tcp.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <ctype.h>

/* Returns the name of the system call as a string */
const char* net_syscall_name(long call);

/* Returns a string description of the socket type */
const char* format_type(int type);

/* Returns a string description of the socket domain */
const char* format_domain(int domain);

/* Returns a string description of the protocol */
const char* format_protocol(int protocol);

/* Returns a string description of the socket option level */
const char* format_socket_level(int level);

/* Returns a string description of socket options at SOL_SOCKET level */
const char* format_sol_socket_option(int optname);
/* Returns a string description of socket options at IPPROTO_TCP level */
const char* format_tcp_option(int optname);
/* Returns a string description of socket options at IPPROTO_IP level */
const char* format_ip_option(int optname);
/* Returns a string description of socket options at IPPROTO_IPV6 level */
const char* format_ipv6_option(int optname);
/* Returns a string description of the socket option name */
const char* format_socket_option(int level, int optname);

/* Converts POSIX API error codes to their string representations */
/* Note: This is a non-standard extension provided by GNU C Library (glibc)
   and should be available on openEuler */
const char* strerrorname_np(int errnum);

/* Reads data from child process memory */
size_t read_data_from_child(pid_t pid, char *remote_addr, size_t len, char *local_buffer, size_t buffer_size);
/* Prints buffer content with special character handling */
void print_buffer(const char *buffer, size_t length);
/* Reads sockaddr structure from child process memory */
void read_sockaddr_from_child(pid_t pid, char *remote_addr, socklen_t addrlen,
                              struct sockaddr_storage *local_addr_storage);
/* Prints sockaddr information */
void print_sockaddr(const struct sockaddr_storage *addr_storage, socklen_t addrlen);
/* Handles the socket system call and outputs call details */
void handle_socket(pid_t pid, const struct user_regs_struct *regs);

/* Handles the connect system call and outputs call details */
void handle_connect(pid_t pid, const struct user_regs_struct *regs);

/* Handles the setsockopt system call and outputs call details */
void handle_setsockopt(pid_t pid, const struct user_regs_struct *regs);

/* Handles the bind system call and outputs call details */
void handle_bind(pid_t pid, const struct user_regs_struct *regs);

/* Handles the getsockopt system call and outputs call details */
void handle_getsockopt(pid_t pid, const struct user_regs_struct *regs);


/* Handles the getpeername system call and outputs call details */
void handle_getpeername(pid_t pid, const struct user_regs_struct *regs);

/* Handles the accept system call and outputs call details */
void handle_accept(pid_t pid, const struct user_regs_struct *regs);

/* Handles the socketpair system call and outputs call details */
void handle_socketpair(pid_t pid, const struct user_regs_struct *regs);

/* Handles the getsockname system call and outputs call details */
void handle_getsockname(pid_t pid, const struct user_regs_struct *regs);

/* Handles the recvfrom system call and outputs call details */
void handle_recvfrom(pid_t pid, struct user_regs_struct *regs);

/* Generic system call handler that outputs any system call's parameters and results */
void handle_generic_syscall(const char *name, const struct user_regs_struct *regs);

/* Converts flags to their string representations */
const char* flags_to_string(int flags);

/* Handles the sendto system call and outputs call details */
void handle_sendto(pid_t pid, struct user_regs_struct *regs);
/* Handles the recvfrom system call and outputs call details */
void handle_recvfrom(pid_t pid, struct user_regs_struct *regs);
/* Buffer sizes for recvfrom and sendto */
#define RECVFROM_BUFFER_SIZE 1024 /* Buffer size for handle_recvfrom */
#define RECVFROM_BUFFER_SHOW 32   /* Length of recvfrom buffer content to display */
#define SENDTO_BUFFER_SIZE 1024
#define SENDTO_BUFFER_SHOW 256

/**
 * @brief Checks if a specific flag is set in the provided 'flags' variable.
 *        If the flag is set, appends its string representation to the 'buffer',
 *        adds a separator if necessary, marks that it's no longer the first flag,
 *        and clears the flag from 'flags'.
 *
 * @param flag      The flag to check and process.
 * @param flag_name The string representation of the flag name.
 * @param flags     A pointer to the variable containing the flags to check.
 * @param first     A pointer to the flag indicating whether this is the first flag being processed.
 * @param buffer    The buffer to which flag names are appended.
 */
static inline void check_flag(int flag, const char *flag_name, int *flags, int *first, char *buffer)
{
    if ((*flags & flag) != 0) {
        if (!(*first)) {
            strcat(buffer, "|");
        }
        strcat(buffer, flag_name);
        *first = 0;
        *flags &= ~flag;
    }
}
#endif /* GZTRACE_SYSCALL_H */
