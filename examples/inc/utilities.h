/*
* Copyright (c) 2022-2023. yyangoO.
* gazelle is licensed under the Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*     http://license.coscl.org.cn/MulanPSL2
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
* PURPOSE.
* See the Mulan PSL v2 for more details.
*/


#ifndef __EXAMPLES_UTILITIES_H__
#define __EXAMPLES_UTILITIES_H__


#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <inttypes.h>
#include <unistd.h>
#include <ctype.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "securec.h"
#include "securectype.h"
#include "sys/uio.h"


#define PRINT_ERROR(format, ...)            do \
                                            { \
                                                printf("\n[error]: "); \
                                                printf(format, ##__VA_ARGS__); \
                                                printf("\n\n"); \
                                            } while (0)
#define PRINT_WARNNING(format, ...)         do \
                                            { \
                                                printf("\n[warnning]: "); \
                                                printf(format, ##__VA_ARGS__); \
                                                printf("\n"); \
                                            } while (0)
#define PRINT_SERVER(format, ...)           do \
                                            { \
                                                printf("<server>: "); \
                                                printf(format, ##__VA_ARGS__); \
                                                printf("\n"); \
                                            } while(0)
#define PRINT_CLIENT(format, ...)           do \
                                            { \
                                                printf("<client>: "); \
                                                printf(format, ##__VA_ARGS__); \
                                                printf("\n"); \
                                            } while(0)
#define PRINT_SERVER_DATAFLOW(format, ...)  do \
                                            { \
                                                printf("\033[?25l\033[A\033[K"); \
                                                printf("--> <server>: "); \
                                                printf(format, ##__VA_ARGS__); \
                                                printf("\033[?25h\n"); \
                                            } while(0)
#define PRINT_CLIENT_DATAFLOW(format, ...)  do \
                                            { \
                                                printf(" "); \
                                                printf("--> <client>: "); \
                                                printf(format, ##__VA_ARGS__); \
                                                printf("\033[?25h\n"); \
                                            } while(0)
#define LIMIT_VAL_RANGE(val, min, max)      ((val) < (min) ? (min) : ((val) > (max) ? (max) : (val)))
#define CHECK_VAL_RANGE(val, min, max)      ((val) < (min) ? (false) : ((val) > (max) ? (false) : (true)))

#define PROGRAM_OK                          (0)                 ///< program ok flag
#define PROGRAM_ABORT                       (1)                 ///< program abort flag
#define PROGRAM_FAULT                       (-1)                ///< program fault flag
#define PROGRAM_INPROGRESS                  (-2)                ///< program in progress flag

#define UNIX_TCP_PORT_MIN                   (1024)              ///< TCP minimum port number in unix
#define UNIX_TCP_PORT_MAX                   (65535)             ///< TCP maximum port number in unix
#define THREAD_NUM_MIN                      (1)                 ///< minimum number of thead
#define THREAD_NUM_MAX                      (1000)              ///< maximum number of thead
#define MESSAGE_PKTLEN_MIN                  (2)                 ///< minimum length of message (1 byte)
#define MESSAGE_PKTLEN_MAX                  (1024 * 1024 * 10)  ///< maximum length of message (10 Mb)
#define UDP_PKTLEN_MAX                      (65507)             ///< maximum length of udp message

#define SERVER_SOCKET_LISTEN_BACKLOG        (4096)              ///< the queue of socket
#define SERVER_EPOLL_SIZE_MAX               (10000)             ///< the max wait event of epoll
#define SERVER_EPOLL_WAIT_TIMEOUT           (-1)                ///< the timeout value of epoll

#define CLIENT_EPOLL_SIZE_MAX               (10000)             ///< the max wait event of epoll
#define CLIENT_EPOLL_WAIT_TIMEOUT           (-1)                ///< the timeout value of epoll

#define TERMINAL_REFRESH_MS                 (100)               ///< the time cut off between of terminal refresh

#define SOCKET_UNIX_DOMAIN_FILE             "unix_domain_file"  ///< socket unix domain file

#define IPV4_STR "V4"
#define IPV6_STR "V6"
#define IPV4_MULTICAST "Multicast"
#define INVAILD_STR "STR_NULL"

#define TIMES_CONVERSION_RATE (1000)
#define KB (1024)
#define MB (KB * KB)
#define GB (MB * MB)

struct ThreadUintInfo {
    uint64_t send_bytes;                ///< total send bytes
    uint32_t cur_connect_num;           ///< total connection number
    char* domain;
    char* ip_type_info;
    pthread_t thread_id;
};

typedef struct ip_addr {
    struct {
        struct in_addr ip4;
        struct in6_addr ip6;
    } u_addr;
    uint32_t addr_family;
} ip_addr_t;

typedef union sockaddr_union {
    struct sockaddr     sa;
    struct sockaddr_in  in;
    struct sockaddr_in6 in6;
} sockaddr_t;

/**
 * @brief client unit
 * The information of each thread of client.
 */
struct ClientUnit {
    struct ClientHandler *handlers;     ///< the handlers
    int32_t epfd;                       ///< the connect epoll file descriptor
    struct epoll_event *epevs;          ///< the epoll events
    uint32_t curr_connect;              ///< current connection number
    ip_addr_t ip;                       ///< server ip
    ip_addr_t groupip;                  ///< server groupip
    uint32_t port;                      ///< server port
    ip_addr_t groupip_interface;        ///< udp multicast interface address>
    uint32_t sport;                     ///< client sport
    uint32_t connect_num;               ///< total connection number
    uint32_t pktlen;                    ///< the length of peckage
    uint32_t loop;                      ///< the packet send to loop
    bool verify;                        ///< if we verify or not
    char* domain;                       ///< the communication domain
    char* api;                          ///< the type of api
    bool debug;                         ///< if we print the debug information
    char* epollcreate;                  ///< epoll_create method
    uint8_t protocol_type_mode;         ///< tcp/udp ipv4/ipv6 protocol mode
    struct ThreadUintInfo threadVolume;
    struct ClientUnit *next;            ///< next pointer
};
struct ServerIpInfo {
    ip_addr_t ip;                           ///< server ip
    ip_addr_t groupip;                      ///< server group ip
    ip_addr_t groupip_interface;            ///< server group interface ip
};
/**
 * @brief create the socket and listen
 * Thi function creates the socket and listen.
 * @param socket_fd     the socket file descriptor
 * @param ip            ip address
 * @param groupip       group ip address
 * @param port          port number
 * @param domain        domain
 * @return              the result
 */
int32_t create_socket_and_listen(int32_t *listen_fd_array, struct ServerIpInfo *server_ip_info, uint16_t port,
                                 uint8_t protocol_mode);

/**
 * @brief create the socket and connect
 * Thi function creates the socket and connect.
 * @param socket_fd     the socket file descriptor
 * @param ip            ip address
 * @param groupip       group ip address
 * @param port          port number
 * @param domain        domain
 * @param api           api
 * @return              the result
 */
int32_t create_socket_and_connect(int32_t *socket_fd, struct ClientUnit *client_unit);

/**
 * @brief set the socket to unblock
 * Thi function sets the socket to unblock.
 * @param socket_fd     the socket file descriptor
 * @return              the result
 */
int32_t set_socket_unblock(int32_t socket_fd);
int32_t set_tcp_keep_alive_info(int32_t sockfd, int32_t tcp_keepalive_idle, int32_t tcp_keepalive_interval);


#endif // __EXAMPLES_UTILITIES_H__
