#ifndef __PERFORMAN_ZEROCOPY_TEST_SERVER_H__
#define __PERFORMAN_ZEROCOPY_TEST_SERVER_H__

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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define DEFAULT_CURRENT_CONNECT (0)
#define DEFAULT_PORT 5050
#define DEFAULT_SERVER_IP "127.0.0.1"
#define DEFAULT_PKLEN 1024
#define DEFAULT_DOMAIN "tcp"
#define DEFAULT_API "readwrite"
#define DEFAULT_DEBUG false
#define DEFAULT_INVALID_LISTEN_FD (-1)

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
                                            } while (0)

#define TIMES_CONVERSION_RATE (1000)
#define KB (1024)
#define MB (KB * KB)
#define GB (MB * MB)

#define PROGRAM_OK                          (0)                 ///< program ok flag
#define PROGRAM_ABORT                       (1)                 ///< program abort flag
#define PROGRAM_FAULT                       (-1)                ///< program fault flag
#define PROGRAM_INPROGRESS                  (-2)                ///< program in progress flag

#define SERVER_SOCKET_LISTEN_BACKLOG        (4096)              ///< the queue of socket
#define MAX_EVENTS                          (512)

/**
 * server test base information
 */
struct ServerInfo {
    uint32_t curr_connect;                  ///< current connection number
    char ip_address[INET_ADDRSTRLEN];       ///< IPv4 address
    uint16_t port;                          ///< server port
    uint32_t pktlen;                        ///< the length of peckage
    char* domain;                           ///< communication domain
    char* api;                              ///< the type of api
    bool debug;                             ///< if we print the debug information
    uint32_t protocol;
    int32_t listen_fd;
    uint32_t epfd;
};

typedef enum {
    V4_TCP,
    V4_UDP,
    PROTOCOL_MODE_MAX
} PROTOCOL_MODE_ENUM_TYPE;

#endif // __PERFORMAN_ZEROCOPY_TEST_SERVER_H__
