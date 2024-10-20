#ifndef __EXAMPLES_CLIENT_H__
#define __EXAMPLES_CLIENT_H__

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
#include <sys/time.h>
#include <math.h>
#include <float.h>

#define MAX_EVENTS 512
#define DEFAULT_PORT 5050
#define DEFAULT_PACKET_SIZE 128
#define BUSSINESS_MESSAGE_SIZE                  26
#define USER_BUFFER_SIZE (1024 * 1024)  // 1MB user buffer for each connection
#define USER_BUFFER_PKT_NUM (5)
#define BYTES_PER_MB ((double)(1024 * 1024))
#define PERF_INFO_PRINT_INTERVAl (5)

#define PRINT_CLIENT(format, ...)           do \
                                            { \
                                                printf("<client>: "); \
                                                printf(format, ##__VA_ARGS__); \
                                                printf("\n"); \
                                            } while (0)

struct ClientInfo {
    char ip_address[INET_ADDRSTRLEN];
    uint32_t port;
    uint32_t pktlen;
    uint32_t socket_num;
    uint32_t msg_idx;
    bool verify;
};

struct PerformanceMetrics {
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
    uint64_t total_messages_sent;
    uint64_t total_messages_received;
    struct timeval start_time;
    struct timeval end_time;
    double min_latency;
    double max_latency;
    double total_latency;
};

struct Connection {
    int fd;
    char *user_buffer;
    size_t buffer_size;
    size_t data_len;
    struct timeval last_send_time;
};
// the lower charactors of business message
static const char bussiness_messages_low[] = "abcdefghijklmnopqrstuvwxyz";
// the capital charactors of business message
static const char bussiness_messages_cap[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

#endif // __EXAMPLES_CLIENT_H__
