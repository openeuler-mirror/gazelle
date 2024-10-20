#include "client.h"
struct PerformanceMetrics global_metrics = {0};

void init_performance_metrics()
{
    global_metrics.total_bytes_sent = 0;
    global_metrics.total_bytes_received = 0;
    global_metrics.total_messages_sent = 0;
    global_metrics.total_messages_received = 0;
    global_metrics.min_latency = DBL_MAX;
    global_metrics.max_latency = 0;
    global_metrics.total_latency = 0;
    gettimeofday(&global_metrics.start_time, NULL);
}

void update_latency_metrics(struct timeval *send_time, struct timeval *receive_time)
{
    double latency = (receive_time->tv_sec - send_time->tv_sec) * 1000.0 +
                     (receive_time->tv_usec - send_time->tv_usec) / 1000.0;
    
    global_metrics.min_latency = fmin(global_metrics.min_latency, latency);
    global_metrics.max_latency = fmax(global_metrics.max_latency, latency);
    global_metrics.total_latency += latency;
}

void print_performance_metrics(int active_connections)
{
    gettimeofday(&global_metrics.end_time, NULL);
    double elapsed_time = (global_metrics.end_time.tv_sec - global_metrics.start_time.tv_sec) +
                          (global_metrics.end_time.tv_usec - global_metrics.start_time.tv_usec) / 1000000.0;

    printf("\nPerformance Metrics:\n");
    printf("Total time: %.2f seconds\n", elapsed_time);
    printf("Total bytes sent: %lu\n", global_metrics.total_bytes_sent);
    printf("Total bytes received: %lu\n", global_metrics.total_bytes_received);
    printf("Throughput (send): %.2f MB/s\n", global_metrics.total_bytes_sent / BYTES_PER_MB / elapsed_time);
    printf("Throughput (receive): %.2f MB/s\n", global_metrics.total_bytes_received / BYTES_PER_MB / elapsed_time);
    printf("Messages sent: %lu\n", global_metrics.total_messages_sent);
    printf("Messages received: %lu\n", global_metrics.total_messages_received);
    printf("Average latency: %.2f ms\n", global_metrics.total_latency / global_metrics.total_messages_received);
    printf("Min latency: %.2f ms\n", global_metrics.min_latency);
    printf("Max latency: %.2f ms\n", global_metrics.max_latency);
    printf("Active connections: %d\n", active_connections);
}

int32_t client_bussiness(char *out, const char *in, uint32_t size, bool verify, uint32_t *msg_idx)
{
    if (verify == false) {
        for (uint32_t i = 0; i < (size - 1); ++i) {
            out[i] = bussiness_messages_low[(*msg_idx + i) % BUSSINESS_MESSAGE_SIZE];
        }
    } else {
        uint32_t verify_start_idx = (*msg_idx == 0) ? (BUSSINESS_MESSAGE_SIZE - 1) : (*msg_idx - 1);
        for (uint32_t i = 0; i < (size - 1); ++i) {
            if (in[i] != bussiness_messages_cap[(verify_start_idx + i) % BUSSINESS_MESSAGE_SIZE]) {
                return -1;
            }
            out[i] = bussiness_messages_low[(*msg_idx + i) % BUSSINESS_MESSAGE_SIZE];
        }
    }
    out[size - 1] = '\0';

    ++(*msg_idx);
    *msg_idx = (*msg_idx) % BUSSINESS_MESSAGE_SIZE;

    return 0;
}

int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL");
        return -1;
    }

    return 0;
}

int create_and_connect_socket(const char *ip, int port)
{
    int sockfd;
    struct sockaddr_in server_addr;

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    /* Set non-blocking */
    if( set_nonblocking(sockfd) < 0 ) {
        close(sockfd);
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        if (errno != EINPROGRESS) {
            perror("Connect failed");
            close(sockfd);
            return -1;
        }
    }

    return sockfd;
}

static int32_t client_ask_write(struct Connection *conn, const void *buffer_out, size_t len)
{
    size_t remaining_space = USER_BUFFER_SIZE - conn->data_len;
    size_t to_copy = (len < remaining_space) ? len : remaining_space;

    memcpy(conn->user_buffer + conn->data_len, buffer_out, to_copy);
    conn->data_len += to_copy;

    // record send time
    gettimeofday(&conn->last_send_time, NULL);

    // update perf info
    global_metrics.total_bytes_sent += to_copy;
    global_metrics.total_messages_sent++;

    return to_copy;
}

static int32_t client_ask_read(int32_t socket_fd, void* buffer_in, struct ClientInfo *client, struct Connection *conn)
{
    int32_t nread = read(socket_fd, buffer_in, client->pktlen);
    if (nread > 0) {
        // update perf info
        global_metrics.total_bytes_received += nread;
        global_metrics.total_messages_received++;

        // Calculation delay
        struct timeval receive_time;
        gettimeofday(&receive_time, NULL);
        update_latency_metrics(&conn->last_send_time, &receive_time);
    }
    if (nread == 0) {
        return -1;  // Connection closed
    } else if (nread < 0) {
        if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN) {
            PRINT_CLIENT("nread =%d, errno=%d", nread, errno);
            return -1;
        }
        return 0;  // No data available, try again later
    }
    return nread;
}

static int32_t try_flush_buffer(struct Connection *conn)
{
    while (conn->data_len > 0) {
        int32_t nwrite = write(conn->fd, conn->user_buffer, conn->data_len);
        if (nwrite > 0) {
            memmove(conn->user_buffer, conn->user_buffer + nwrite, conn->data_len - nwrite);
            conn->data_len -= nwrite;
        } else if (nwrite == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Buffer is full, try again later
                return 0;
            } else {
                PRINT_CLIENT("write error: %d", errno);
                return -1;
            }
        }
    }
    return 0;
}

/* Client for multiple connections using single thread and epoll */
void client_run(struct ClientInfo *client)
{
    int epfd, nfds, n;
    struct epoll_event ev, events[MAX_EVENTS];
    char *recv_buf = (char *)malloc(client->pktlen * sizeof(char));
    char *send_buf = (char *)malloc(client->pktlen * sizeof(char));
    struct Connection *connections = (struct Connection *)malloc(client->socket_num * sizeof(struct Connection));

    if (connections == NULL || recv_buf == NULL || send_buf == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    epfd = epoll_create1(0);
    if (epfd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < client->socket_num; ++i) {
        connections[i].fd = create_and_connect_socket(client->ip_address, client->port);
        if (connections[i].fd == -1) {
            printf("Failed to create connection %d\n", i);
            continue;
        }

        connections[i].user_buffer = (char *)malloc(client->pktlen * USER_BUFFER_PKT_NUM * sizeof(char));
        connections[i].buffer_size = client->pktlen * USER_BUFFER_PKT_NUM;
        connections[i].data_len = 0;

        if (connections[i].user_buffer == NULL) {
            perror("malloc for user buffer");
            close(connections[i].fd);
            continue;
        }

        ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
        ev.data.ptr = &connections[i];
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, connections[i].fd, &ev) == -1) {
            perror("epoll_ctl: conn_sock");
            close(connections[i].fd);
            free(connections[i].user_buffer);
            continue;
        }

        // Initial message
        client_bussiness(send_buf, recv_buf, client->pktlen, false, &client->msg_idx);
        client_ask_write(&connections[i], send_buf, client->pktlen);
    }

    init_performance_metrics();
    int active_connections = client->socket_num;
    while (true) {
        nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait");
            break;
        }

        for (n = 0; n < nfds; ++n) {
            struct Connection *conn = (struct Connection *)events[n].data.ptr;

            if (events[n].events & EPOLLIN) {
                int32_t bytes_read = client_ask_read(conn->fd, recv_buf, client, conn);
                if (bytes_read > 0) {
                //     PRINT_CLIENT("[fd: %d len: %d]recv: %s", conn->fd, bytes_read, recv_buf);
                    client_bussiness(send_buf, recv_buf, client->pktlen, client->verify, &client->msg_idx);
                    client_ask_write(conn, send_buf, client->pktlen);
                } else if (bytes_read == -1) {
                    // Handle disconnection
                    epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL);
                    close(conn->fd);
                    free(conn->user_buffer);
                    conn->fd = -1;
                    active_connections--;
                }
            }

            if (events[n].events & EPOLLOUT) {
                if (try_flush_buffer(conn) == -1) {
                    // Handle write error
                    epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL);
                    close(conn->fd);
                    free(conn->user_buffer);
                    conn->fd = -1;
                    active_connections--;
                }
            }
        }

        // Print performance metrics every once in a while
        static time_t last_print_time = 0;
        time_t current_time = time(NULL);
        if (current_time - last_print_time >= PERF_INFO_PRINT_INTERVAl) {  // Print every 5 s
            print_performance_metrics(active_connections);
            last_print_time = current_time;
        }

        if (active_connections == 0) {
            break;
        }
    }

    // print finnal performance metrics
    print_performance_metrics(active_connections);

    // Cleanup
    for (int i = 0; i < client->socket_num; ++i) {
        if (connections[i].fd != -1) {
            close(connections[i].fd);
            free(connections[i].user_buffer);
        }
    }
    free(connections);
    free(recv_buf);
    free(send_buf);
    close(epfd);
}

void parse_arguments(int argc, char *argv[], struct ClientInfo *client)
{
    int opt;
    while ((opt = getopt(argc, argv, "i:p:P:n:v:")) != -1) {
        switch (opt) {
            case 'i':
                strncpy(client->ip_address, optarg, INET_ADDRSTRLEN - 1);
                client->ip_address[INET_ADDRSTRLEN - 1] = '\0';
                break;
            case 'p':
                client->port = atoi(optarg);
                break;
            case 'P':
                client->pktlen = atoi(optarg);
                break;
            case 'n':
                client->socket_num = atoi(optarg);
                break;
            case 'v':
                client->verify = true;
                break;
            default:
                fprintf(stderr, "Usage: %s -i ipv4 -p port -P pktlen -n socket_num\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[])
{
    struct ClientInfo *client = (struct ClientInfo *)malloc(sizeof(struct ClientInfo));
    client->verify = false;
    client->msg_idx = 0;
    parse_arguments(argc, argv, client);

    client_run(client);

    return 0;
}
