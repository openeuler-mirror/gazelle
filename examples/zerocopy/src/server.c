#include "server.h"
#include "lstack_zc_api.h"

/* read by specify api */
int32_t read_api(int32_t fd, void *buffer_in, const uint32_t length, const char *api)
{
    if (strcmp(api, "readwrite") == 0) {
        return read(fd, buffer_in, length);
    } else if (strcmp(api, "zerocopy_readwrite") == 0) {
        return zc_read(fd, buffer_in, length);
    } else if (strcmp(api, "recvsend") == 0) {
        return recv(fd, buffer_in, length, 0);
    } else if (strcmp(api, "zerocopy_recvsend") == 0) {
        return zc_recv(fd, buffer_in, length, 0);
    } else {
        PRINT_ERROR("invaild read api");
    }
    return PROGRAM_FAULT;
}

/* write by specify api */
int32_t write_api(int32_t fd, void *buffer_out, const uint32_t length, const char *api)
{
    if (strcmp(api, "readwrite") == 0) {
        return write(fd, buffer_out, length);
    } else if (strcmp(api, "zerocopy_readwrite") == 0) {
        return zc_write(fd, buffer_out, length);
    } else if (strcmp(api, "recvsend") == 0) {
        return send(fd, buffer_out, length, 0);
    } else if (strcmp(api, "zerocopy_recvsend") == 0) {
        return zc_send(fd, buffer_out, length, 0);
    } else {
        PRINT_ERROR("invaild write api");
    }
    return PROGRAM_FAULT;
}

static int32_t server_ans_read(int32_t socket_fd, struct ServerInfo *server_unit, void *buffer_in)
{
    const uint32_t length = server_unit->pktlen;
    const char *api = server_unit->api;

    int32_t cread = 0;
    int32_t sread = length;
    int32_t nread = 0;

    uint32_t len = sizeof(struct sockaddr_in);

    while (cread < sread) {
        nread = read_api(socket_fd, buffer_in, length, api);
        if (nread == 0) {
            return PROGRAM_ABORT;
        } else if (nread < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN) {
                PRINT_ERROR("nread =%d, errno=%d", nread, errno);
                return PROGRAM_FAULT;
            }
        } else {
            cread += nread;
            continue;
        }
    }
    return PROGRAM_OK;
}

static int32_t server_ans_write(int32_t socket_fd, struct ServerInfo *server_unit, void *buffer_out)
{
    const uint32_t length = server_unit->pktlen;
    const char *api = server_unit->api;

    int32_t cwrite = 0;
    int32_t swrite = length;
    int32_t nwrite = 0;
    uint32_t len = sizeof(struct sockaddr_in);

    while (cwrite < swrite) {
        nwrite = write_api(socket_fd, buffer_out, swrite - cwrite, api);
        if (nwrite == 0) {
            return PROGRAM_ABORT;
        } else if (nwrite < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN) {
                PRINT_ERROR("nwrite =%d, errno=%d", nwrite, errno);
                return PROGRAM_FAULT;
            }
        } else {
            cwrite += nwrite;
            continue;
        }
    }
    return PROGRAM_OK;
}

/* create socket */
static int32_t server_create_sock(uint8_t protocol_mode, struct ServerInfo * server_unit)
{
    bool ret = true;
    /* UDP or TCP socket */
    if (protocol_mode == V4_TCP) {
        server_unit->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    } else if (protocol_mode == V4_UDP) {
        server_unit->listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    } else {
        PRINT_ERROR("invalid protocol mode");
    }

    if (server_unit->listen_fd < 0) {
        PRINT_ERROR("can't create socket errno=%d! ", errno);
        ret = false;
        return PROGRAM_FAULT;
    }

    if (!ret) {
        for (int32_t i = 0; i < PROTOCOL_MODE_MAX; i++) {
            if (server_unit->listen_fd > 0) {
                close(server_unit->listen_fd);
            }
        }
        return PROGRAM_FAULT;
    }

    return PROGRAM_OK;
}

static int32_t set_socket_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl get");
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl set");
        return -1;
    }

    return PROGRAM_OK;
}

static int32_t add_socket_to_epoll(struct ServerInfo *server_unit)
{
    struct sockaddr_in server_addr;
    struct epoll_event ev;
    int len;

    if (server_unit->listen_fd <= 0) {
        PRINT_ERROR("listen_fd is invalid.\n");
        return PROGRAM_FAULT;
    }

    /* Set up non-blocking */
    if (set_socket_nonblocking(server_unit->listen_fd) < 0) {
        PRINT_ERROR("can't set socket to non-blocking! ");
        return PROGRAM_FAULT;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_unit->ip_address);
    server_addr.sin_port = htons(server_unit->port);

    len = sizeof(struct sockaddr_in);

    if (bind(server_unit->listen_fd, (struct sockaddr *)&server_addr, len) < 0) {
        PRINT_ERROR("can't bind address! errno=%d\n", errno);
        return PROGRAM_FAULT;
    }

    if (server_unit->protocol == V4_TCP) {
        if (listen(server_unit->listen_fd, SERVER_SOCKET_LISTEN_BACKLOG) < 0) {
            PRINT_ERROR("server socket can't listen! errno=%d\n", errno);
            return PROGRAM_FAULT;
        }
    }

    /* ET mode */
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = server_unit->listen_fd;
    if (epoll_ctl(server_unit->epfd, EPOLL_CTL_ADD, server_unit->listen_fd, &ev) == -1) {
        perror("epoll_ctl: listen_sock");
        return PROGRAM_FAULT;
    }

    return PROGRAM_OK;
}

static void serverinfo_default_init(struct ServerInfo *serverinfo)
{
    serverinfo->curr_connect = DEFAULT_CURRENT_CONNECT;
    strncpy(serverinfo->ip_address, DEFAULT_SERVER_IP, INET_ADDRSTRLEN - 1);
    serverinfo->port = DEFAULT_PORT;
    serverinfo->pktlen = DEFAULT_PKLEN;
    serverinfo->domain = DEFAULT_DOMAIN;
    serverinfo->api = DEFAULT_API;
    serverinfo->debug = DEFAULT_DEBUG;
    serverinfo->listen_fd = -1;
    serverinfo->protocol = 0;
}

static void server_bussiness(char *out, const char *in, uint32_t size)
{
    char diff = 'a' - 'A';
    for (uint32_t i = 0; i < strlen(in) && i < size; ++i) {
        if (in[i] != '\0') {
            out[i] = in[i] - diff;
        } else {
            out[i] = '\0';
        }
    }
}

static void server_bussiness_pbuf_in(char *out, void *in, uint32_t size)
{
    char diff = 'a' - 'A';
    uint32_t out_idx = 0; 
    struct pbuf *pbuf_in = (struct pbuf *)in;

    if (pbuf_in == NULL || pbuf_get_tot_len(pbuf_in) < size) {
        return;
    }

    while (pbuf_in != NULL && size > 0) {
        uint32_t pbuf_len = pbuf_get_len(pbuf_in);
        uint32_t len_to_process = (pbuf_len < size) ? pbuf_len : size;
        char *payload_char = (char *)pbuf_get_payload(pbuf_in);

        for (uint32_t i = 0; i < len_to_process; ++i) {
            if (payload_char[i] != '\0') {
                /* server bussiness */
                out[out_idx++] = payload_char[i] - diff;
            } else {
                out[out_idx++] = '\0';
            }
        }

        size -= len_to_process;
        pbuf_in = pbuf_get_next(pbuf_in);
    }

    if (size > 0) {
        out[out_idx] = '\0';
    }
}

static int32_t server_ans(struct ServerInfo *server_unit, uint32_t fd)
{
    const uint32_t length = server_unit->pktlen;
    char *buffer_in = (char *)calloc(length, sizeof(char));
    char *buffer_out = (char *)calloc(length, sizeof(char));

    if (buffer_in == NULL || buffer_out == NULL) {
        return PROGRAM_FAULT;
    }

    if (server_ans_read(fd, server_unit, buffer_in) != PROGRAM_OK) {
        free(buffer_in);
        free(buffer_out);
        return PROGRAM_FAULT;
    }

    server_bussiness(buffer_out, buffer_in, length);

    if (server_ans_write(fd, server_unit, buffer_out) != PROGRAM_OK) {
        free(buffer_in);
        free(buffer_out);
        return PROGRAM_FAULT;
    }
//     PRINT_SERVER("[fd: %d len: %d]send: %s", fd, (int)strlen(buffer_out), buffer_out);

    free(buffer_in);
    free(buffer_out);

    return PROGRAM_OK;
}

/* server answers for zero copy */
static int32_t server_ans_zero_copy(struct ServerInfo *server_unit, uint32_t fd)
{
    const size_t length = server_unit->pktlen;
    struct pbuf *pbuf_in = NULL;
    char *buffer_out = (char *)calloc(length, sizeof(char));
    if (buffer_out == NULL) {
        return PROGRAM_FAULT;
    }

    if (server_ans_read(fd, server_unit, &pbuf_in) != PROGRAM_OK) {
        if (gazelle_free(fd, pbuf_in, length) != 0) {
            printf("unknown arguments");
        }
        free(buffer_out);
        return PROGRAM_FAULT;
    }

    server_bussiness_pbuf_in(buffer_out, pbuf_in, length);

    if (server_ans_write(fd, server_unit, buffer_out) != PROGRAM_OK) {
        if (gazelle_free(fd, pbuf_in, length) != 0) {
            printf("unknown arguments");
        }
        free(buffer_out);
        return PROGRAM_FAULT;
    }
//     PRINT_SERVER("[fd: %d len: %d]send: %s", fd, (int)strlen(buffer_out), buffer_out);

    if (gazelle_free(fd, pbuf_in, length) != 0) {
        printf("unknown arguments");
    }
    free(buffer_out);

    return PROGRAM_OK;
}

static void server_run(struct ServerInfo *server_unit)
{
    struct epoll_event ev, events[MAX_EVENTS];
    int nfds;

    server_unit->epfd = epoll_create1(0);
    if (server_unit->epfd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    if (server_create_sock(V4_TCP, server_unit) != PROGRAM_OK) {
        PRINT_ERROR("can't create socket\n");
        return;
    }

    if (add_socket_to_epoll(server_unit) != PROGRAM_OK) {
        PRINT_ERROR("socket add epoll error\n");
        return;
    }

    // server event loop
    while (true) {
        nfds = epoll_wait(server_unit->epfd, events, MAX_EVENTS, -1);  // wait events
        if (nfds == -1) {
            perror("epoll_wait");
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; ++n) {
            if (events[n].events & EPOLLIN) {
                if (events[n].data.fd == server_unit->listen_fd) {
                    /* new connection */
                    int conn_sock;
                    while ((conn_sock = accept(events[n].data.fd, NULL, NULL)) != -1) {
                        printf("New connection accepted: %d\n", conn_sock);
                        set_socket_nonblocking(conn_sock);

                        ev.events = EPOLLIN | EPOLLET;
                        ev.data.fd = conn_sock;
                        if (epoll_ctl(server_unit->epfd, EPOLL_CTL_ADD, conn_sock, &ev) == -1) {
                            perror("epoll_ctl: conn_sock");
                            exit(EXIT_FAILURE);
                        }
                    }
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("accept");
                    }
                } else {
                    if(strcmp(server_unit->api, "readwrite") == 0 ||
                       strcmp(server_unit->api, "recvsend") == 0) {
                        server_ans(server_unit, events[n].data.fd);
                    } else {
                        server_ans_zero_copy(server_unit, events[n].data.fd);
                    }
                }
            }
        }
    }
}

void parse_arguments(int argc, char *argv[], struct ServerInfo *server)
{
    int opt;
    while ((opt = getopt(argc, argv, "A:i:P:")) != -1) {
        switch (opt) {
        case 'A':
            server->api = strdup(optarg);
            if (server->api == NULL) {
                perror("strdup");
                exit(EXIT_FAILURE);
            }
            break;
        case 'i':
            strncpy(server->ip_address, optarg, INET_ADDRSTRLEN - 1);
            server->ip_address[INET_ADDRSTRLEN - 1] = '\0';
            break;
        case 'P':
            server->pktlen = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s -A api -i ipv4 -P pktlen\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[])
{
    struct ServerInfo *server = (struct ServerInfo *)malloc(sizeof(struct ServerInfo));
    memset(server, 0, sizeof(struct ServerInfo));
    serverinfo_default_init(server);

    parse_arguments(argc, argv, server);

    server_run(server);
    free(server);

    return PROGRAM_OK;
}