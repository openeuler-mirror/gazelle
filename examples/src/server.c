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


#include "server.h"

static pthread_mutex_t server_debug_mutex;      // the server mutex for debug

// server debug information print
void server_debug_print(const char *ch_str, const char *act_str, ip_addr_t *ip, uint16_t port, bool debug)
{
    if (debug == true) {
        pthread_mutex_lock(&server_debug_mutex);
        uint8_t str_len = ip->addr_family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
        char str_ip[str_len];
        inet_ntop(ip->addr_family, &ip->u_addr, str_ip, str_len);
        PRINT_SERVER("[%s] [pid: %d] [tid: %ld] [%s <- %s:%d]. ", \
                    ch_str, \
                    getpid(), \
                    pthread_self(), \
                    act_str, \
                    str_ip, \
                    ntohs(port));
        pthread_mutex_unlock(&server_debug_mutex);
    }
}

// the multi thread, unblock, dissymmetric server prints informations
void sermud_info_print(struct ServerMud *server_mud)
{
    if (server_mud->debug == false) {
        uint32_t curr_connect = 0;

        struct timeval begin;
        gettimeofday(&begin, NULL);
        uint64_t begin_time = (uint64_t)begin.tv_sec * 1000 + (uint64_t)begin.tv_usec / 1000;

        double bytes_ps = 0;
        uint64_t begin_recv_bytes = 0;
        struct ServerMudWorker *begin_uint = server_mud->workers;
        while (begin_uint != NULL) {
            begin_recv_bytes += begin_uint->recv_bytes;
            curr_connect += begin_uint->curr_connect;
            begin_uint = begin_uint->next;
        }

        struct timeval delay;
        delay.tv_sec = 0;
        delay.tv_usec = TERMINAL_REFRESH_MS * 1000;
        select(0, NULL, NULL, NULL, &delay);

        uint64_t end_recv_bytes = 0;
        struct ServerMudWorker *end_uint = server_mud->workers;
        while (end_uint != NULL) {
            end_recv_bytes += end_uint->recv_bytes;
            end_uint = end_uint->next;
        }

        struct timeval end;
        gettimeofday(&end, NULL);
        uint64_t end_time = (uint64_t)end.tv_sec * 1000 + (uint64_t)end.tv_usec / 1000;
        
        double bytes_sub = end_recv_bytes > begin_recv_bytes ? (double)(end_recv_bytes - begin_recv_bytes) : 0;
        double time_sub = end_time > begin_time ? (double)(end_time - begin_time) / 1000 : 0;

        bytes_ps = bytes_sub  / time_sub;

        if (bytes_ps < 1024) {
            PRINT_SERVER_DATAFLOW("[connect num]: %d, [receive]: %.3f B/s", curr_connect, bytes_ps);
        } else if (bytes_ps < (1024 * 1024)) {
            PRINT_SERVER_DATAFLOW("[connect num]: %d, [receive]: %.3f KB/s", curr_connect, bytes_ps / 1024);
        } else {
            PRINT_SERVER_DATAFLOW("[connect num]: %d, [receive]: %.3f MB/s", curr_connect, bytes_ps / (1024 * 1024));
        }
    }
}

// the worker thread, unblock, dissymmetric server listens and gets epoll feature descriptors
int32_t sermud_worker_create_epfd_and_reg(struct ServerMudWorker *worker_unit)
{
    if (strcmp(worker_unit->epollcreate, "ec1") == 0) {
        worker_unit->epfd = epoll_create1(EPOLL_CLOEXEC);
    } else {
        worker_unit->epfd = epoll_create(SERVER_EPOLL_SIZE_MAX);
    }
    
    if (worker_unit->epfd < 0) {
       PRINT_ERROR("server can't create epoll %d! ", worker_unit->epfd);
       return PROGRAM_FAULT;
    }

    struct epoll_event ep_ev;
    ep_ev.data.ptr = (void *)&(worker_unit->worker);
    ep_ev.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(worker_unit->epfd, EPOLL_CTL_ADD, worker_unit->worker.fd, &ep_ev) < 0) {
        PRINT_ERROR("server can't control epoll %d! ", errno);
        return PROGRAM_FAULT;
    }

    return PROGRAM_OK;
}

// the listener thread, unblock, dissymmetric server listens and gets epoll feature descriptors
int32_t sermud_listener_create_epfd_and_reg(struct ServerMud *server_mud)
{
    if (strcmp(server_mud->epollcreate, "ec1") == 0) {
        server_mud->epfd = epoll_create1(EPOLL_CLOEXEC);
    } else {
        server_mud->epfd = epoll_create(SERVER_EPOLL_SIZE_MAX);
    }
    
    if (server_mud->epfd < 0) {
       PRINT_ERROR("server can't create epoll %d! ", server_mud->epfd);
       return PROGRAM_FAULT;
    }

    struct epoll_event ep_ev;
    ep_ev.events = EPOLLIN | EPOLLET;
    for (int i = 0; i < PROTOCOL_MODE_MAX; i++) {
        if (server_mud->listener.listen_fd_array[i] != -1) {
            struct ServerHandler *server_handler = (struct ServerHandler *)malloc(sizeof(struct ServerHandler));
            memset_s(server_handler, sizeof(struct ServerHandler), 0, sizeof(struct ServerHandler));
            server_handler->fd = server_mud->listener.listen_fd_array[i];
            ep_ev.data.ptr = (void *)server_handler;
            if (epoll_ctl(server_mud->epfd, EPOLL_CTL_ADD, server_mud->listener.listen_fd_array[i], &ep_ev) < 0) {
                PRINT_ERROR("epoll_ctl failed %d! listen_fd=%d ", errno, server_mud->listener.listen_fd_array[i]);
                return PROGRAM_FAULT;
            }
        }
    }

    return PROGRAM_OK;
}

static void sermud_accept_get_remote_ip(sockaddr_t *accept_addr, ip_addr_t *remote_ip, bool is_tcp_v6_flag)
{
    remote_ip->addr_family = is_tcp_v6_flag ? AF_INET6 : AF_INET;
    if (is_tcp_v6_flag == false) {
        remote_ip->u_addr.ip4 = ((struct sockaddr_in *)accept_addr)->sin_addr;
    } else {
        remote_ip->u_addr.ip6 = ((struct sockaddr_in6 *)accept_addr)->sin6_addr;
    }
}

int32_t sermud_set_socket_opt(int32_t accept_fd, struct ServerMud *server_mud)
{
    if (set_tcp_keep_alive_info(accept_fd, server_mud->tcp_keepalive_idle, server_mud->tcp_keepalive_interval) < 0) {
        PRINT_ERROR("cant't set_tcp_keep_alive_info! ");
        return PROGRAM_FAULT;
    }

    if (set_socket_unblock(accept_fd) < 0) {
        PRINT_ERROR("server can't set the connect socket to unblock! ");
        return PROGRAM_FAULT;
    }
    return PROGRAM_OK;
}

// the listener thread, unblock, dissymmetric server accepts the connections
int32_t sermud_listener_accept_connects(struct epoll_event *curr_epev, struct ServerMud *server_mud)
{
    int32_t fd = ((struct ServerHandler*)(curr_epev->data.ptr))->fd;
    fault_inject_delay(INJECT_DELAY_ACCEPT);

    while (true) {
        sockaddr_t accept_addr;
        bool is_tcp_v6_flag = (fd == server_mud->listener.listen_fd_array[V6_TCP]) ? true : false;

        uint32_t sockaddr_in_len = is_tcp_v6_flag ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

        int32_t accept_fd;

        int32_t listen_fd_index = is_tcp_v6_flag ? V6_TCP : V4_TCP;
        int32_t listen_fd = server_mud->listener.listen_fd_array[listen_fd_index];

        if (strcmp(server_mud->accept, "ac4") == 0) {
            accept_fd = accept4(listen_fd, (struct sockaddr *)&accept_addr, &sockaddr_in_len, SOCK_CLOEXEC);
        } else {
            accept_fd = accept(listen_fd, (struct sockaddr *)&accept_addr, &sockaddr_in_len);
        }

        if (accept_fd < 0) {
            break;
        }

        if (sermud_set_socket_opt(accept_fd, server_mud) < 0) {
            return PROGRAM_FAULT;
        }

        // sockaddr to ip, port
        ip_addr_t remote_ip;
        uint16_t remote_port = ((struct sockaddr_in *)&accept_addr)->sin_port;
        sermud_accept_get_remote_ip(&accept_addr, &remote_ip, is_tcp_v6_flag);

        pthread_t *tid = (pthread_t *)malloc(sizeof(pthread_t));
        struct ServerMudWorker *worker = (struct ServerMudWorker *)malloc(sizeof(struct ServerMudWorker));
        worker->worker.fd = accept_fd;
        worker->epfd = -1;
        worker->epevs = (struct epoll_event *)malloc(sizeof(struct epoll_event));
        worker->recv_bytes = 0;
        worker->pktlen = server_mud->pktlen;
        worker->ip = remote_ip;
        worker->port = remote_port;
        worker->api = server_mud->api;
        worker->debug = server_mud->debug;
        worker->next = server_mud->workers;
        worker->epollcreate = server_mud->epollcreate;
        worker->worker.is_v6 = is_tcp_v6_flag ? 1 : 0;
        worker->domain = server_mud->domain;
        worker->curr_connect = 1;

        server_mud->workers = worker;

        if (pthread_create(tid, NULL, sermud_worker_create_and_run, worker) < 0) {
            PRINT_ERROR("server can't create poisx thread %d! ", errno);
            return PROGRAM_FAULT;
        }

        server_debug_print("server mud listener", "accept", &remote_ip, remote_port, server_mud->debug);
    }

    return PROGRAM_OK;
}

static int32_t server_handler_close(int32_t epfd, struct ServerHandler *server_handler)
{
    int32_t fd = server_handler->fd;
    struct epoll_event ep_ev;
    if (server_handler) {
        free(server_handler);
    }

    if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ep_ev) < 0) {
        PRINT_ERROR("server can't delete socket '%d' to control epoll %d! ", fd, errno);
        return PROGRAM_FAULT;
    }

    if (close(fd) < 0) {
        PRINT_ERROR("server can't close the socket %d! ", errno);
        return PROGRAM_FAULT;
    }

    return 0;
}

// the worker thread, unblock, dissymmetric server processes the events
int32_t sermud_worker_proc_epevs(struct ServerMudWorker *worker_unit, const char* domain)
{
    int32_t epoll_nfds = epoll_wait(worker_unit->epfd, worker_unit->epevs, SERVER_EPOLL_SIZE_MAX, SERVER_EPOLL_WAIT_TIMEOUT);
    if (epoll_nfds < 0) {
        PRINT_ERROR("server epoll wait error %d! ", errno);
        return PROGRAM_FAULT;
    }

    for (int32_t i = 0; i < epoll_nfds; ++i) {
        struct epoll_event *curr_epev = worker_unit->epevs + i;

        if (curr_epev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
            worker_unit->curr_connect--;
            PRINT_ERROR("server epoll wait error %d! ", curr_epev->events);
            if (server_handler_close(worker_unit->epfd, (struct ServerHandler *)curr_epev->data.ptr) != 0) {
                return PROGRAM_FAULT;
            }
        }

        if (curr_epev->events == EPOLLIN) {
            struct ServerHandler *server_handler = (struct ServerHandler *)curr_epev->data.ptr;

            int32_t server_ans_ret = server_ans(server_handler->fd, worker_unit->pktlen, worker_unit->api, "tcp");
            if (server_ans_ret == PROGRAM_FAULT) {
                worker_unit->curr_connect--;
                if (server_handler_close(worker_unit->epfd, server_handler) != 0) {
                    return PROGRAM_FAULT;
                }
            } else if (server_ans_ret == PROGRAM_ABORT) {
                worker_unit->curr_connect--;
                server_debug_print("server mud worker", "close", &worker_unit->ip, worker_unit->port, worker_unit->debug);
                if (server_handler_close(worker_unit->epfd, server_handler) != 0) {
                    return PROGRAM_FAULT;
                }
            } else {
                worker_unit->recv_bytes += worker_unit->pktlen;
                server_debug_print("server mud worker", "receive", &worker_unit->ip, worker_unit->port, worker_unit->debug);
            }
        }
    }

    return PROGRAM_OK;
}

static int32_t sermud_process_epollin_event(struct epoll_event *curr_epev, struct ServerMud *server_mud)
{
    struct ServerHandler *server_handler = (struct ServerHandler *)curr_epev->data.ptr;

    if (server_handler->fd == server_mud->listener.listen_fd_array[V4_UDP] ||
        server_handler->fd == server_mud->listener.listen_fd_array[UDP_MULTICAST]) {
        uint32_t pktlen = server_mud->pktlen > UDP_PKTLEN_MAX ? UDP_PKTLEN_MAX : server_mud->pktlen;
        int32_t server_ans_ret = server_ans(server_handler->fd, pktlen, server_mud->api, "udp");
        if (server_ans_ret != PROGRAM_OK) {
            if (server_handler_close(server_mud->epfd, server_handler) != 0) {
                PRINT_ERROR("server_handler_close server_ans_ret %d! \n", server_ans_ret);
                return PROGRAM_FAULT;
            }
        }
        server_mud->workers->recv_bytes += pktlen;
    } else {
        int32_t sermud_listener_accept_connects_ret = sermud_listener_accept_connects(curr_epev, server_mud);
        if (sermud_listener_accept_connects_ret < 0) {
            PRINT_ERROR("server try accept error %d! ", sermud_listener_accept_connects_ret);
            return PROGRAM_FAULT;
        }
    }

    return PROGRAM_OK;
}

// the listener thread, unblock, dissymmetric server processes the events
int32_t sermud_listener_proc_epevs(struct ServerMud *server_mud)
{
    int32_t epoll_nfds = epoll_wait(server_mud->epfd, server_mud->epevs, SERVER_EPOLL_SIZE_MAX, SERVER_EPOLL_WAIT_TIMEOUT);
    if (epoll_nfds < 0) {
        PRINT_ERROR("server epoll wait error %d! ", errno);
        return PROGRAM_FAULT;
    }

    for (int32_t i = 0; i < epoll_nfds; ++i) {
        struct epoll_event *curr_epev = server_mud->epevs + i;
    
        if (curr_epev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
            PRINT_ERROR("server epoll wait error %d! ", curr_epev->events);
            server_handler_close(server_mud->epfd, (struct ServerHandler *)curr_epev->data.ptr);
            return PROGRAM_OK;
        }

        if (curr_epev->events == EPOLLIN) {
            if (sermud_process_epollin_event(curr_epev, server_mud) < 0) {
                return PROGRAM_FAULT;
            }
        }
    }

    return PROGRAM_OK;
}

// create the worker thread, unblock, dissymmetric server and run
void *sermud_worker_create_and_run(void *arg)
{
    pthread_detach(pthread_self());

    struct ServerMudWorker *worker_unit = (struct ServerMudWorker *)arg;
    char *domain = worker_unit->domain;

    if (sermud_worker_create_epfd_and_reg(worker_unit) < 0) {
        return (void *)PROGRAM_OK;
    }
    while (true) {
        if (sermud_worker_proc_epevs(worker_unit, domain) < 0) {
            return (void *)PROGRAM_OK;
        }
    }

    close(worker_unit->worker.fd);
    close(worker_unit->epfd);

    return (void *)PROGRAM_OK;
}

void sermud_memory_recycle(struct ServerMud *server_mud)
{
    // recycle mem of epevs
    if (server_mud->epevs) {
        free(server_mud->epevs);
    }
    struct ServerMudWorker *head = server_mud->workers;
    while (head) {
        if (head->epevs) {
            free(head->epevs);
        }
        struct ServerMudWorker *next = head->next;
        free(head);
        head = next;
    }
}

// create the listener thread, unblock, dissymmetric server and run
void *sermud_listener_create_and_run(void *arg)
{
    struct ServerMud *server_mud = (struct ServerMud *)arg;

    uint32_t port = 0;
    for (; port < UNIX_TCP_PORT_MAX; port++) {
        if ((server_mud->port)[port]) {
            if (create_socket_and_listen(server_mud->listener.listen_fd_array, &(server_mud->server_ip_info),
                                         htons(port), server_mud->protocol_type_mode) < 0) {
                PRINT_ERROR("create_socket_and_listen err");
                sermud_memory_recycle(server_mud);
                exit(PROGRAM_FAULT);
            }
        }
    }

    if (sermud_listener_create_epfd_and_reg(server_mud) < 0) {
        sermud_memory_recycle(server_mud);
        exit(PROGRAM_FAULT);
    }
    while (true) {
        if (sermud_listener_proc_epevs(server_mud) < 0) {
            sermud_memory_recycle(server_mud);
            exit(PROGRAM_FAULT);
        }
    }

    for (int i = 0; i < PROTOCOL_MODE_MAX; i++) {
        if (server_mud->listener.listen_fd_array[i] == -1)
            continue;
        if (close(server_mud->listener.listen_fd_array[i]) < 0) {
            sermud_memory_recycle(server_mud);
            exit(PROGRAM_FAULT);
        }
    }
    sermud_memory_recycle(server_mud);
    return (void *)PROGRAM_OK;
}

// create the multi thread, unblock, dissymmetric server and run
int32_t sermud_create_and_run(struct ProgramParams *params)
{
    pthread_t *tid = (pthread_t *)malloc(sizeof(pthread_t));
    struct ServerMud *server_mud = (struct ServerMud *)malloc(sizeof(struct ServerMud));

    if (pthread_mutex_init(&server_debug_mutex, NULL) < 0) {
        PRINT_ERROR("server can't init posix mutex %d! ", errno);
        return PROGRAM_FAULT;
    }

    server_mud->listener.fd = -1;
    for (int32_t i = 0; i < PROTOCOL_MODE_MAX; i++) {
        server_mud->listener.listen_fd_array[i] = -1;
    }

    struct ServerMudWorker *workers = (struct ServerMudWorker *)malloc(sizeof(struct ServerMudWorker));
    if (workers == NULL) {
        PRINT_ERROR("malloc truct ServerMudWorker failed ");
        return PROGRAM_FAULT;
    }
    memset_s(workers, sizeof(struct ServerMudWorker), 0, sizeof(struct ServerMudWorker));
    workers->next = NULL;
    server_mud->workers = workers;

    server_mud->epfd = -1;
    server_mud->epevs = (struct epoll_event *)malloc(SERVER_EPOLL_SIZE_MAX * sizeof(struct epoll_event));
    server_mud->server_ip_info.ip.addr_family = params->addr_family;

    inet_pton(AF_INET, params->ip, &server_mud->server_ip_info.ip.u_addr.ip4);
    inet_pton(AF_INET6, params->ipv6, &server_mud->server_ip_info.ip.u_addr.ip6);

    server_mud->server_ip_info.groupip.addr_family = params->addr_family;
    inet_pton(AF_INET, params->groupip, &server_mud->server_ip_info.groupip.u_addr);

    server_mud->server_ip_info.groupip_interface.addr_family = params->addr_family;
    inet_pton(AF_INET, params->groupip_interface, &server_mud->server_ip_info.groupip_interface.u_addr);

    server_mud->port = params->port;
    server_mud->pktlen = params->pktlen;

    server_mud->protocol_type_mode = program_get_protocol_mode_by_domain_ip(params->domain, params->ip, params->ipv6,
                                                                            params->groupip);

    server_mud->api = params->api;
    server_mud->debug = params->debug;
    server_mud->epollcreate = params->epollcreate;
    server_mud->accept = params->accept;
    server_mud->tcp_keepalive_idle = params->tcp_keepalive_idle;
    server_mud->tcp_keepalive_interval = params->tcp_keepalive_interval;

    if (pthread_create(tid, NULL, sermud_listener_create_and_run, server_mud) < 0) {
        PRINT_ERROR("server can't create poisx thread %d! ", errno);
        return PROGRAM_FAULT;
    }

    if (server_mud->debug == false) {
        printf("[program informations]: \n\n");
    }
    while (true) {
        sermud_info_print(server_mud);
    }

    pthread_mutex_destroy(&server_debug_mutex);

    return PROGRAM_OK;
}

// the multi thread, unblock, mutliplexing IO server prints informations
void sermum_info_print(struct ServerMum *server_mum)
{
    if (server_mum->debug == false) {
        struct timeval begin;
        gettimeofday(&begin, NULL);
        uint64_t begin_time = (uint64_t)begin.tv_sec * 1000 + (uint64_t)begin.tv_usec / 1000;

        uint32_t curr_connect = 0;
        double bytes_ps = 0;
        uint64_t begin_recv_bytes = 0;
        struct ServerMumUnit *begin_uint = server_mum->uints;
        while (begin_uint != NULL) {
            curr_connect += begin_uint->curr_connect;
            begin_recv_bytes += begin_uint->recv_bytes;
            begin_uint = begin_uint->next;
        }

        struct timeval delay;
        delay.tv_sec = 0;
        delay.tv_usec = TERMINAL_REFRESH_MS * 1000;
        select(0, NULL, NULL, NULL, &delay);

        uint64_t end_recv_bytes = 0;
        struct ServerMumUnit *end_uint = server_mum->uints;
        while (end_uint != NULL) {
            end_recv_bytes += end_uint->recv_bytes;
            end_uint = end_uint->next;
        }

        struct timeval end;
        gettimeofday(&end, NULL);
        uint64_t end_time = (uint64_t)end.tv_sec * 1000 + (uint64_t)end.tv_usec / 1000;
        
        double bytes_sub = end_recv_bytes > begin_recv_bytes ? (double)(end_recv_bytes - begin_recv_bytes) : 0;
        double time_sub = end_time > begin_time ? (double)(end_time - begin_time) / 1000 : 0;

        bytes_ps = bytes_sub  / time_sub;

        if (bytes_ps < 1024) {
            PRINT_SERVER_DATAFLOW("[connect num]: %d, [receive]: %.3f B/s", curr_connect, bytes_ps);
        } else if (bytes_ps < (1024 * 1024)) {
            PRINT_SERVER_DATAFLOW("[connect num]: %d, [receive]: %.3f KB/s", curr_connect, bytes_ps / 1024);
        } else {
            PRINT_SERVER_DATAFLOW("[connect num]: %d, [receive]: %.3f MB/s", curr_connect, bytes_ps / (1024 * 1024));
        }
    }
}

// the single thread, unblock, mutliplexing IO server listens and gets epoll feature descriptors
int32_t sersum_create_epfd_and_reg(struct ServerMumUnit *server_unit)
{
    if (strcmp(server_unit->epollcreate, "ec1") == 0) {
        server_unit->epfd = epoll_create1(EPOLL_CLOEXEC);
    } else {
        server_unit->epfd = epoll_create(SERVER_EPOLL_SIZE_MAX);
    }
    
    if (server_unit->epfd < 0) {
       PRINT_ERROR("server can't create epoll %d! ", server_unit->epfd);
       return PROGRAM_FAULT;
    }

    struct epoll_event ep_ev = {0};
    ep_ev.events = EPOLLIN | EPOLLET;

    for (int32_t i = 0; i < PROTOCOL_MODE_MAX; i++) {
        if (server_unit->listener.listen_fd_array[i] != -1) {
            struct ServerHandler *server_handler = (struct ServerHandler *)malloc(sizeof(struct ServerHandler));
            memset_s(server_handler, sizeof(struct ServerHandler), 0, sizeof(struct ServerHandler));
            server_handler->fd = server_unit->listener.listen_fd_array[i];

            ep_ev.data.ptr = (void *)server_handler;
            if (epoll_ctl(server_unit->epfd, EPOLL_CTL_ADD, server_unit->listener.listen_fd_array[i], &ep_ev) < 0) {
                PRINT_ERROR("epoll_ctl failed %d! listen_fd=%d ", errno, server_unit->listener.listen_fd_array[i]);
                return PROGRAM_FAULT;
            }
        }
    }

    server_debug_print("server mum unit", "waiting", &server_unit->server_ip_info.ip, server_unit->port,
                       server_unit->debug);

    return PROGRAM_OK;
}

// the single thread, unblock, mutliplexing IO server accepts the connections
int32_t sersum_accept_connects(struct epoll_event *cur_epev, struct ServerMumUnit *server_unit)
{
    fault_inject_delay(INJECT_DELAY_ACCEPT);
    int32_t fd = ((struct ServerHandler*)(cur_epev->data.ptr))->fd;
    while (true) {
        sockaddr_t accept_addr;
        bool is_tcp_v6 = (fd == (server_unit->listener.listen_fd_array[V6_TCP])) ? true : false;

        socklen_t sockaddr_in_len = is_tcp_v6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
        int32_t accept_fd;
        int32_t ret = 0;

        int32_t listen_index = (is_tcp_v6) ? V6_TCP : V4_TCP;
        int32_t listen_fd = server_unit->listener.listen_fd_array[listen_index];

        if (strcmp(server_unit->accept, "ac4") == 0) {
            accept_fd = accept4(listen_fd, (struct sockaddr *)&accept_addr, &sockaddr_in_len, SOCK_CLOEXEC);
        } else {
            accept_fd = accept(listen_fd, (struct sockaddr *)&accept_addr, &sockaddr_in_len);
        }

        if (accept_fd < 0) {
            PRINT_ERROR("accept_fd=%d , errno=%d ", accept_fd, errno);
            break;
        }
        ret = set_tcp_keep_alive_info(accept_fd, server_unit->tcp_keepalive_idle, server_unit->tcp_keepalive_interval);
        if (ret < 0) {
            PRINT_ERROR("set_tcp_keep_alive_info ret=%d \n", ret);
            return PROGRAM_FAULT;
        }

        if (set_socket_unblock(accept_fd) < 0) {
            PRINT_ERROR("server can't set the connect socket to unblock! ");
            return PROGRAM_FAULT;
        }

        struct ServerHandler *server_handler = (struct ServerHandler *)malloc(sizeof(struct ServerHandler));
        server_handler->fd = accept_fd;
        server_handler->is_v6 = (is_tcp_v6) ? 1 : 0;

        struct epoll_event ep_ev;
        ep_ev.data.ptr = (void *)server_handler;
        ep_ev.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(server_unit->epfd, EPOLL_CTL_ADD, accept_fd, &ep_ev) < 0) {
            PRINT_ERROR("server can't add socket '%d' to control epoll %d! ", accept_fd, errno);
            return PROGRAM_FAULT;
        }

        ++server_unit->curr_connect;

        // sockaddr tp ip, port
        ip_addr_t remote_ip;
        uint16_t remote_port = ((struct sockaddr_in*)&accept_addr)->sin_port;
        remote_ip.addr_family = (is_tcp_v6) ? AF_INET6 : AF_INET;
        if (is_tcp_v6 == false) {
            remote_ip.u_addr.ip4 = ((struct sockaddr_in *)&accept_addr)->sin_addr;
        } else {
            remote_ip.u_addr.ip6 = ((struct sockaddr_in6 *)&accept_addr)->sin6_addr;
        }

        server_debug_print("server mum unit", "accept", &remote_ip, remote_port, server_unit->debug);
    }

    return PROGRAM_OK;
}

static int sersum_get_remote_ip(struct ServerHandler *server_handler, ip_addr_t *remote_ip, uint16_t *remote_port)
{
    sockaddr_t connect_addr;
    socklen_t connect_addr_len = server_handler->is_v6 == 0 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    if (getpeername(server_handler->fd, (struct sockaddr *)&connect_addr, &connect_addr_len) < 0) {
        PRINT_ERROR("server can't socket peername %d! ", errno);
        return PROGRAM_ABORT;
    }

    *remote_port = ((struct sockaddr_in *)&connect_addr)->sin_port;
    if (((struct sockaddr *)&connect_addr)->sa_family == AF_INET) {
        remote_ip->addr_family = AF_INET;
        remote_ip->u_addr.ip4 = ((struct sockaddr_in *)&connect_addr)->sin_addr;
    } else if (((struct sockaddr *)&connect_addr)->sa_family == AF_INET6) {
        remote_ip->addr_family = AF_INET6;
        remote_ip->u_addr.ip6 = ((struct sockaddr_in6 *)&connect_addr)->sin6_addr;
    }
    return PROGRAM_OK;
}

static int sersum_process_tcp_accept_event(struct ServerMumUnit *server_unit, struct epoll_event *curr_epev)
{
    struct ServerHandler *server_handler = (struct ServerHandler *)curr_epev->data.ptr;
    ip_addr_t remote_ip;
    uint16_t remote_port;

    if (sersum_get_remote_ip(server_handler, &remote_ip, &remote_port) != PROGRAM_OK) {
        return PROGRAM_ABORT;
    }

    int32_t server_ans_ret = server_ans(server_handler->fd, server_unit->pktlen, server_unit->api, "tcp");
    if (server_ans_ret == PROGRAM_FAULT) {
        --server_unit->curr_connect;
        server_handler_close(server_unit->epfd, server_handler);
    } else if (server_ans_ret == PROGRAM_ABORT) {
        --server_unit->curr_connect;
        server_debug_print("server mum unit", "close", &remote_ip, remote_port, server_unit->debug);
        server_handler_close(server_unit->epfd, server_handler);
    } else {
        server_unit->recv_bytes += server_unit->pktlen;
        server_debug_print("server mum unit", "receive", &remote_ip, remote_port, server_unit->debug);
    }
    return PROGRAM_OK;
}

static int sersum_process_epollin_event(struct ServerMumUnit *server_unit, struct epoll_event *curr_epev)
{
    struct ServerHandler *server_handler = (struct ServerHandler *)curr_epev->data.ptr;
    int32_t fd = server_handler->fd;
    if (fd == (server_unit->listener.listen_fd_array[V4_TCP]) ||
        fd == (server_unit->listener.listen_fd_array[V6_TCP])) {
        int32_t sersum_accept_connects_ret = sersum_accept_connects(curr_epev, server_unit);
        if (sersum_accept_connects_ret < 0) {
            PRINT_ERROR("server try accept error %d! ", sersum_accept_connects_ret);
            return PROGRAM_ABORT;
        }
    } else if (fd == (server_unit->listener.listen_fd_array[V4_UDP]) ||
               fd == (server_unit->listener.listen_fd_array[UDP_MULTICAST])) {
        uint32_t pktlen = server_unit->pktlen > UDP_PKTLEN_MAX ? UDP_PKTLEN_MAX : server_unit->pktlen;
        int32_t server_ans_ret = server_ans(fd, pktlen, server_unit->api, "udp");
        if (server_ans_ret != PROGRAM_OK) {
            if (server_handler_close(server_unit->epfd, server_handler) != 0) {
                PRINT_ERROR("server_handler_close ret %d! \n", server_ans_ret);
                return PROGRAM_ABORT;
            }
        }
        server_unit->recv_bytes += pktlen;
    } else {
        if (sersum_process_tcp_accept_event(server_unit, curr_epev) != PROGRAM_OK) {
            return PROGRAM_ABORT;
        }
    }
    return PROGRAM_OK;
}

// the single thread, unblock, mutliplexing IO server processes the events
int32_t sersum_proc_epevs(struct ServerMumUnit *server_unit)
{
    int32_t epoll_nfds = epoll_wait(server_unit->epfd, server_unit->epevs, SERVER_EPOLL_SIZE_MAX, SERVER_EPOLL_WAIT_TIMEOUT);
    if (epoll_nfds < 0) {
        PRINT_ERROR("server epoll wait error %d! ", errno);
        return PROGRAM_FAULT;
    }

    for (int32_t i = 0; i < epoll_nfds; ++i) {
        struct epoll_event *curr_epev = server_unit->epevs + i;

        if (curr_epev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
            server_unit->curr_connect--;
            if (server_handler_close(server_unit->epfd, (struct ServerHandler *)curr_epev->data.ptr) != 0) {
                return PROGRAM_OK;
            }
        }

        if (curr_epev->events == EPOLLIN) {
            if (sersum_process_epollin_event(server_unit, curr_epev) != PROGRAM_OK) {
                return PROGRAM_ABORT;
            }
        }
    }

    return PROGRAM_OK;
}

// create the single thread, unblock, mutliplexing IO server
void *sersum_create_and_run(void *arg)
{
    struct ServerMumUnit *server_unit = (struct ServerMumUnit *)arg;

    if (create_socket_and_listen(server_unit->listener.listen_fd_array, &(server_unit->server_ip_info),
                                 server_unit->port, server_unit->protocol_type_mode) < 0) {
        PRINT_ERROR("create_socket_and_listen err! \n");
        exit(PROGRAM_FAULT);
    }
    if (sersum_create_epfd_and_reg(server_unit) < 0) {
       exit(PROGRAM_FAULT);
    }
    while (true) {
        if (sersum_proc_epevs(server_unit) < 0) {
            exit(PROGRAM_FAULT);
        }
    }
    
    close(server_unit->listener.fd);
    close(server_unit->epfd);

    return (void *)PROGRAM_OK;
}

// create the multi thread, unblock, mutliplexing IO server
int32_t sermum_create_and_run(struct ProgramParams *params)
{
    const uint32_t thread_num = params->thread_num;
    pthread_t *tids = (pthread_t *)malloc(thread_num * sizeof(pthread_t));
    struct ServerMum *server_mum = (struct ServerMum *)malloc(sizeof(struct ServerMum));
    struct ServerMumUnit *server_unit = (struct ServerMumUnit *)malloc(sizeof(struct ServerMumUnit));
    memset_s(server_unit, sizeof(struct ServerMumUnit), 0, sizeof(struct ServerMumUnit));

    if (pthread_mutex_init(&server_debug_mutex, NULL) < 0) {
        PRINT_ERROR("server can't init posix mutex %d! ", errno);
        return PROGRAM_FAULT;
    }

    server_mum->uints = server_unit;
    server_mum->debug = params->debug;
    uint32_t port = UNIX_TCP_PORT_MIN;

    for (uint32_t i = 0; i < thread_num; ++i) {
        server_unit->listener.fd = -1;
        for (int32_t i = 0; i < PROTOCOL_MODE_MAX; i++) {
            server_unit->listener.listen_fd_array[i] = -1;
        }
        server_unit->epfd = -1;
        server_unit->epevs = (struct epoll_event *)malloc(SERVER_EPOLL_SIZE_MAX * sizeof(struct epoll_event));
        server_unit->curr_connect = 0;
        server_unit->recv_bytes = 0;
        server_unit->server_ip_info.ip.addr_family = params->addr_family;
        inet_pton(AF_INET, params->ip, &server_unit->server_ip_info.ip.u_addr.ip4);
        inet_pton(AF_INET6, params->ipv6, &server_unit->server_ip_info.ip.u_addr.ip6);

        server_unit->server_ip_info.groupip.addr_family = AF_INET;
        inet_pton(AF_INET, params->groupip, &server_unit->server_ip_info.groupip.u_addr);

        server_unit->server_ip_info.groupip_interface.addr_family = AF_INET;
        inet_pton(AF_INET, params->groupip_interface, &server_unit->server_ip_info.groupip_interface.u_addr);

        /* loop to set ports to each server_mums */
        while (!((params->port)[port])) {
            port = (port + 1) % UNIX_TCP_PORT_MAX;
        }
        server_unit->port = htons(port++);
        server_unit->pktlen = params->pktlen;

        server_unit->protocol_type_mode = program_get_protocol_mode_by_domain_ip(params->domain, params->ip,
                                                                                 params->ipv6, params->groupip);

        server_unit->api = params->api;
        server_unit->debug = params->debug;
        server_unit->epollcreate = params->epollcreate;
        server_unit->accept = params->accept;
        server_unit->tcp_keepalive_idle = params->tcp_keepalive_idle;
        server_unit->tcp_keepalive_interval = params->tcp_keepalive_interval;
        server_unit->next = (struct ServerMumUnit *)malloc(sizeof(struct ServerMumUnit));
        if (server_unit->next) {
            memset_s(server_unit->next, sizeof(struct ServerMumUnit), 0, sizeof(struct ServerMumUnit));
        }

        if (pthread_create((tids + i), NULL, sersum_create_and_run, server_unit) < 0) {
            PRINT_ERROR("server can't create poisx thread %d! ", errno);
            return PROGRAM_FAULT;
        }
        server_unit = server_unit->next;
    }

    if (server_mum->debug == false) {
        printf("[program informations]: \n\n");
    }

    if (strcmp(params->as, "server") == 0) {
        while (true) {
            sermum_info_print(server_mum);
        }
    }

    pthread_mutex_destroy(&server_debug_mutex);

    return PROGRAM_OK;
}

// create server and run
int32_t server_create_and_run(struct ProgramParams *params)
{
    int32_t ret = PROGRAM_OK;

    if (strcmp(params->model, "mum") == 0) {
        ret = sermum_create_and_run(params);
    } else {
        ret = sermud_create_and_run(params);
    }

    return ret;
}
