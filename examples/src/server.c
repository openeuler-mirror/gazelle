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


static pthread_mutex_t server_printf_mutex;                     // the server mutex for printf


// the single thread, unblock, mutliplexing IO server prints debug informations
void sersum_debug_print(struct ServerMumUnit *server_unit, const char *str, const char *ip, uint16_t port)
{
    if (server_unit->debug == true) {
        pthread_mutex_lock(&server_printf_mutex);
        PRINT_SERVER("[mum pid: %d] [tid: %ld cnnt: %d] [%s <- %s:%d]. ", \
                    getpid(), \
                    pthread_self(), \
                    server_unit->connections, \
                    str, \
                    ip, \
                    port);
        pthread_mutex_unlock(&server_printf_mutex);
    }
}

// the multi thread, unblock, mutliplexing IO server prints informations
void sermum_info_print(struct ServerMum *server_mum)
{
    if (server_mum->debug == false) {
        struct timeval begin;
        gettimeofday(&begin, NULL);
        uint64_t begin_time = (uint64_t)begin.tv_sec * 1000 + (uint64_t)begin.tv_usec / 1000;

        uint32_t connections = 0;
        double bytes_ps = 0;
        uint64_t begin_recv_bytes = 0;
        struct ServerMumUnit *begin_uint = server_mum->uints;
        while (begin_uint != NULL) {
            connections += begin_uint->connections;
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
            PRINT_SERVER_DATAFLOW("[connections]: %d, [receive]: %.3f b/s", connections, bytes_ps);
        } else if (bytes_ps < (1024 * 1024)) {
            PRINT_SERVER_DATAFLOW("[connections]: %d, [receive]: %.3f kb/s", connections, bytes_ps / 1024);
        } else {
            PRINT_SERVER_DATAFLOW("[connections]: %d, [receive]: %.3f mb/s", connections, bytes_ps / (1024 * 1024));
        }
    }
}

// the single thread, unblock, mutliplexing IO server listens and gets epoll feature descriptors
int32_t sersum_get_epfd(struct ServerMumUnit *server_unit)
{
    server_unit->epfd = epoll_create(SERVER_EPOLL_SIZE_MAX);
    if (server_unit->epfd < 0) {
       PRINT_ERROR("server can't create epoll!");
       return PROGRAM_FAULT;
    }

    struct epoll_event ep_ev;
    ep_ev.data.ptr = (void *)&(server_unit->listener);
    ep_ev.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(server_unit->epfd, EPOLL_CTL_ADD, server_unit->listener.fd, &ep_ev) < 0) {
        PRINT_ERROR("server can't control epoll! ");
        return PROGRAM_FAULT;
    }

    sersum_debug_print(server_unit, "waiting", "xxx.xxx.xxx.xxx", 0);

    return PROGRAM_OK;
}

// the single thread, unblock, mutliplexing IO server accepts the connections
int32_t sersum_try_accept(struct ServerMumUnit *server_unit, struct ServerHandler *server_handler)
{
    while (true) {
        struct sockaddr_in accept_addr;
        uint32_t sockaddr_in_len = sizeof(struct sockaddr_in);
        int32_t accept_fd = accept(server_unit->listener.fd, (struct sockaddr *)&accept_addr, &sockaddr_in_len);
        if (accept_fd < 0) {
            break;
        }

        int32_t set_socket_unblock_ret = set_socket_unblock(accept_fd);
        if (set_socket_unblock_ret < 0) {
            PRINT_ERROR("server can't set the connect socket to unblock %d! ", set_socket_unblock_ret);
            return PROGRAM_FAULT;
        }

        struct ServerHandler *server_handler = (struct ServerHandler *)malloc(sizeof(struct ServerHandler));
        server_handler->fd = accept_fd;
        struct epoll_event ep_ev;
        ep_ev.data.ptr = (void *)server_handler;
        ep_ev.events = EPOLLIN | EPOLLET;
        int32_t epoll_ctl_ret = epoll_ctl(server_unit->epfd, EPOLL_CTL_ADD, accept_fd, &ep_ev);
        if (epoll_ctl_ret < 0) {
            PRINT_ERROR("server can't add socket '%d' to control epoll %d! ", accept_fd, epoll_ctl_ret);
            return PROGRAM_FAULT;
        }

        ++server_unit->connections;
        sersum_debug_print(server_unit, "accept", inet_ntoa(accept_addr.sin_addr), accept_addr.sin_port);
    }

    return PROGRAM_OK;
}

// the single thread, unblock, mutliplexing IO server processes the events
int32_t sersum_proc_epevs(struct ServerMumUnit *server_unit)
{
    int32_t epoll_nfds = epoll_wait(server_unit->epfd, server_unit->epevs, SERVER_EPOLL_SIZE_MAX, SERVER_EPOLL_WAIT_TIMEOUT);
    if (epoll_nfds < 0) {
        PRINT_ERROR("server epoll wait error %d! ", epoll_nfds);
        return PROGRAM_FAULT;
    }

    for (int32_t i = 0; i < epoll_nfds; ++i) {
        if (server_unit->epevs[i].events == EPOLLERR || server_unit->epevs[i].events == EPOLLHUP || server_unit->epevs[i].events == EPOLLRDHUP) {
            PRINT_ERROR("server epoll wait error %d! ", server_unit->epevs[i].events);
            return PROGRAM_FAULT;
        }

        if (server_unit->epevs[i].events == EPOLLIN) {
            if (server_unit->epevs[i].data.ptr == (void *)&(server_unit->listener)) {
                int32_t sersum_try_accept_ret = sersum_try_accept(server_unit, &(server_unit->listener));
                if (sersum_try_accept_ret < 0) {
                    PRINT_ERROR("server try accept error %d! ", sersum_try_accept_ret);
                    return PROGRAM_FAULT;
                }
                continue;
            } else {
                struct ServerHandler *server_handler = (struct ServerHandler *)server_unit->epevs[i].data.ptr;
                struct sockaddr_in connect_addr;
                socklen_t connect_addr_len = sizeof(connect_addr);
                int32_t getpeername_ret = getpeername(server_handler->fd, (struct sockaddr *)&connect_addr, &connect_addr_len);
                if (getpeername_ret < 0) {
                    PRINT_ERROR("server can't socket peername %d! ", getpeername_ret);
                    return PROGRAM_FAULT;
                }

                int32_t server_ans_ret = server_ans(server_handler, server_unit->pktlen);
                if (server_ans_ret == PROGRAM_FAULT) {
                    --server_unit->connections;
                    struct epoll_event ep_ev;
                    int32_t epoll_ctl_ret = epoll_ctl(server_unit->epfd, EPOLL_CTL_DEL, server_handler->fd, &ep_ev);
                    if (epoll_ctl_ret < 0) {
                        PRINT_ERROR("server can't delete socket '%d' to control epoll %d! ", server_handler->fd, epoll_ctl_ret);
                        return PROGRAM_FAULT;
                    }
                } else if (server_ans_ret == PROGRAM_ABORT) {
                    --server_unit->connections;
                    int32_t cloes_ret = close(server_handler->fd);
                    if (cloes_ret < 0) {
                        PRINT_ERROR("server can't close the socket %d! ", cloes_ret);
                        return PROGRAM_FAULT;
                    }
                    sersum_debug_print(server_unit, "close", inet_ntoa(connect_addr.sin_addr), connect_addr.sin_port);
                } else {
                    server_unit->recv_bytes += server_unit->pktlen;
                    sersum_debug_print(server_unit, "receive", inet_ntoa(connect_addr.sin_addr), connect_addr.sin_port);
                }
            }
        }
    }

    return PROGRAM_OK;
}

// create the single thread, unblock, mutliplexing IO server
void *sersum_create(void *arg)
{
    struct ServerMumUnit *server_unit = (struct ServerMumUnit *)arg;

    if (socket_create(&(server_unit->listener.fd), server_unit->ip, server_unit->port) < 0) {
        exit(PROGRAM_FAULT);
    }
    if (sersum_get_epfd(server_unit) < 0) {
       exit(PROGRAM_FAULT);
    }
    while (true) {
        if (sersum_proc_epevs(server_unit) < 0) {
            exit(PROGRAM_FAULT);
        }
    }
    if (close(server_unit->listener.fd) < 0 || close(server_unit->epfd) < 0) {
        exit(PROGRAM_FAULT);
    }

    return (void *)PROGRAM_OK;
}

// create the multi thread, unblock, mutliplexing IO server
int32_t sermum_create(struct ProgramParams *params)
{
    const uint32_t thread_num = params->thread_num;
    pthread_t *tids = (pthread_t *)malloc(thread_num * sizeof(pthread_t));
    struct ServerMum *server_mum = (struct ServerMum *)malloc(sizeof(struct ServerMum));
    struct ServerMumUnit *server_unit = (struct ServerMumUnit *)malloc(sizeof(struct ServerMumUnit));

    int32_t pthread_mutex_init_ret = pthread_mutex_init(&server_printf_mutex, NULL);
    if (pthread_mutex_init_ret < 0) {
        PRINT_ERROR("server can't init posix mutex %d! ", pthread_mutex_init_ret);
        return PROGRAM_FAULT;
    }

    {
        server_mum->uints = server_unit;
        server_mum->debug = params->debug;
    }

    for (uint32_t i = 0; i < thread_num; ++i) {
        server_unit->listener.fd = -1;
        server_unit->epfd = -1;
        server_unit->epevs = (struct epoll_event *)malloc(SERVER_EPOLL_SIZE_MAX * sizeof(struct epoll_event));
        server_unit->connections = 0;
        server_unit->recv_bytes = 0;
        server_unit->ip = inet_addr(params->ip);
        server_unit->port = htons(params->port);
        server_unit->pktlen = params->pktlen;
        server_unit->debug = params->debug;
        server_unit->next = (struct ServerMumUnit *)malloc(sizeof(struct ServerMumUnit));

        int32_t pthread_create_ret = pthread_create((tids + i), NULL, sersum_create, server_unit);
        if (pthread_create_ret < 0) {
            PRINT_ERROR("server can't create poisx thread %d! ", pthread_create_ret);
            return PROGRAM_FAULT;
        }
        server_unit = server_unit->next;
    }

    if (server_mum->debug == false) {
        printf("[program informations]: \n\n");
    }
    while (true) {
        sermum_info_print(server_mum);
    }

    int32_t pthread_mutex_destroy_ret = pthread_mutex_destroy(&server_printf_mutex);
    if (pthread_mutex_destroy_ret < 0) {
        PRINT_ERROR("server can't destroy posix mutex %d! ", pthread_mutex_destroy_ret);
        return PROGRAM_FAULT;
    }

    return PROGRAM_OK;
}

// create server
int32_t server_create(struct ProgramParams *params)
{
    int32_t ret = PROGRAM_OK;

    if (strcmp(params->model, "mum") == 0) {
        ret = sermum_create(params);
    }

    return ret;
}
