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
void server_debug_print(const char *ch_str, const char *act_str, in_addr_t ip, uint16_t port, bool debug)
{
    if (debug == true) {
        pthread_mutex_lock(&server_debug_mutex);
        struct in_addr sin_addr;
        sin_addr.s_addr = ip;
        PRINT_SERVER("[%s] [pid: %d] [tid: %ld] [%s <- %s:%d]. ", \
                    ch_str, \
                    getpid(), \
                    pthread_self(), \
                    act_str, \
                    inet_ntoa(sin_addr), \
                    ntohs(port));
        pthread_mutex_unlock(&server_debug_mutex);
    }
}

// the multi thread, unblock, dissymmetric server prints informations
void sermud_info_print(struct ServerMud *server_mud)
{
    if (server_mud->debug == false) {
        uint32_t curr_connect = server_mud->curr_connect;

        struct timeval begin;
        gettimeofday(&begin, NULL);
        uint64_t begin_time = (uint64_t)begin.tv_sec * 1000 + (uint64_t)begin.tv_usec / 1000;

        double bytes_ps = 0;
        uint64_t begin_recv_bytes = 0;
        struct ServerMudWorker *begin_uint = server_mud->workers;
        while (begin_uint != NULL) {
            begin_recv_bytes += begin_uint->recv_bytes;
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
    worker_unit->epfd = epoll_create(SERVER_EPOLL_SIZE_MAX);
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
    server_mud->epfd = epoll_create(SERVER_EPOLL_SIZE_MAX);
    if (server_mud->epfd < 0) {
       PRINT_ERROR("server can't create epoll %d! ", server_mud->epfd);
       return PROGRAM_FAULT;
    }

    struct epoll_event ep_ev;
    ep_ev.data.ptr = (void *)&(server_mud->listener);
    ep_ev.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(server_mud->epfd, EPOLL_CTL_ADD, server_mud->listener.fd, &ep_ev) < 0) {
        PRINT_ERROR("server can't control epoll %d! ", errno);
        return PROGRAM_FAULT;
    }

    server_debug_print("server mud listener", "waiting", server_mud->ip, server_mud->port, server_mud->debug);

    return PROGRAM_OK;
}

// the listener thread, unblock, dissymmetric server accepts the connections
int32_t sermud_listener_accept_connects(struct ServerMud *server_mud)
{
    while (true) {
        struct sockaddr_in accept_addr;
        uint32_t sockaddr_in_len = sizeof(struct sockaddr_in);
        int32_t accept_fd = accept(server_mud->listener.fd, (struct sockaddr *)&accept_addr, &sockaddr_in_len);
        if (accept_fd < 0) {
            break;
        }

        if (set_socket_unblock(accept_fd) < 0) {
            PRINT_ERROR("server can't set the connect socket to unblock! ");
            return PROGRAM_FAULT;
        }

        ++(server_mud->curr_connect);

        pthread_t *tid = (pthread_t *)malloc(sizeof(pthread_t));
        struct ServerMudWorker *worker = (struct ServerMudWorker *)malloc(sizeof(struct ServerMudWorker));
        worker->worker.fd = accept_fd;
        worker->epfd = -1;
        worker->epevs = (struct epoll_event *)malloc(sizeof(struct epoll_event));
        worker->recv_bytes = 0;
        worker->pktlen = server_mud->pktlen;
        worker->ip = accept_addr.sin_addr.s_addr;
        worker->port = accept_addr.sin_port;
        worker->api = server_mud->api;
        worker->debug = server_mud->debug;
        worker->next = server_mud->workers;

        server_mud->workers = worker;

        if (pthread_create(tid, NULL, sermud_worker_create_and_run, server_mud->workers) < 0) {
            PRINT_ERROR("server can't create poisx thread %d! ", errno);
            return PROGRAM_FAULT;
        }

        server_debug_print("server mud listener", "accept", accept_addr.sin_addr.s_addr, accept_addr.sin_port, server_mud->debug);
    }

    return PROGRAM_OK;
}

// the worker thread, unblock, dissymmetric server processes the events
int32_t sermud_worker_proc_epevs(struct ServerMudWorker *worker_unit)
{
    int32_t epoll_nfds = epoll_wait(worker_unit->epfd, worker_unit->epevs, SERVER_EPOLL_SIZE_MAX, SERVER_EPOLL_WAIT_TIMEOUT);
    if (epoll_nfds < 0) {
        PRINT_ERROR("server epoll wait error %d! ", errno);
        return PROGRAM_FAULT;
    }

    for (int32_t i = 0; i < epoll_nfds; ++i) {
        struct epoll_event *curr_epev = worker_unit->epevs + i;

        if (curr_epev->events == EPOLLERR || curr_epev->events == EPOLLHUP || curr_epev->events == EPOLLRDHUP) {
            PRINT_ERROR("server epoll wait error %d! ", curr_epev->events);
            return PROGRAM_FAULT;
        }

        if (curr_epev->events == EPOLLIN) {
            struct ServerHandler *server_handler = (struct ServerHandler *)curr_epev->data.ptr;

            int32_t server_ans_ret = server_ans(server_handler, worker_unit->pktlen, worker_unit->api);
            if (server_ans_ret == PROGRAM_FAULT) {
                struct epoll_event ep_ev;
                if (epoll_ctl(worker_unit->epfd, EPOLL_CTL_DEL, server_handler->fd, &ep_ev) < 0) {
                    PRINT_ERROR("server can't delete socket '%d' to control epoll %d! ", server_handler->fd, errno);
                    return PROGRAM_FAULT;
                }
            } else if (server_ans_ret == PROGRAM_ABORT) {
                if (close(server_handler->fd) < 0) {
                    PRINT_ERROR("server can't close the socket %d! ", errno);
                    return PROGRAM_FAULT;
                }
                server_debug_print("server mud worker", "close", worker_unit->ip, worker_unit->port, worker_unit->debug);
            } else {
                worker_unit->recv_bytes += worker_unit->pktlen;
                server_debug_print("server mud worker", "receive", worker_unit->ip, worker_unit->port, worker_unit->debug);
            }
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
    
        if (curr_epev->events == EPOLLERR || curr_epev->events == EPOLLHUP || curr_epev->events == EPOLLRDHUP) {
            PRINT_ERROR("server epoll wait error %d! ", curr_epev->events);
            return PROGRAM_FAULT;
        }

        if (curr_epev->events == EPOLLIN) {
            int32_t sermud_listener_accept_connects_ret = sermud_listener_accept_connects(server_mud);
            if (sermud_listener_accept_connects_ret < 0) {
                PRINT_ERROR("server try accept error %d! ", sermud_listener_accept_connects_ret);
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

    if (sermud_worker_create_epfd_and_reg(worker_unit) < 0) {
       exit(PROGRAM_FAULT);
    }
    while (true) {
        if (sermud_worker_proc_epevs(worker_unit) < 0) {
            exit(PROGRAM_FAULT);
        }
    }

    close(worker_unit->worker.fd);
    close(worker_unit->epfd);

    return (void *)PROGRAM_OK;
}

// create the listener thread, unblock, dissymmetric server and run
void *sermud_listener_create_and_run(void *arg)
{
    struct ServerMud *server_mud = (struct ServerMud *)arg;

    if (create_socket_and_listen(&(server_mud->listener.fd), server_mud->ip, server_mud->port, server_mud->domain) < 0) {
        exit(PROGRAM_FAULT);
    }
    if (sermud_listener_create_epfd_and_reg(server_mud) < 0) {
       exit(PROGRAM_FAULT);
    }
    while (true) {
        if (sermud_listener_proc_epevs(server_mud) < 0) {
            exit(PROGRAM_FAULT);
        }
    }
    if (close(server_mud->listener.fd) < 0 || close(server_mud->epfd) < 0) {
        exit(PROGRAM_FAULT);
    }

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
    server_mud->workers = NULL;
    server_mud->epfd = -1;
    server_mud->epevs = (struct epoll_event *)malloc(SERVER_EPOLL_SIZE_MAX * sizeof(struct epoll_event));
    server_mud->curr_connect = 0;
    server_mud->ip = inet_addr(params->ip);
    server_mud->port = htons(params->port);
    server_mud->pktlen = params->pktlen;
    server_mud->domain = params->domain;
    server_mud->api = params->api;
    server_mud->debug = params->debug;

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
    server_unit->epfd = epoll_create(SERVER_EPOLL_SIZE_MAX);
    if (server_unit->epfd < 0) {
       PRINT_ERROR("server can't create epoll %d! ", server_unit->epfd);
       return PROGRAM_FAULT;
    }

    struct epoll_event ep_ev;
    ep_ev.data.ptr = (void *)&(server_unit->listener);
    ep_ev.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(server_unit->epfd, EPOLL_CTL_ADD, server_unit->listener.fd, &ep_ev) < 0) {
        PRINT_ERROR("server can't control epoll %d! ", errno);
        return PROGRAM_FAULT;
    }

    server_debug_print("server mum unit", "waiting", server_unit->ip, server_unit->port, server_unit->debug);

    return PROGRAM_OK;
}

// the single thread, unblock, mutliplexing IO server accepts the connections
int32_t sersum_accept_connects(struct ServerMumUnit *server_unit, struct ServerHandler *server_handler)
{
    while (true) {
        struct sockaddr_in accept_addr;
        uint32_t sockaddr_in_len = sizeof(struct sockaddr_in);
        int32_t accept_fd = accept(server_unit->listener.fd, (struct sockaddr *)&accept_addr, &sockaddr_in_len);
        if (accept_fd < 0) {
            break;
        }

        if (set_socket_unblock(accept_fd) < 0) {
            PRINT_ERROR("server can't set the connect socket to unblock! ");
            return PROGRAM_FAULT;
        }

        struct ServerHandler *server_handler = (struct ServerHandler *)malloc(sizeof(struct ServerHandler));
        server_handler->fd = accept_fd;
        struct epoll_event ep_ev;
        ep_ev.data.ptr = (void *)server_handler;
        ep_ev.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(server_unit->epfd, EPOLL_CTL_ADD, accept_fd, &ep_ev) < 0) {
            PRINT_ERROR("server can't add socket '%d' to control epoll %d! ", accept_fd, errno);
            return PROGRAM_FAULT;
        }

        ++server_unit->curr_connect;
        
        server_debug_print("server mum unit", "accept", accept_addr.sin_addr.s_addr, accept_addr.sin_port, server_unit->debug);
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

        if (curr_epev->events == EPOLLERR || curr_epev->events == EPOLLHUP || curr_epev->events == EPOLLRDHUP) {
            PRINT_ERROR("server epoll wait error %d! ", curr_epev->events);
            return PROGRAM_FAULT;
        }

        if (curr_epev->events == EPOLLIN) {
            if (curr_epev->data.ptr == (void *)&(server_unit->listener)) {
                int32_t sersum_accept_connects_ret = sersum_accept_connects(server_unit, &(server_unit->listener));
                if (sersum_accept_connects_ret < 0) {
                    PRINT_ERROR("server try accept error %d! ", sersum_accept_connects_ret);
                    return PROGRAM_FAULT;
                }
                continue;
            } else {
                struct ServerHandler *server_handler = (struct ServerHandler *)curr_epev->data.ptr;
                struct sockaddr_in connect_addr;
                socklen_t connect_addr_len = sizeof(connect_addr);
                if (getpeername(server_handler->fd, (struct sockaddr *)&connect_addr, &connect_addr_len) < 0) {
                    PRINT_ERROR("server can't socket peername %d! ", errno);
                    return PROGRAM_FAULT;
                }

                int32_t server_ans_ret = server_ans(server_handler, server_unit->pktlen, server_unit->api);
                if (server_ans_ret == PROGRAM_FAULT) {
                    --server_unit->curr_connect;
                    struct epoll_event ep_ev;
                    if (epoll_ctl(server_unit->epfd, EPOLL_CTL_DEL, server_handler->fd, &ep_ev) < 0) {
                        PRINT_ERROR("server can't delete socket '%d' to control epoll %d! ", server_handler->fd, errno);
                        return PROGRAM_FAULT;
                    }
                } else if (server_ans_ret == PROGRAM_ABORT) {
                    --server_unit->curr_connect;
                    if (close(server_handler->fd) < 0) {
                        PRINT_ERROR("server can't close the socket %d! ", errno);
                        return PROGRAM_FAULT;
                    }
                    server_debug_print("server mum unit", "close", connect_addr.sin_addr.s_addr, connect_addr.sin_port, server_unit->debug);
                } else {
                    server_unit->recv_bytes += server_unit->pktlen;
                    server_debug_print("server mum unit", "receive", connect_addr.sin_addr.s_addr, connect_addr.sin_port, server_unit->debug);
                }
            }
        }
    }

    return PROGRAM_OK;
}

// create the single thread, unblock, mutliplexing IO server
void *sersum_create_and_run(void *arg)
{
    struct ServerMumUnit *server_unit = (struct ServerMumUnit *)arg;

    if (create_socket_and_listen(&(server_unit->listener.fd), server_unit->ip, server_unit->port, server_unit->domain) < 0) {
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

    if (pthread_mutex_init(&server_debug_mutex, NULL) < 0) {
        PRINT_ERROR("server can't init posix mutex %d! ", errno);
        return PROGRAM_FAULT;
    }

    server_mum->uints = server_unit;
    server_mum->debug = params->debug;

    for (uint32_t i = 0; i < thread_num; ++i) {
        server_unit->listener.fd = -1;
        server_unit->epfd = -1;
        server_unit->epevs = (struct epoll_event *)malloc(SERVER_EPOLL_SIZE_MAX * sizeof(struct epoll_event));
        server_unit->curr_connect = 0;
        server_unit->recv_bytes = 0;
        server_unit->ip = inet_addr(params->ip);
        server_unit->port = htons(params->port);
        server_unit->pktlen = params->pktlen;
        server_unit->domain = params->domain;
        server_unit->api = params->api;
        server_unit->debug = params->debug;
        server_unit->next = (struct ServerMumUnit *)malloc(sizeof(struct ServerMumUnit));

        if (pthread_create((tids + i), NULL, sersum_create_and_run, server_unit) < 0) {
            PRINT_ERROR("server can't create poisx thread %d! ", errno);
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
