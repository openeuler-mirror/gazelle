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


// the single thread, unblock, mutliplexing IO server listens and gets epoll feature descriptors
int32_t sersum_get_epfd(struct ServerMumUnit *server_unit)
{
    if (listen(server_unit->lstnfd, SERVER_SOCKET_LISTEN_BACKLOG) < 0) {
        PRINT_ERROR("server socket can't lisiten! ");
        return PROGRAM_FAULT;
    }

    server_unit->epfd = epoll_create(SERVER_EPOLL_SIZE_MAX);
    if (server_unit->epfd < 0) {
       PRINT_ERROR("server can't create epoll!");
       return PROGRAM_FAULT;
    }

    struct epoll_event ep_ev;
    ep_ev.data.fd = server_unit->lstnfd;
    ep_ev.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(server_unit->epfd, EPOLL_CTL_ADD, server_unit->lstnfd, &ep_ev) < 0) {
        PRINT_ERROR("server can't control epoll! ");
        return PROGRAM_FAULT;
    }

    if (server_unit->debug == true) {
        pthread_mutex_lock(server_unit->lock);
        PRINT_SERVER("'mum' 'pid->%d' 'tid->%ld' 'connections->0' wait client connect... ", getpid(), pthread_self());
        pthread_mutex_unlock(server_unit->lock);
    }

    return PROGRAM_OK;
}

// the single thread, unblock, mutliplexing IO server prints debug informations
void sersum_debug_print(struct ServerMumUnit *server_unit, const char *str, const char *ip, uint32_t port)
{
    if (server_unit->debug == true) {
        pthread_mutex_lock(server_unit->lock);
        PRINT_SERVER("'mum' 'pid: %d' 'tid: %ld' 'connections: %d' [%s] <- %s:%d. ", \
                    getpid(), \
                    pthread_self(), \
                    server_unit->connections, \
                    str, \
                    ip, \
                    port);
        pthread_mutex_unlock(server_unit->lock);
    }
}

// the single thread, unblock, mutliplexing IO server processes the events
int32_t sersum_proc_epevs(struct ServerMumUnit *server_unit)
{
    int32_t epoll_nfds = epoll_wait(server_unit->epfd, server_unit->epevs, SERVER_EPOLL_SIZE_MAX, SERVER_EPOLL_WAIT_TIMEOUT);
    if (epoll_nfds < 0) {
        PRINT_ERROR("server epoll wait error! ");
        return PROGRAM_FAULT;
    }

    struct epoll_event ep_ev;
    for (int i = 0; i < epoll_nfds; ++i) {
        if (server_unit->epevs[i].events == EPOLLERR) {
            if (epoll_ctl(server_unit->epfd, EPOLL_CTL_DEL, server_unit->epevs[i].data.fd, &ep_ev) < 0) {
                PRINT_ERROR("server can't delete socket '%d' to control epoll! ", server_unit->epevs[i].data.fd);
                return PROGRAM_FAULT;
            }
            if (server_unit->epevs[i].data.fd != server_unit->lstnfd) {
                --server_unit->connections;
            }
            if (close(server_unit->epevs[i].data.fd) < 0) {
                PRINT_ERROR("server can't close the event's file descriptor! ");
                return PROGRAM_FAULT;
            }
            PRINT_ERROR("server epoll wait error! ");
            return PROGRAM_FAULT;
        }

        if (server_unit->epevs[i].events == EPOLLIN) {
            if (server_unit->epevs[i].data.fd == server_unit->lstnfd) {
                struct sockaddr_in connect_addr;
                uint32_t sockaddr_in_len = sizeof(struct sockaddr_in);

                int32_t connect_fd = accept(server_unit->lstnfd, (struct sockaddr *)&connect_addr, &sockaddr_in_len);
                if (connect_fd < 0) {
                    continue;
                }

                ++server_unit->connections;

                sersum_debug_print(server_unit, "accept", inet_ntoa(connect_addr.sin_addr), connect_addr.sin_port);

                if (set_socket_unblock(connect_fd) < 0) {
                    PRINT_ERROR("server can't set the connect socket to unblock! ");
                    return PROGRAM_FAULT;
                }

                ep_ev.data.fd = connect_fd;
                ep_ev.events = EPOLLIN | EPOLLET;
                if (epoll_ctl(server_unit->epfd, EPOLL_CTL_ADD, connect_fd, &ep_ev) < 0) {
                    PRINT_ERROR("server can't add socket '%d' to control epoll! ", connect_fd);
                    return PROGRAM_FAULT;
                }

                continue;
            }

            struct sockaddr_in connect_addr;
            socklen_t connect_addr_len = sizeof(connect_addr);
            if (getpeername(server_unit->epevs[i].data.fd, (struct sockaddr *)&connect_addr, &connect_addr_len) < 0) {
                PRINT_ERROR("server can't socket peername! ");
                return PROGRAM_FAULT;
            }
            int32_t server_handle_ret = server_chk_ans(server_unit->epevs[i].data.fd, server_unit->pktlen, server_unit->verify, &server_unit->msg_idx);
            if (server_handle_ret == PROGRAM_FAULT) {
                --server_unit->connections;
                if (epoll_ctl(server_unit->epfd, EPOLL_CTL_DEL, server_unit->epevs[i].data.fd, &ep_ev) < 0) {
                    PRINT_ERROR("server can't delete socket '%d' to control epoll! ", server_unit->epevs[i].data.fd);
                    return PROGRAM_FAULT;
                }
            } else if (server_handle_ret == PROGRAM_ABORT) {
                --server_unit->connections;
                if (close(server_unit->epevs[i].data.fd) < 0) {
                    PRINT_ERROR("server can't close the socket! ");
                    return PROGRAM_FAULT;
                }
                sersum_debug_print(server_unit, "close", inet_ntoa(connect_addr.sin_addr), connect_addr.sin_port);
            } else {
                sersum_debug_print(server_unit, "receive", inet_ntoa(connect_addr.sin_addr), connect_addr.sin_port);
            }
        }
    }

    return PROGRAM_OK;
}

// create the single thread, unblock, mutliplexing IO server
void *sersum_create(void *arg)
{
    struct ServerMumUnit *server_unit = (struct ServerMumUnit *)arg;

    if (socket_create(&(server_unit->lstnfd), server_unit->ip, server_unit->port) < 0) {
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

    if (close(server_unit->lstnfd) < 0 || close(server_unit->epfd) < 0) {
        exit(PROGRAM_FAULT);
    }

    return (void *)PROGRAM_OK;
}

// create the multi thread, unblock, mutliplexing IO server
int32_t sermum_create(struct ProgramParams *params)
{
    const uint32_t thread_num = params->thread_num;
    pthread_t *tids = (pthread_t *)malloc(thread_num * sizeof(pthread_t));
    struct ServerMumUnit *server_unit = (struct ServerMumUnit *)malloc(thread_num * sizeof(struct ServerMumUnit *));

    pthread_mutex_t lock;
    if (params->debug == true) {
        if (pthread_mutex_init(&lock, NULL) != 0) {
            PRINT_ERROR("server can't init posix mutex! ");
            return PROGRAM_FAULT;
        }
    }

    for (int i = 0; i < params->thread_num; ++i) {
        (server_unit + i)->lstnfd = -1;
        (server_unit + i)->epfd = -1;
        (server_unit + i)->epevs = (struct epoll_event *)malloc(SERVER_EPOLL_SIZE_MAX * sizeof(struct epoll_event *));
        (server_unit + i)->connections = 0;
        (server_unit + i)->lock = (params->debug == true) ? &lock : NULL;
        (server_unit + i)->ip = params->ip;
        (server_unit + i)->port = params->port;
        (server_unit + i)->pktlen = params->pktlen;
        (server_unit + i)->verify = params->verify;
        (server_unit + i)->msg_idx = 0;
        (server_unit + i)->debug = params->debug;

        if (pthread_create((tids + i), NULL, sersum_create, server_unit + i) != 0) {
            PRINT_ERROR("server can't create poisx thread! ");
            return PROGRAM_FAULT;
        }
    }

    for (int i = 0; i < params->thread_num; ++i) {
        pthread_join(*(tids + i), NULL);
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
