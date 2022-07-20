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


#include "client.h"


// the single thread, client prints informations
void clithd_debug_print(struct ClientUnit *client_unit, const char *str, const char *ip, uint32_t port)
{
    if (client_unit->debug == true) {
        pthread_mutex_lock(client_unit->lock);
        PRINT_CLIENT("'pid: %d' 'tid: %ld' 'connections: %d' [%s] -> %s:%d. ", \
                    getpid(), \
                    pthread_self(), \
                    client_unit->connections, \
                    str, \
                    ip, \
                    port);
        pthread_mutex_unlock(client_unit->lock);
    }
}

// the single thread, client connects and gets epoll feature descriptors
int32_t clithd_get_epfd(struct ClientUnit *client_unit)
{
    const uint32_t connect_num = client_unit->connect_num;

    client_unit->epfd = epoll_create(CLIENT_EPOLL_SIZE_MAX);
    if (client_unit->epfd < 0) {
        PRINT_ERROR("client can't create epoll! ");
        return PROGRAM_FAULT;
    }

    struct epoll_event ep_ev;
    for (int i = 0; i < connect_num; ++i) {
        client_unit->cnntfds[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (client_unit->cnntfds[i] < 0) {
            PRINT_ERROR("client can't create socket! ");
            return PROGRAM_FAULT;
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr(client_unit->ip);
        server_addr.sin_port = htons(client_unit->port);

        int32_t connect_ret = connect(client_unit->cnntfds[i], (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (connect_ret < 0) {
            if (errno != EINPROGRESS) {
                PRINT_ERROR("client can't connect to the server! ");
                return PROGRAM_FAULT;
            } else {
                ep_ev.events = EPOLLOUT;
            }
        } else {
            ep_ev.events = EPOLLIN | EPOLLET;
            client_unit->connections = i + 1;
        }
        ep_ev.data.fd = client_unit->cnntfds[i];
        if (epoll_ctl(client_unit->epfd, EPOLL_CTL_ADD, client_unit->cnntfds[i], &ep_ev) < 0) {
            PRINT_ERROR("client cant't set epoll! ");
            return PROGRAM_FAULT;
        }

        clithd_debug_print(client_unit, "connect", client_unit->ip, client_unit->port);
    }

    return PROGRAM_OK;
}

// the single thread, client processes epoll events
int32_t clithd_proc_epevs(struct ClientUnit *client_unit)
{
    int32_t epoll_nfds = epoll_wait(client_unit->epfd, client_unit->epevs, CLIENT_EPOLL_SIZE_MAX, CLIENT_EPOLL_WAIT_TIMEOUT);
    if (epoll_nfds < 0) {
        PRINT_ERROR("client epoll wait error! ");
        return PROGRAM_FAULT;
    }

    struct epoll_event ep_ev;
    for (int i = 0; i < epoll_nfds; ++i) {
        if (client_unit->epevs[i].events == EPOLLOUT) {
            int32_t connect_error = 0;
            socklen_t connect_error_len = sizeof(connect_error);
            if (getsockopt(client_unit->epevs[i].data.fd, SOL_SOCKET, SO_ERROR, (void *)(&connect_error), &connect_error_len)) {
                PRINT_ERROR("client can't get socket option! ");
                return PROGRAM_FAULT;
            }
            if (connect_error < 0) {
                PRINT_ERROR("client connect error %d! ", connect_error);
                return PROGRAM_FAULT;
            } else {
                // firstly ask
            }
        }

        if (client_unit->epevs[i].events == EPOLLIN) {
            struct sockaddr_in server_addr;
            socklen_t server_addr_len = sizeof(server_addr);

            if (getpeername(client_unit->epevs[i].data.fd, (struct sockaddr *)&server_addr, &server_addr_len) < 0) {
                PRINT_ERROR("client can't socket peername! ");
                return PROGRAM_FAULT;
            }
            int32_t client_handle_ret = client_chk_ans(client_unit->epevs[i].data.fd, client_unit->pktlen, client_unit->verify, &client_unit->msg_idx);
            if (client_handle_ret == PROGRAM_FAULT) {
                --client_unit->connections;
                if (epoll_ctl(client_unit->epfd, EPOLL_CTL_DEL, client_unit->epevs[i].data.fd, &ep_ev) < 0) {
                    PRINT_ERROR("client can't delete socket '%d' to control epoll! ", client_unit->epevs[i].data.fd);
                    return PROGRAM_FAULT;
                }
            } else if (client_handle_ret == PROGRAM_ABORT) {
                --client_unit->connections;
                if (close(client_unit->epevs[i].data.fd) < 0) {
                    PRINT_ERROR("client can't close the socket! ");
                    return PROGRAM_FAULT;
                }
                clithd_debug_print(client_unit, "close", inet_ntoa(server_addr.sin_addr), server_addr.sin_port);
            } else {
                clithd_debug_print(client_unit, "receive", inet_ntoa(server_addr.sin_addr), server_addr.sin_port);
            }
        }
    }

    return PROGRAM_OK;
}

// create client of single thread
void *client_s_create(void *arg)
{
    struct ClientUnit *client_unit = (struct ClientUnit *)arg;

    if (clithd_get_epfd(client_unit) < 0) {
       exit(PROGRAM_FAULT);
    }

    while (true) {
        if (clithd_proc_epevs(client_unit) < 0) {
            exit(PROGRAM_FAULT);
        }
    }

    for (int i = 0; i < client_unit->connect_num; ++i) {
        if (close(*(client_unit->cnntfds + i)) < 0) {
            exit(PROGRAM_FAULT);
        }
    }
    if (close(client_unit->epfd) < 0) {
        exit(PROGRAM_FAULT);
    }

    return (void *)PROGRAM_OK;
}

// create client
int32_t client_create(struct ProgramParams *params)
{
    const uint32_t connect_num = params->connect_num;
    const uint32_t thread_num = params->thread_num;
    pthread_t *tids = (pthread_t *)malloc(thread_num * sizeof(pthread_t));
    struct ClientUnit *client_unit = (struct ClientUnit *)malloc(thread_num * sizeof(struct ClientUnit *));

    pthread_mutex_t lock;
    if (params->debug == true) {
        if (pthread_mutex_init(&lock, NULL) != 0) {
            PRINT_ERROR("client can't init posix mutex! ");
            return PROGRAM_FAULT;
        }
    }

    for (int i = 0; i < params->thread_num; ++i) {
        (client_unit + i)->cnntfds = (int32_t *)malloc(connect_num * sizeof(int32_t *));
        (client_unit + i)->epfd = -1;
        (client_unit + i)->epevs = (struct epoll_event *)malloc(CLIENT_EPOLL_SIZE_MAX * sizeof(struct epoll_event *));
        (client_unit + i)->lock = (params->debug == true) ? &lock : NULL;
        (client_unit + i)->connections = 0;
        (client_unit + i)->ip = params->ip;
        (client_unit + i)->port = params->port;
        (client_unit + i)->connect_num = params->connect_num;
        (client_unit + i)->pktlen = params->pktlen;
        (client_unit + i)->verify = params->verify;
        (client_unit + i)->msg_idx = 0;
        (client_unit + i)->debug = params->debug;

        if (pthread_create((tids + i), NULL, client_s_create, client_unit + i) != 0) {
            PRINT_ERROR("client can't create thread of poisx! ");
            return PROGRAM_FAULT;
        }
    }

    for (int i = 0; i < params->thread_num; ++i) {
        pthread_join(*(tids + i), NULL);
    }

    return PROGRAM_OK; 
}
