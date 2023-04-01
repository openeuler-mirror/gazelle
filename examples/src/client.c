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


static pthread_mutex_t client_debug_mutex;      // the client mutex for printf


// the single thread, client prints informations
void client_debug_print(const char *ch_str, const char *act_str, in_addr_t ip, uint16_t port, bool debug)
{
    if (debug == true) {
        pthread_mutex_lock(&client_debug_mutex);
        struct in_addr sin_addr;
        sin_addr.s_addr = ip;
        PRINT_CLIENT("[%s] [pid: %d] [tid: %ld] [%s <- %s:%d]. ", \
                    ch_str, \
                    getpid(), \
                    pthread_self(), \
                    act_str, \
                    inet_ntoa(sin_addr), \
                    ntohs(port));
        pthread_mutex_unlock(&client_debug_mutex);
    }
}

// the client prints informations
void client_info_print(struct Client *client)
{
    if (client->debug == false) {
        struct timeval begin;
        gettimeofday(&begin, NULL);
        uint64_t begin_time = (uint64_t)begin.tv_sec * 1000 + (uint64_t)begin.tv_usec / 1000;

        uint32_t curr_connect = 0;
        double bytes_ps = 0;
        uint64_t begin_send_bytes = 0;
        struct ClientUnit *begin_uint = client->uints;
        while (begin_uint != NULL) {
            curr_connect += begin_uint->curr_connect;
            begin_send_bytes += begin_uint->send_bytes;
            begin_uint = begin_uint->next;
        }

        struct timeval delay;
        delay.tv_sec = 0;
        delay.tv_usec = TERMINAL_REFRESH_MS * 1000;
        select(0, NULL, NULL, NULL, &delay);

        uint64_t end_send_bytes = 0;
        struct ClientUnit *end_uint = client->uints;
        while (end_uint != NULL) {
            end_send_bytes += end_uint->send_bytes;
            end_uint = end_uint->next;
        }

        struct timeval end;
        gettimeofday(&end, NULL);
        uint64_t end_time = (uint64_t)end.tv_sec * 1000 + (uint64_t)end.tv_usec / 1000;
        
        double bytes_sub = end_send_bytes > begin_send_bytes ? (double)(end_send_bytes - begin_send_bytes) : 0;
        double time_sub = end_time > begin_time ? (double)(end_time - begin_time) / 1000 : 0;

        bytes_ps = bytes_sub  / time_sub;

        if (bytes_ps < 1024) {
            PRINT_CLIENT_DATAFLOW("[connect num]: %d, [send]: %.3f B/s", curr_connect, bytes_ps);
        } else if (bytes_ps < (1024 * 1024)) {
            PRINT_CLIENT_DATAFLOW("[connect num]: %d, [send]: %.3f KB/s", curr_connect, bytes_ps / 1024);
        } else {
            PRINT_CLIENT_DATAFLOW("[connect num]: %d, [send]: %.3f MB/s", curr_connect, bytes_ps / (1024 * 1024));
        }
    }
}

// the single thread, client try to connect to server, register to epoll
int32_t client_thread_try_connect(struct ClientHandler *client_handler, int32_t epoll_fd, in_addr_t ip, uint16_t port, const char *domain)
{
    int32_t create_socket_and_connect_ret = create_socket_and_connect(&(client_handler->fd), ip, port, domain);
    if (create_socket_and_connect_ret == PROGRAM_INPROGRESS) {
        struct epoll_event ep_ev;
        ep_ev.events = EPOLLOUT;
        ep_ev.data.ptr = (void *)client_handler;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_handler->fd, &ep_ev) < 0) {
            PRINT_ERROR("client cant't set epoll %d! ", errno);
            return PROGRAM_FAULT;
        }
    }
    return PROGRAM_OK;
}

// the single thread, client retry to connect to server, register to epoll
int32_t client_thread_retry_connect(struct ClientUnit *client_unit, struct ClientHandler *client_handler)
{
    int32_t clithd_try_cnntask_ret = client_thread_try_connect(client_handler, client_unit->epfd, client_unit->ip, client_unit->port, client_unit->domain);
    if (clithd_try_cnntask_ret < 0) {
        if (clithd_try_cnntask_ret == PROGRAM_INPROGRESS) {
            return PROGRAM_OK;
        }
        return PROGRAM_FAULT;
    }
    struct epoll_event ep_ev;
    ep_ev.events = EPOLLIN | EPOLLET;
    ep_ev.data.ptr = (void *)client_handler;
    if (epoll_ctl(client_unit->epfd, EPOLL_CTL_ADD, client_handler->fd, &ep_ev) < 0) {
        PRINT_ERROR("client cant't set epoll %d! ", errno);
        return PROGRAM_FAULT;
    }

    ++(client_unit->curr_connect);

    struct sockaddr_in server_addr;
    socklen_t server_addr_len = sizeof(server_addr);
    if (getpeername(client_handler->fd, (struct sockaddr *)&server_addr, &server_addr_len) < 0) {
        PRINT_ERROR("client can't socket peername %d! ", errno);
        return PROGRAM_FAULT;
    }
    client_debug_print("client unit", "connect", server_addr.sin_addr.s_addr, server_addr.sin_port, client_unit->debug);

    int32_t client_ask_ret = client_ask(client_handler, client_unit->pktlen, client_unit->api);
    if (client_ask_ret == PROGRAM_FAULT) {
        --client_unit->curr_connect;
        struct epoll_event ep_ev;
        if (epoll_ctl(client_unit->epfd, EPOLL_CTL_DEL, client_handler->fd, &ep_ev) < 0) {
            PRINT_ERROR("client can't delete socket '%d' to control epoll %d! ", client_handler->fd, errno);
            return PROGRAM_FAULT;
        }
    } else if (client_ask_ret == PROGRAM_ABORT) {
        --client_unit->curr_connect;
        if (close(client_handler->fd) < 0) {
            PRINT_ERROR("client can't close the socket %d! ", errno);
            return PROGRAM_FAULT;
        }
        client_debug_print("client unit", "close", server_addr.sin_addr.s_addr, server_addr.sin_port, client_unit->debug);
    } else {
        client_unit->send_bytes += client_unit->pktlen;
        client_debug_print("client unit", "send", server_addr.sin_addr.s_addr, server_addr.sin_port, client_unit->debug);
    }

    return PROGRAM_OK;
}

// the single thread, client connects and gets epoll feature descriptors
int32_t client_thread_create_epfd_and_reg(struct ClientUnit *client_unit)
{
    const uint32_t connect_num = client_unit->connect_num;
    //jacky modify
    if (strcmp(client_unit->epollcreate, "ec1") == 0) {
        client_unit->epfd = epoll_create1(EPOLL_CLOEXEC);
    } else {
        client_unit->epfd = epoll_create(CLIENT_EPOLL_SIZE_MAX);
    }
    
    if (client_unit->epfd < 0) {
        PRINT_ERROR("client can't create epoll %d! ", errno);
        return PROGRAM_FAULT;
    }

    for (uint32_t i = 0; i < connect_num; ++i) {
        int32_t clithd_try_cnntask_ret = client_thread_try_connect(client_unit->handlers + i, client_unit->epfd, client_unit->ip, client_unit->port, client_unit->domain);
        if (clithd_try_cnntask_ret < 0) {
            if (clithd_try_cnntask_ret == PROGRAM_INPROGRESS) {
                continue;
            }
            return PROGRAM_FAULT;
        } else {
            struct epoll_event ep_ev;
            ep_ev.events = EPOLLIN | EPOLLET;
            ep_ev.data.ptr = (struct ClientHandler *)(client_unit->handlers + i);
            if (epoll_ctl(client_unit->epfd, EPOLL_CTL_ADD, (client_unit->handlers + i)->fd, &ep_ev) < 0) {
                PRINT_ERROR("client cant't set epoll %d! ", errno);
                return PROGRAM_FAULT;
            }

            ++(client_unit->curr_connect);

            struct sockaddr_in server_addr;
            socklen_t server_addr_len = sizeof(server_addr);
            if (getpeername((client_unit->handlers + i)->fd, (struct sockaddr *)&server_addr, &server_addr_len) < 0) {
                PRINT_ERROR("client can't socket peername %d! ", errno);
                return PROGRAM_FAULT;
            }
            client_debug_print("client unit", "connect", server_addr.sin_addr.s_addr, server_addr.sin_port, client_unit->debug);

            int32_t client_ask_ret = client_ask(client_unit->handlers + i, client_unit->pktlen, client_unit->api);
            if (client_ask_ret == PROGRAM_FAULT) {
                --client_unit->curr_connect;
                struct epoll_event ep_ev;
                if (epoll_ctl(client_unit->epfd, EPOLL_CTL_DEL, (client_unit->handlers + i)->fd, &ep_ev) < 0) {
                    PRINT_ERROR("client can't delete socket '%d' to control epoll %d! ", client_unit->epevs[i].data.fd, errno);
                    return PROGRAM_FAULT;
                }
            } else if (client_ask_ret == PROGRAM_ABORT) {
                --client_unit->curr_connect;
                if (close((client_unit->handlers + i)->fd) < 0) {
                    PRINT_ERROR("client can't close the socket! ");
                    return PROGRAM_FAULT;
                }
                client_debug_print("client unit", "close", server_addr.sin_addr.s_addr, server_addr.sin_port, client_unit->debug);
            } else {
                client_unit->send_bytes += client_unit->pktlen;
                client_debug_print("client unit", "send", server_addr.sin_addr.s_addr, server_addr.sin_port, client_unit->debug);
            }
        }
    }

    return PROGRAM_OK;
}

// the single thread, client processes epoll events
int32_t clithd_proc_epevs(struct ClientUnit *client_unit)
{
    int32_t epoll_nfds = epoll_wait(client_unit->epfd, client_unit->epevs, CLIENT_EPOLL_SIZE_MAX, CLIENT_EPOLL_WAIT_TIMEOUT);
    if (epoll_nfds < 0) {
        PRINT_ERROR("client epoll wait error %d! ", errno);
        return PROGRAM_FAULT;
    }

    for (int32_t i = 0; i < epoll_nfds; ++i) {
        struct epoll_event *curr_epev = client_unit->epevs + i;

        if (curr_epev->events == EPOLLERR) {
            PRINT_ERROR("client epoll wait error! %d", curr_epev->events);
            return PROGRAM_FAULT;
        } else if (curr_epev->events == EPOLLOUT) {
            int32_t connect_error = 0;
            socklen_t connect_error_len = sizeof(connect_error);
            struct ClientHandler *client_handler = (struct ClientHandler *)curr_epev->data.ptr;
            if (getsockopt(client_handler->fd, SOL_SOCKET, SO_ERROR, (void *)(&connect_error), &connect_error_len) < 0) {
                PRINT_ERROR("client can't get socket option %d! ", errno);
                return PROGRAM_FAULT;
            }
            if (connect_error < 0) {
                if (connect_error == ETIMEDOUT) {
                    if (client_thread_retry_connect(client_unit, client_handler) < 0) {
                        return PROGRAM_FAULT;
                    }
                    continue;
                }
                PRINT_ERROR("client connect error %d! ", connect_error);
                return PROGRAM_FAULT;
            } else {
                ++(client_unit->curr_connect);

                struct sockaddr_in server_addr;
                socklen_t server_addr_len = sizeof(server_addr);
                if (getpeername(client_handler->fd, (struct sockaddr *)&server_addr, &server_addr_len) < 0) {
                    PRINT_ERROR("client can't socket peername %d! ", errno);
                    return PROGRAM_FAULT;
                }
                client_debug_print("client unit", "connect", server_addr.sin_addr.s_addr, server_addr.sin_port, client_unit->debug);
                
                int32_t client_ask_ret = client_ask(client_handler, client_unit->pktlen, client_unit->api);
                if (client_ask_ret == PROGRAM_FAULT) {
                    --client_unit->curr_connect;
                    struct epoll_event ep_ev;
                    if (epoll_ctl(client_unit->epfd, EPOLL_CTL_DEL, curr_epev->data.fd, &ep_ev) < 0) {
                        PRINT_ERROR("client can't delete socket '%d' to control epoll %d! ", curr_epev->data.fd, errno);
                        return PROGRAM_FAULT;
                    }
                } else if (client_ask_ret == PROGRAM_ABORT) {
                    --client_unit->curr_connect;
                    if (close(curr_epev->data.fd) < 0) {
                        PRINT_ERROR("client can't close the socket! ");
                        return PROGRAM_FAULT;
                    }
                    client_debug_print("client unit", "close", server_addr.sin_addr.s_addr, server_addr.sin_port, client_unit->debug);
                } else {
                    client_unit->send_bytes += client_unit->pktlen;
                    client_debug_print("client unit", "send", server_addr.sin_addr.s_addr, server_addr.sin_port, client_unit->debug);
                }
            }
        } else if (curr_epev->events == EPOLLIN) {
            struct sockaddr_in server_addr;
            socklen_t server_addr_len = sizeof(server_addr);
            struct ClientHandler *client_handler = (struct ClientHandler *)curr_epev->data.ptr;
            if (getpeername(client_handler->fd, (struct sockaddr *)&server_addr, &server_addr_len) < 0) {
                PRINT_ERROR("client can't socket peername %d! ", errno);
                return PROGRAM_FAULT;
            }
            int32_t client_chkans_ret = client_chkans((struct ClientHandler *)curr_epev->data.ptr, client_unit->pktlen, client_unit->verify, client_unit->api);
            if (client_chkans_ret == PROGRAM_FAULT) {
                --client_unit->curr_connect;
                struct epoll_event ep_ev;
                if (epoll_ctl(client_unit->epfd, EPOLL_CTL_DEL, curr_epev->data.fd, &ep_ev) < 0) {
                    PRINT_ERROR("client can't delete socket '%d' to control epoll %d! ", curr_epev->data.fd, errno);
                    return PROGRAM_FAULT;
                }
            } else if (client_chkans_ret == PROGRAM_ABORT) {
                --client_unit->curr_connect;
                if (close(curr_epev->data.fd) < 0) {
                    PRINT_ERROR("client can't close the socket %d! ", errno);
                    return PROGRAM_FAULT;
                }
                client_debug_print("client unit", "close", server_addr.sin_addr.s_addr, server_addr.sin_port, client_unit->debug);
            } else {
                client_unit->send_bytes += client_unit->pktlen;
                client_debug_print("client unit", "receive", server_addr.sin_addr.s_addr, server_addr.sin_port, client_unit->debug);
            }
        }
    }

    return PROGRAM_OK;
}

// create client of single thread and run
void *client_s_create_and_run(void *arg)
{
    struct ClientUnit *client_unit = (struct ClientUnit *)arg;

    if (client_thread_create_epfd_and_reg(client_unit) < 0) {
       exit(PROGRAM_FAULT);
    }
    while (true) {
        if (clithd_proc_epevs(client_unit) < 0) {
            exit(PROGRAM_FAULT);
        }
    }
    for (int i = 0; i < client_unit->connect_num; ++i) {
        close((client_unit->handlers + i)->fd);
    }
    close(client_unit->epfd);

    return (void *)PROGRAM_OK;
}

// create client and run
int32_t client_create_and_run(struct ProgramParams *params)
{
    const uint32_t connect_num = params->connect_num;
    const uint32_t thread_num = params->thread_num;
    pthread_t *tids = (pthread_t *)malloc(thread_num * sizeof(pthread_t));
    struct Client *client = (struct Client *)malloc(sizeof(struct Client));
    struct ClientUnit *client_unit = (struct ClientUnit *)malloc(sizeof(struct ClientUnit));

    if (pthread_mutex_init(&client_debug_mutex, NULL) < 0) {
        PRINT_ERROR("client can't init posix mutex %d! ", errno);
        return PROGRAM_FAULT;
    }

    client->uints = client_unit;
    client->debug = params->debug;

    for (uint32_t i = 0; i < thread_num; ++i) {
        client_unit->handlers = (struct ClientHandler *)malloc(connect_num * sizeof(struct ClientHandler));
        for (uint32_t j = 0; j < connect_num; ++j) {
            client_unit->handlers[j].fd = -1;
            client_unit->handlers[j].msg_idx = 0;
        }
        client_unit->epfd = -1;
        client_unit->epevs = (struct epoll_event *)malloc(CLIENT_EPOLL_SIZE_MAX * sizeof(struct epoll_event));
        client_unit->curr_connect = 0;
        client_unit->send_bytes = 0;
        client_unit->ip = inet_addr(params->ip);
        client_unit->port = htons(params->port);
        client_unit->connect_num = params->connect_num;
        client_unit->pktlen = params->pktlen;
        client_unit->verify = params->verify;
        client_unit->domain = params->domain;
        client_unit->api = params->api;
        client_unit->epollcreate = params->epollcreate;
        client_unit->debug = params->debug;
        client_unit->next = (struct ClientUnit *)malloc(sizeof(struct ClientUnit));
        memset_s(client_unit->next, sizeof(struct ClientUnit), 0, sizeof(struct ClientUnit));

        if (pthread_create((tids + i), NULL, client_s_create_and_run, client_unit) < 0) {
            PRINT_ERROR("client can't create thread of poisx %d! ", errno);
            return PROGRAM_FAULT;
        }
        client_unit = client_unit->next;
    }

    if (client->debug == false) {
        printf("[program informations]: \n\n");
    }
    while (true) {
        client_info_print(client);
    }

    pthread_mutex_destroy(&client_debug_mutex);

    return PROGRAM_OK;
}
