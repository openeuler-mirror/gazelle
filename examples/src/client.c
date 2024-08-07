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
#include "server.h"

static pthread_mutex_t client_debug_mutex;      // the client mutex for printf
struct Client *g_client_begin = NULL;

static int32_t client_process_ask(struct ClientHandler *client_handler, struct ClientUnit *client_unit);
static void client_get_domain_ipversion(uint8_t protocol_type, struct ClientUnit *client_unit);

static void timer_handle(int signum)
{
    if (g_client_begin == NULL) {
        return;
    }

    struct ClientUnit *begin_client_unit = g_client_begin->uints;
    while (begin_client_unit != NULL) {
        if (begin_client_unit->domain != NULL && strcmp(begin_client_unit->domain, "udp") != 0) {
            begin_client_unit = begin_client_unit->next;
            continue;
        }
        for (int32_t i = 0; i < begin_client_unit->connect_num; i++) {
            struct ClientHandler *handle = begin_client_unit->handlers + i;
            if (handle->sendtime_interverl == TIME_SEND_INTERVAL) {
                client_process_ask(handle, begin_client_unit);
            } else {
                handle->sendtime_interverl++;
            }
        }

        begin_client_unit = begin_client_unit->next;
    }
    alarm(TIME_SCAN_INTERVAL);
}

static struct Client_domain_ip g_cfgmode_map[PROTOCOL_MODE_MAX] = {
    [V4_TCP] = {"tcp", AF_INET},
    [V6_TCP] = {"tcp", AF_INET6},
    [V4_UDP] = {"udp", AF_INET},
    [V6_UDP] = {"udp", AF_INET6},
    [UDP_MULTICAST] = {"udp", AF_INET}};

// the single thread, client prints informations
void client_debug_print(const char *ch_str, const char *act_str, ip_addr_t *ip, uint16_t port, bool debug)
{
    if (debug == true) {
        pthread_mutex_lock(&client_debug_mutex);
        uint8_t str_len = ip->addr_family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
        char str_ip[str_len];
        inet_ntop(ip->addr_family, &ip->u_addr, str_ip, str_len);
        PRINT_CLIENT("[%s] [pid: %d] [tid: %ld] [%s <- %s:%d]. ", \
                    ch_str, \
                    getpid(), \
                    pthread_self(), \
                    act_str, \
                    str_ip, \
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
        uint64_t begin_time = (uint64_t)begin.tv_sec * TIMES_CONVERSION_RATE +
                              (uint64_t)begin.tv_usec / TIMES_CONVERSION_RATE;

        uint32_t curr_connect = 0;
        double bytes_ps = 0;
        uint64_t begin_send_bytes = 0;
        struct ClientUnit *begin_uint = client->uints;
        while (begin_uint != NULL) {
            curr_connect += begin_uint->curr_connect;
            begin_send_bytes += begin_uint->threadVolume.send_bytes;
            begin_uint = begin_uint->next;
        }

        struct timeval delay;
        delay.tv_sec = 0;
        delay.tv_usec = TERMINAL_REFRESH_MS * TIMES_CONVERSION_RATE;
        select(0, NULL, NULL, NULL, &delay);

        uint64_t end_send_bytes = 0;
        struct ClientUnit *end_uint = client->uints;
        while (end_uint != NULL) {
            end_send_bytes += end_uint->threadVolume.send_bytes;
            end_uint = end_uint->next;
        }

        struct timeval end;
        gettimeofday(&end, NULL);
        uint64_t end_time = (uint64_t)end.tv_sec * TIMES_CONVERSION_RATE +
                            (uint64_t)end.tv_usec / TIMES_CONVERSION_RATE;

        double bytes_sub = end_send_bytes > begin_send_bytes ? (double)(end_send_bytes - begin_send_bytes) : 0;
        double time_sub = end_time > begin_time ? (double)(end_time - begin_time) / TIMES_CONVERSION_RATE : 0;

        bytes_ps = bytes_sub  / time_sub;

        if (bytes_ps < KB) {
            PRINT_CLIENT_DATAFLOW("[connect num]: %d, [send]: %.3f B/s", curr_connect, bytes_ps);
        } else if (bytes_ps < MB) {
            PRINT_CLIENT_DATAFLOW("[connect num]: %d, [send]: %.3f KB/s", curr_connect, bytes_ps / KB);
        } else {
            PRINT_CLIENT_DATAFLOW("[connect num]: %d, [send]: %.3f MB/s", curr_connect, bytes_ps / MB);
        }
        
        if (client->loop) {
            printf("\033[2A\033[120C\033[K\n");
            return;
        }
        printf("\033[A\033[K");
    }
}

static int32_t client_process_ask(struct ClientHandler *client_handler, struct ClientUnit *client_unit)
{
    // not support udp+v6 currently
    if (strcmp(client_unit->domain, "udp") == 0 && client_unit->ip.addr_family == AF_INET6) {
        return PROGRAM_OK;
    }

    int32_t client_ask_ret = client_ask(client_handler, client_unit);
    if (client_ask_ret == PROGRAM_FAULT) {
        --client_unit->curr_connect;
        struct epoll_event ep_ev;
        if (client_handler->fd > 0 && epoll_ctl(client_unit->epfd, EPOLL_CTL_DEL, (client_handler)->fd, &ep_ev) < 0) {
            PRINT_ERROR("client can't delete socket '%d' to control epoll %d! ", (client_handler)->fd, errno);
            return PROGRAM_FAULT;
        }
    } else if (client_ask_ret == PROGRAM_ABORT) {
        --client_unit->curr_connect;
        if (close((client_handler)->fd) < 0) {
            PRINT_ERROR("client can't close the socket! ");
            return PROGRAM_FAULT;
        }
        client_debug_print("client unit", "close", &client_unit->ip, client_unit->port, client_unit->debug);
    } else {
        client_unit->threadVolume.send_bytes += client_unit->pktlen;
        client_handler->sendtime_interverl = 0;
        client_debug_print("client unit", "send", &client_unit->ip, client_unit->port, client_unit->debug);
    }
    return PROGRAM_OK;
}

static void client_get_thread_volume(struct Client *client, struct ThreadUintInfo *threadVolume)
{
    int index = 0;
    struct ClientUnit *curUint = client->uints;
    while (curUint != NULL && index < client->threadNum) {
        threadVolume[index].send_bytes = curUint->threadVolume.send_bytes;

        threadVolume[index].cur_connect_num = curUint->curr_connect;
        threadVolume[index].thread_id = curUint->threadVolume.thread_id;
        threadVolume[index].domain = curUint->threadVolume.domain;
        threadVolume[index].ip_type_info = curUint->threadVolume.ip_type_info;
        curUint = curUint->next;
        index++;
    }
}

void client_info_print_mixed(struct Client *client, struct ThreadUintInfo *threadVolume,
                             struct ThreadUintInfo *endThreadVolume)
{
    if (client->debug == true) {
        return;
    }
    int32_t pthread_num = client->threadNum;
    int32_t not_support_thread = 0;
    struct timeval cur = {0};

    gettimeofday(&cur, NULL);
    uint64_t begin_time = (uint64_t)cur.tv_sec * TIMES_CONVERSION_RATE + (uint64_t)cur.tv_usec / TIMES_CONVERSION_RATE;

    client_get_thread_volume(client, threadVolume);

    struct timeval delay;
    delay.tv_sec = 0;
    delay.tv_usec = TERMINAL_REFRESH_MS * TIMES_CONVERSION_RATE;
    select(0, NULL, NULL, NULL, &delay);

    client_get_thread_volume(client, endThreadVolume);

    gettimeofday(&cur, NULL);
    uint64_t end_time = (uint64_t)cur.tv_sec * TIMES_CONVERSION_RATE + (uint64_t)cur.tv_usec / TIMES_CONVERSION_RATE;

    for (int i = 0; i < pthread_num; i++) {
        uint64_t begin_send_bytes = threadVolume[i].send_bytes;
        uint64_t end_send_bytes = endThreadVolume[i].send_bytes;
        pthread_t thread_id = endThreadVolume[i].thread_id;
        uint32_t connect_num = endThreadVolume[i].cur_connect_num;
        char *domain = endThreadVolume[i].domain;
        char *ip_ver = endThreadVolume[i].ip_type_info;

        if (thread_id == 0) {
            not_support_thread++;
            continue;
        }

        double bytes_sub = end_send_bytes > begin_send_bytes ? (double)(end_send_bytes - begin_send_bytes) : 0;
        double time_sub = end_time > begin_time ? (double)(end_time - begin_time) / TIMES_CONVERSION_RATE : 0;
        double bytes_ps = bytes_sub / time_sub;

        if (bytes_ps < KB) {
            PRINT_CLIENT_DATAFLOW("threadID=%-15lu, %s_%-9s [connect num]: %u, [send]: %.3f B/s",
                                  thread_id, domain, ip_ver, connect_num, bytes_ps);
        } else if (bytes_ps < MB) {
            PRINT_CLIENT_DATAFLOW("threadID=%-15lu, %s_%-9s [connect num]: %u, [send]: %.3f kB/s",
                                  thread_id, domain, ip_ver, connect_num, bytes_ps / KB);
        } else {
            PRINT_CLIENT_DATAFLOW("threadID=%-15lu, %s_%-9s [connect num]: %u, [send]: %.3f MB/s",
                                  thread_id, domain, ip_ver, connect_num, bytes_ps / MB);
        }
    }
    printf("\033[%dA\033[K", pthread_num - not_support_thread);
}

void loop_info_print()
{
    printf(" ");
    if (strcmp(loopmod.model, "mum") == 0) {
        sermum_info_print(loopmod.server_mum_info);
    } else {
        sermud_info_print(loopmod.server_mud_info);
    }
}

// the single thread, client try to connect to server, register to epoll
int32_t client_thread_try_connect(struct ClientHandler *client_handler, struct ClientUnit *client_unit)
{
    int32_t create_socket_and_connect_ret = create_socket_and_connect(&(client_handler->fd), client_unit);
    if (create_socket_and_connect_ret == PROGRAM_INPROGRESS) {
        return PROGRAM_OK;
    }
    return PROGRAM_OK;
}

// the single thread, client retry to connect to server, register to epoll
int32_t client_thread_retry_connect(struct ClientUnit *client_unit, struct ClientHandler *client_handler)
{
    int32_t clithd_try_cnntask_ret = client_thread_try_connect(client_handler, client_unit);
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

    sockaddr_t server_addr;
    socklen_t server_addr_len = client_unit->ip.addr_family ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    if (getpeername(client_handler->fd, (struct sockaddr *)&server_addr, &server_addr_len) < 0) {
        PRINT_ERROR("client can't socket peername %d! ", errno);
        return PROGRAM_FAULT;
    }

    // sockaddr to ip, port
    ip_addr_t remote_ip;
    uint16_t remote_port = ((struct sockaddr_in*)&server_addr)->sin_port;
    if (((struct sockaddr *)&server_addr)->sa_family == AF_INET) {
        remote_ip.addr_family = AF_INET;
        remote_ip.u_addr.ip4 = ((struct sockaddr_in *)&server_addr)->sin_addr;
    } else if (((struct sockaddr *)&server_addr)->sa_family == AF_INET6) {
        remote_ip.addr_family = AF_INET6;
        remote_ip.u_addr.ip6 = ((struct sockaddr_in6 *)&server_addr)->sin6_addr;
    }

    client_debug_print("client unit", "connect", &remote_ip, remote_port, client_unit->debug);

    return client_process_ask(client_handler, client_unit);
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
        int32_t clithd_try_cnntask_ret = client_thread_try_connect(client_unit->handlers + i, client_unit);
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

            client_debug_print("client unit", "connect", &client_unit->ip, client_unit->port, client_unit->debug);

            int32_t client_ask_ret = client_process_ask(client_unit->handlers + i, client_unit);
            if (client_ask_ret != PROGRAM_OK) {
                return client_ask_ret;
            }
        }
    }

    return PROGRAM_OK;
}


static int32_t clithd_proc_epevs_epollout(struct epoll_event *curr_epev, struct ClientUnit *client_unit)
{
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
            return PROGRAM_OK;
        }
        PRINT_ERROR("client connect error %d! ", connect_error);
        return PROGRAM_FAULT;
    } else {
        ++(client_unit->curr_connect);

        sockaddr_t server_addr;
        socklen_t server_addr_len =
            client_unit->ip.addr_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        if (getpeername(client_handler->fd, (struct sockaddr *)&server_addr, &server_addr_len) < 0) {
            PRINT_ERROR("client can't socket peername %d! ", errno);
            return PROGRAM_FAULT;
        }

        // sockaddr to ip, port
        ip_addr_t remote_ip;
        uint16_t remote_port = ((struct sockaddr_in *)&server_addr)->sin_port;
        if (((struct sockaddr *)&server_addr)->sa_family == AF_INET) {
            remote_ip.addr_family = AF_INET;
            remote_ip.u_addr.ip4 = ((struct sockaddr_in *)&server_addr)->sin_addr;
        } else if (((struct sockaddr *)&server_addr)->sa_family == AF_INET6) {
            remote_ip.addr_family = AF_INET6;
            remote_ip.u_addr.ip6 = ((struct sockaddr_in6 *)&server_addr)->sin6_addr;
        }

        client_debug_print("client unit", "connect", &remote_ip, remote_port, client_unit->debug);

        int32_t client_ask_ret = client_process_ask(client_handler, client_unit);
        if (client_ask_ret != PROGRAM_OK) {
            return client_ask_ret;
        }
    }
    return PROGRAM_OK;
}

static int32_t clithd_proc_epevs_epollin(struct epoll_event *curr_epev, struct ClientUnit *client_unit)
{
    ip_addr_t *chkans_ip = client_unit->protocol_type_mode == UDP_MULTICAST ? &client_unit->groupip : &client_unit->ip;
    int32_t client_chkans_ret = client_chkans((struct ClientHandler *)curr_epev->data.ptr, client_unit->pktlen,
                                              client_unit->verify, client_unit->api, client_unit->domain, chkans_ip);
    struct ClientHandler *client_handler = (struct ClientHandler *)curr_epev->data.ptr;
    int32_t fd = client_handler->fd;
    if (client_chkans_ret == PROGRAM_FAULT) {
        --client_unit->curr_connect;
        struct epoll_event ep_ev;
        if (epoll_ctl(client_unit->epfd, EPOLL_CTL_DEL, fd, &ep_ev) < 0) {
            PRINT_ERROR("client can't delete socket '%d' to control epoll %d! ", fd, errno);
            return PROGRAM_FAULT;
        }
    } else if (client_chkans_ret == PROGRAM_ABORT) {
        --client_unit->curr_connect;
        if (close(fd) < 0) {
            PRINT_ERROR("client can't close the socket %d! ", errno);
            return PROGRAM_FAULT;
        }
        client_debug_print("client unit", "close", &client_unit->ip, client_unit->port, client_unit->debug);
    } else {
        client_unit->threadVolume.send_bytes += client_unit->pktlen;
        client_handler->sendtime_interverl = 0;
        client_debug_print("client unit", "receive", &client_unit->ip, client_unit->port, client_unit->debug);
    }
    return PROGRAM_OK;
}

// the single thread, client processes epoll events
int32_t clithd_proc_epevs(struct ClientUnit *client_unit)
{
    int32_t epoll_nfds = epoll_wait(client_unit->epfd, client_unit->epevs, CLIENT_EPOLL_SIZE_MAX, CLIENT_EPOLL_WAIT_TIMEOUT);
    int ret = 0;
    if (epoll_nfds < 0) {
        PRINT_ERROR("client epoll wait error %d! ", errno);
        return PROGRAM_FAULT;
    }


    for (int32_t i = 0; i < epoll_nfds; ++i) {
        struct epoll_event *curr_epev = client_unit->epevs + i;

        if (curr_epev->events == EPOLLERR && errno != 0) {
            PRINT_ERROR("client epoll wait error! %d", curr_epev->events);
            return PROGRAM_FAULT;
        } else if (curr_epev->events == EPOLLOUT) {
            ret = clithd_proc_epevs_epollout(curr_epev, client_unit);
            if (ret != PROGRAM_OK) {
                return ret;
            }
        } else if (curr_epev->events == EPOLLIN) {
            ret = clithd_proc_epevs_epollin(curr_epev, client_unit);
            if (ret != PROGRAM_OK) {
                return ret;
            }
        }
    }
    return PROGRAM_OK;
}

// create client of single thread and run
void *client_s_create_and_run(void *arg)
{
    struct ClientUnit *client_unit = (struct ClientUnit *)arg;
    // update domain ip info.
    client_get_domain_ipversion(client_unit->protocol_type_mode, client_unit);

    if (client_unit->protocol_type_mode == UDP_MULTICAST) {
        client_unit->threadVolume.ip_type_info = IPV4_MULTICAST;
    } else {
        client_unit->threadVolume.ip_type_info = (client_unit->ip.addr_family == AF_INET ? IPV4_STR : IPV6_STR);
    }
    client_unit->threadVolume.thread_id = pthread_self();

    client_unit->threadVolume.domain = client_unit->domain;

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

// prase the specific supported TCP IP types by cfg_mode.
static void client_get_protocol_type_by_cfgmode(uint8_t mode, int32_t *support_type_array, int32_t buff_len,
                                                int32_t *actual_len)
{
    int32_t index = 0;
    for (uint8_t i = V4_TCP; i < PROTOCOL_MODE_MAX; i++) {
        if (i == V6_UDP) {
            continue;
        }
        if (getbit_num(mode, i) == 1) {
            if (index >= buff_len) {
                PRINT_ERROR("index is over, index =%d", index);
                return;
            }
            support_type_array[index] = i;
            index++;
        }
    }
    *actual_len = index;
}

static void client_get_domain_ipversion(uint8_t protocol_type, struct ClientUnit *client_unit)
{
    client_unit->domain = g_cfgmode_map[protocol_type].domain;
    client_unit->ip.addr_family = g_cfgmode_map[protocol_type].ip_family;
}

static void alarm_init()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &timer_handle;
    sigaction(SIGALRM, &sa, NULL);
    alarm(TIME_SCAN_INTERVAL);
}

// create client and run
int32_t client_create_and_run(struct ProgramParams *params)
{
    const uint32_t connect_num = params->connect_num;
    const uint32_t thread_num = params->thread_num;
    pthread_t *tids = (pthread_t *)malloc(thread_num * sizeof(pthread_t));
    struct Client *client = (struct Client *)malloc(sizeof(struct Client));
    g_client_begin = client;
    client->threadNum = thread_num;

    struct ClientUnit *client_unit = (struct ClientUnit *)malloc(sizeof(struct ClientUnit));
    memset_s(client_unit, sizeof(struct ClientUnit), 0, sizeof(struct ClientUnit));
    int32_t protocol_support_array[PROTOCOL_MODE_MAX] = {0};
    int32_t number_of_support_type = 1;

    if (pthread_mutex_init(&client_debug_mutex, NULL) < 0) {
        PRINT_ERROR("client can't init posix mutex %d! ", errno);
        return PROGRAM_FAULT;
    }

    bool v4_cfg_flag = (strcmp(params->ip, PARAM_DEFAULT_IP) != 0);
    bool v6_cfg_flag = (strcmp(params->ipv6, PARAM_DEFAULT_IP_V6) != 0);
    bool multcact_cfg_flag = (strcmp(params->groupip, PARAM_DEFAULT_GROUPIP) != 0);

    bool mixed_mode_flag = false;
    if ((strchr(params->domain, ',') != NULL) || (v4_cfg_flag && v6_cfg_flag) ||
        (multcact_cfg_flag && (v4_cfg_flag || v6_cfg_flag))) {
        mixed_mode_flag = true;
    }

    client->uints = client_unit;
    client->debug = params->debug;

    uint8_t protocol_type_mode = program_get_protocol_mode_by_domain_ip(params->domain, params->ip, params->ipv6,
                                                                        params->groupip);

    client_get_protocol_type_by_cfgmode(protocol_type_mode, protocol_support_array, PROTOCOL_MODE_MAX,
        &number_of_support_type);

    uint32_t port = UNIX_TCP_PORT_MIN;
    uint32_t sport = 0;
    uint32_t sp = 0;

    alarm_init();

    for (uint32_t i = 0; i < thread_num; ++i) {
        client_unit->handlers = (struct ClientHandler *)malloc(connect_num * sizeof(struct ClientHandler));
        for (uint32_t j = 0; j < connect_num; ++j) {
            client_unit->handlers[j].fd = -1;
            client_unit->handlers[j].msg_idx = 0;
        }
        client_unit->epfd = -1;
        client_unit->epevs = (struct epoll_event *)malloc(CLIENT_EPOLL_SIZE_MAX * sizeof(struct epoll_event));
        client_unit->curr_connect = 0;

        client_unit->threadVolume.cur_connect_num = 0;
        client_unit->threadVolume.thread_id = 0;
        client_unit->threadVolume.send_bytes = 0;
        client_unit->threadVolume.ip_type_info = INVAILD_STR;
        client_unit->threadVolume.domain = INVAILD_STR;

        client_unit->ip.addr_family = params->addr_family;
        inet_pton(AF_INET, params->ip, &client_unit->ip.u_addr.ip4);
        inet_pton(AF_INET6, params->ipv6, &client_unit->ip.u_addr.ip6);
        client_unit->groupip.addr_family = AF_INET;
        inet_pton(AF_INET, params->groupip, &client_unit->groupip.u_addr);
        client_unit->groupip_interface.addr_family = params->addr_family;
        inet_pton(AF_INET, params->groupip_interface, &client_unit->groupip_interface.u_addr);

        /* loop to set ports to each client_units */
        while (!((params->port)[port])) {
            port = (port + 1) % UNIX_TCP_PORT_MAX;
        }
        client_unit->port = htons(port++);

        sp = sport;
        sport++;
        while (!((params->sport)[sport]) && (sport != sp)) {
            sport = (sport + 1) % UNIX_TCP_PORT_MAX;
        }

        client_unit->sport = htons(sport);
        client_unit->connect_num = params->connect_num;
        client_unit->pktlen = params->pktlen;
        if (strcmp(params->as, "loop") == 0) {
            client_unit->loop = 1;
        } else {
            client_unit->loop = 0;
        }

        client_unit->verify = params->verify;
        client_unit->domain = params->domain;
        client_unit->api = params->api;
        client_unit->epollcreate = params->epollcreate;
        client_unit->debug = params->debug;
        client_unit->next = (struct ClientUnit *)malloc(sizeof(struct ClientUnit));
        memset_s(client_unit->next, sizeof(struct ClientUnit), 0, sizeof(struct ClientUnit));

        if (number_of_support_type > 0) {
            int32_t index = i % number_of_support_type;
            client_unit->protocol_type_mode = protocol_support_array[index];
        }
        if (client_unit->protocol_type_mode == V4_UDP || client_unit->protocol_type_mode == V6_UDP ||
            client_unit->protocol_type_mode == UDP_MULTICAST) {
            client_unit->pktlen = params->pktlen > UDP_PKTLEN_MAX ? UDP_PKTLEN_MAX : params->pktlen;
        } else {
            client_unit->pktlen = params->pktlen;
        }
        if (pthread_create((tids + i), NULL, client_s_create_and_run, client_unit) < 0) {
            PRINT_ERROR("client can't create thread of poisx %d! ", errno);
            return PROGRAM_FAULT;
        }
        client_unit = client_unit->next;
    }

    if (client->debug == false) {
        printf("[program informations]: \n\n");
    }

    struct ThreadUintInfo *beginVolume = (struct ThreadUintInfo *)malloc(thread_num * sizeof(struct ThreadUintInfo));
    if (beginVolume == NULL) {
        return PROGRAM_FAULT;
    }
    memset_s(beginVolume, thread_num * sizeof(struct ThreadUintInfo), 0, thread_num * sizeof(struct ThreadUintInfo));
    struct ThreadUintInfo *endVolume = (struct ThreadUintInfo *)malloc(thread_num * sizeof(struct ThreadUintInfo));
    if (endVolume == NULL) {
        return PROGRAM_FAULT;
    }
    memset_s(endVolume, thread_num * sizeof(struct ThreadUintInfo), 0, thread_num * sizeof(struct ThreadUintInfo));

    if (strcmp(params->as, "loop") == 0) {
        client->loop = true;
    }

    while (true) {
	if (strcmp(params->as, "loop") == 0) {
            loop_info_print();
	}
        if (mixed_mode_flag == true) {
            client_info_print_mixed(client, beginVolume, endVolume);
        } else {
            client_info_print(client);
        }
    }
    free(beginVolume);
    free(endVolume);

    pthread_mutex_destroy(&client_debug_mutex);

    return PROGRAM_OK;
}
