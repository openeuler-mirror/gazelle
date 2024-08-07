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


#include "parameter.h"

int32_t set_tcp_keep_alive_info(int32_t sockfd, int32_t tcp_keepalive_idle, int32_t tcp_keepalive_interval)
{
    int32_t ret = 0;
    int32_t keep_alive = 1;
    int32_t keep_idle = 1;
    int32_t keep_interval = 1;

    if ((tcp_keepalive_idle == PARAM_DEFAULT_KEEPALIVEIDLE) ||
        (tcp_keepalive_interval == PARAM_DEFAULT_KEEPALIVEIDLE)) {
        return 0;
    }

    keep_idle = tcp_keepalive_idle;
    ret = setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keep_alive, sizeof(keep_alive));
    if (ret != 0) {
        PRINT_ERROR("setsockopt keep_alive err ret=%d \n", ret);
        return ret;
    }

    ret = setsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, (void *)&keep_idle, sizeof(keep_idle));
    if (ret != 0) {
        PRINT_ERROR("setsockopt keep_idle err ret=%d \n", ret);
        return ret;
    }

    keep_interval = tcp_keepalive_interval;
    ret = setsockopt(sockfd, SOL_TCP, TCP_KEEPINTVL, (void *)&keep_interval, sizeof(keep_interval));
    if (ret != 0) {
        PRINT_ERROR("setsockopt keep_interval err ret=%d \n", ret);
        return ret;
    }
    return ret;
}

static int32_t process_unix_fd(int32_t *socket_fd, int32_t *listen_fd_array)
{
    struct sockaddr_un socket_addr;
    int32_t fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        PRINT_ERROR("can't create socket %d! ", errno);
        return PROGRAM_FAULT;
    }
    *socket_fd = fd;

    unlink(SOCKET_UNIX_DOMAIN_FILE);
    socket_addr.sun_family = AF_UNIX;
    strcpy_s(socket_addr.sun_path, sizeof(socket_addr.sun_path), SOCKET_UNIX_DOMAIN_FILE);
    if (bind(*socket_fd, (struct sockaddr *)&socket_addr, sizeof(struct sockaddr_un)) < 0) {
        PRINT_ERROR("can't bind the address to socket %d! ", errno);
        return PROGRAM_FAULT;
    }

    if (listen(*socket_fd, SERVER_SOCKET_LISTEN_BACKLOG) < 0) {
        PRINT_ERROR("server socket can't lisiten %d! ", errno);
        return PROGRAM_FAULT;
    }
    return PROGRAM_OK;
}

static int32_t process_udp_groupip(int32_t fd, ip_addr_t *ip, ip_addr_t *groupip, sockaddr_t *socker_add_info,
                                   ip_addr_t *groupip_interface)
{
    struct ip_mreq mreq;
    if (groupip->u_addr.ip4.s_addr) {
        mreq.imr_multiaddr = groupip->u_addr.ip4;
        if (groupip_interface->u_addr.ip4.s_addr) {
            mreq.imr_interface = groupip_interface->u_addr.ip4;
        } else {
            mreq.imr_interface = ip->u_addr.ip4;
        }

        if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(struct ip_mreq)) == -1) {
            PRINT_ERROR("can't set the address to group %d! ", errno);
            return PROGRAM_FAULT;
        }
        ((struct sockaddr_in *)socker_add_info)->sin_addr = groupip->u_addr.ip4;
        return PROGRAM_OK;
    }
    return PROGRAM_OK;
}

static int32_t server_create_sock(uint8_t protocol_mode, int32_t* fd_arry)
{
    bool ret = true;
    for (int32_t i = 0; i < PROTOCOL_MODE_MAX; i++) {
        if (getbit_num(protocol_mode, i) == 0)
            continue;
        if (i == V4_TCP) {
            fd_arry[i] = socket(AF_INET, SOCK_STREAM, 0);
        } else if (i == V6_TCP) {
            fd_arry[i] = socket(AF_INET6, SOCK_STREAM, 0);
        } else if (i == V4_UDP) {
            fd_arry[i] = socket(AF_INET, SOCK_DGRAM, 0);
        } else if (i == UDP_MULTICAST) {
            fd_arry[i] = socket(AF_INET, SOCK_DGRAM, 0);
        } else {
            continue;
        }
        if (fd_arry[i] < 0) {
            PRINT_ERROR("can't create socket type=%d errno=%d! ", i, errno);
            ret = false;
            break;
        }
    }

    if (ret == false) {
        for (int32_t i = 0; i< PROTOCOL_MODE_MAX; i++) {
            if (fd_arry[i] > 0) {
                close(fd_arry[i]);
            }
        }
        return PROGRAM_FAULT;
    }
    return PROGRAM_OK;
}

static int32_t socket_add_info_init(int32_t idx, uint16_t port, struct ServerIpInfo *server_ip_info,
                                    sockaddr_t *socker_add_info, int32_t *listen_fd_array)
{
    ip_addr_t *ip = &(server_ip_info->ip);
    ip_addr_t *groupip = &(server_ip_info->groupip);
    ip_addr_t *groupip_interface = &(server_ip_info->groupip_interface);

    uint32_t len = ((idx == V4_TCP || idx == V4_UDP || idx == UDP_MULTICAST) ?
        sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    memset_s(socker_add_info, len, 0, len);

    if (idx == V4_TCP || idx == V4_UDP) {
        ((struct sockaddr_in *)socker_add_info)->sin_addr = ip->u_addr.ip4;
    } else if (idx == V6_TCP) {
        ((struct sockaddr_in6 *)socker_add_info)->sin6_addr = ip->u_addr.ip6;
    } else if (idx == UDP_MULTICAST) {
        if (process_udp_groupip(listen_fd_array[idx], ip, groupip, socker_add_info, groupip_interface) != PROGRAM_OK) {
            return PROGRAM_FAULT;
        }
    }

    ((struct sockaddr *)socker_add_info)->sa_family = ((idx == V4_TCP || idx == V4_UDP || idx == UDP_MULTICAST) ?
                                                        AF_INET : AF_INET6);
    ((struct sockaddr_in *)socker_add_info)->sin_port = port;
    return PROGRAM_OK;
}

// create the socket and listen
int32_t create_socket_and_listen(int32_t *listen_fd_array, struct ServerIpInfo *server_ip_info,
                                 uint16_t port, uint8_t protocol_mode)
{
    int32_t port_multi = 1;
    uint32_t len = 0;
    sockaddr_t socker_add_info;

    if (getbit_num(protocol_mode, UNIX) == 1) {
        if (process_unix_fd(&listen_fd_array[UNIX], listen_fd_array) != PROGRAM_OK) {
            return PROGRAM_FAULT;
        }
        return PROGRAM_OK;
    }

    if (server_create_sock(protocol_mode, listen_fd_array) != PROGRAM_OK) {
        return PROGRAM_FAULT;
    }

    for (int32_t i = 0;i< PROTOCOL_MODE_MAX; i++) {
        if (listen_fd_array[i] <= 0)
            continue;
        if (setsockopt(listen_fd_array[i], SOL_SOCKET, SO_REUSEPORT, (void *)&port_multi, sizeof(int32_t)) < 0) {
            PRINT_ERROR("can't set the option of socket %d! ", errno);
            return PROGRAM_FAULT;
        }
        if (set_socket_unblock(listen_fd_array[i]) < 0) {
            PRINT_ERROR("can't set the socket to unblock! ");
            return PROGRAM_FAULT;
        }
        if (socket_add_info_init(i, port, server_ip_info, &socker_add_info, listen_fd_array) != PROGRAM_OK) {
            return PROGRAM_FAULT;
        }

        len = ((i == V4_TCP || i == V4_UDP || i == UDP_MULTICAST) ?
                sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));

        if (bind(listen_fd_array[i], (struct sockaddr *)&socker_add_info, len) < 0) {
            PRINT_ERROR("can't bind the address %d!, i=%d, listen_fd_array[i]=%d ", errno, i, listen_fd_array[i]);
            return PROGRAM_FAULT;
        }

        if (i == V4_TCP || i == V6_TCP) {
            if (listen(listen_fd_array[i], SERVER_SOCKET_LISTEN_BACKLOG) < 0) {
                PRINT_ERROR("server socket can't lisiten %d! ", errno);
                return PROGRAM_FAULT;
            }
        }
    }
    return PROGRAM_OK;
}

static int32_t creat_socket_init(int32_t *socket_fd, struct ClientUnit *client_unit, sockaddr_t *server_addr)
{
    ip_addr_t *ip = &client_unit->ip;
    const char *domain = client_unit->domain;

    if (strcmp(domain, "tcp") == 0) {
        *socket_fd = socket(ip->addr_family, SOCK_STREAM, 0);
    } else {
        *socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    }
    if (*socket_fd < 0) {
        PRINT_ERROR("client can't create socket %d! ", errno);
        return PROGRAM_FAULT;
    }

    if (set_socket_unblock(*socket_fd) < 0) {
        PRINT_ERROR("can't set the socket to unblock! ");
        return PROGRAM_FAULT;
    }

    ((struct sockaddr *)server_addr)->sa_family = ip->addr_family;

    return PROGRAM_OK;
}

static int32_t pocess_connect_sport(int32_t *socket_fd, struct ClientUnit *client_unit, sockaddr_t *server_addr)
{
    uint16_t sport = client_unit->sport;
    ip_addr_t *ip = &client_unit->ip;
    uint32_t addr_len = ip->addr_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    if (sport) {
        if (ip->addr_family == AF_INET) {
            ((struct sockaddr_in *)server_addr)->sin_addr.s_addr = htonl(INADDR_ANY);
        } else if (ip->addr_family == AF_INET6) {
            ((struct sockaddr_in6 *)server_addr)->sin6_addr = in6addr_any;
        }
        ((struct sockaddr_in *)server_addr)->sin_port = sport;
        if (bind(*socket_fd, (struct sockaddr *)server_addr, addr_len) < 0) {
            PRINT_ERROR("can't bind the address to socket %d! ", errno);
            return PROGRAM_FAULT;
        }
    }
    return PROGRAM_OK;
}

static int32_t pocess_unix_create_connect(int32_t *socket_fd)
{
    *socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (*socket_fd < 0) {
        PRINT_ERROR("client can't create socket %d! ", errno);
        return PROGRAM_FAULT;
    }

    struct sockaddr_un server_addr;
    server_addr.sun_family = AF_UNIX;
    strcpy_s(server_addr.sun_path, sizeof(server_addr.sun_path), SOCKET_UNIX_DOMAIN_FILE);
    if (connect(*socket_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) < 0) {
        if (errno == EINPROGRESS) {
            return PROGRAM_INPROGRESS;
        } else {
            PRINT_ERROR("client can't connect to the server %d! ", errno);
            return PROGRAM_FAULT;
        }
    }
    return PROGRAM_OK;
}

static int32_t pocess_udp_multicast(int32_t *socket_fd, struct ClientUnit *client_unit, sockaddr_t *server_addr)
{
    const uint32_t loop = client_unit->loop;
    ip_addr_t *groupip = &client_unit->groupip;
    if (client_unit->protocol_type_mode == UDP_MULTICAST) {
        /* set the local device for a multicast socket */
        ((struct sockaddr_in *)server_addr)->sin_addr = groupip->u_addr.ip4;

        struct in_addr localInterface;
        localInterface.s_addr = client_unit->groupip_interface.u_addr.ip4.s_addr;
        if (localInterface.s_addr) {
            if (setsockopt(*socket_fd, IPPROTO_IP, IP_MULTICAST_IF, (char *)&localInterface,
                           sizeof(localInterface)) < 0) {
                PRINT_ERROR("can't set the multicast interface %d! ", errno);
                return PROGRAM_FAULT;
            }
        }

        /* sent multicast packets should be looped back to the local socket */
        if (setsockopt(*socket_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) == -1) {
            PRINT_ERROR("can't set the multicast loop %d! ", errno);
            return PROGRAM_FAULT;
        }
    }
    return PROGRAM_OK;
}

// create the socket and connect
int32_t create_socket_and_connect(int32_t *socket_fd,  struct ClientUnit *client_unit)
{
    ip_addr_t *ip = &client_unit->ip;
    const char *domain = client_unit->domain;
    const char *api = client_unit->api;

    sockaddr_t server_addr;

    if (strcmp(domain, "tcp") == 0 || strcmp(domain, "udp") == 0) {
        uint32_t addr_len = ip->addr_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        memset_s(&server_addr, addr_len, 0, addr_len);

        if (creat_socket_init(socket_fd, client_unit, &server_addr) != PROGRAM_OK) {
            return PROGRAM_FAULT;
        }

        if (pocess_connect_sport(socket_fd, client_unit, &server_addr) < 0) {
            return PROGRAM_FAULT;
        }

        if (ip->addr_family == AF_INET) {
            ((struct sockaddr_in *)&server_addr)->sin_addr = ip->u_addr.ip4;
        } else if (ip->addr_family == AF_INET6) {
            ((struct sockaddr_in6 *)&server_addr)->sin6_addr = ip->u_addr.ip6;
        }
        ((struct sockaddr_in *)&server_addr)->sin_port = client_unit->port;

        if (strcmp(domain, "udp") == 0) {
            int32_t ret = pocess_udp_multicast(socket_fd, client_unit, &server_addr);
            if (ret != PROGRAM_OK) {
                return ret;
            }
        }

        if (strcmp(domain, "udp") != 0 || strcmp(api, "recvfromsendto") != 0) {
            if (connect(*socket_fd, (struct sockaddr *)&server_addr, addr_len) < 0) {
                if (errno == EINPROGRESS) {
                    return PROGRAM_INPROGRESS;
                } else {
                    PRINT_ERROR("client can't connect to the server %d! ", errno);
                    return PROGRAM_FAULT;
                }
            }
        }
    } else if (strcmp(domain, "unix") == 0) {
        int32_t ret = pocess_unix_create_connect(socket_fd);
        if (ret != PROGRAM_OK) {
            return ret;
        }
    }
    return PROGRAM_OK;
}

// set the socket to unblock
int32_t set_socket_unblock(int32_t socket_fd)
{
    int flags = -1;
    
    flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags == -1) {
        printf("get socket flag error, fd:[%d], errno: %d\n", socket_fd, errno);
	return -1;
    }

    flags |= O_NONBLOCK;
    if (fcntl(socket_fd, F_SETFL, flags) == -1) {
        printf("set socket flag error, fd:[%d], errno: %d\n", socket_fd, errno);
	return -1;
    }

    return 0;
}
