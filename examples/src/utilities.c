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


#include "utilities.h"


// create the socket and listen
int32_t create_socket_and_listen(int32_t *socket_fd, in_addr_t ip, uint16_t port, const char *domain)
{
    if (strcmp(domain, "posix") == 0) {
        *socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (*socket_fd < 0) {
            PRINT_ERROR("can't create socket %d! ", errno);
            return PROGRAM_FAULT;
        }
    } else {
        *socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (*socket_fd < 0) {
            PRINT_ERROR("can't create socket %d! ", errno);
            return PROGRAM_FAULT;
        }
    }

    int32_t port_multi = 1;
    if (setsockopt(*socket_fd, SOL_SOCKET, SO_REUSEPORT, (void *)&port_multi, sizeof(int32_t)) < 0) {
        PRINT_ERROR("can't set the option of socket %d! ", errno);
        return PROGRAM_FAULT;
    }

    if (set_socket_unblock(*socket_fd) < 0) {
        PRINT_ERROR("can't set the socket to unblock! ");
        return PROGRAM_FAULT;
    }

    if (strcmp(domain, "posix") == 0) {
        struct sockaddr_in socket_addr;
        memset_s(&socket_addr, sizeof(socket_addr), 0, sizeof(socket_addr));
        socket_addr.sin_family = AF_INET;
        socket_addr.sin_addr.s_addr = ip;
        socket_addr.sin_port = port;
        if (bind(*socket_fd, (struct sockaddr *)&socket_addr, sizeof(struct sockaddr_in)) < 0) {
            PRINT_ERROR("can't bind the address to socket %d! ", errno);
            return PROGRAM_FAULT;
        }

        if (listen(*socket_fd, SERVER_SOCKET_LISTEN_BACKLOG) < 0) {
            PRINT_ERROR("server socket can't lisiten %d! ", errno);
            return PROGRAM_FAULT;
        }
    } else {
        struct sockaddr_un socket_addr;
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
    }
    
    return PROGRAM_OK;
}

// create the socket and connect
int32_t create_socket_and_connect(int32_t *socket_fd, in_addr_t ip, uint16_t port, const char *domain)
{
    if (strcmp(domain, "posix") == 0) {
        *socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (*socket_fd < 0) {
            PRINT_ERROR("client can't create socket %d! ", errno);
            return PROGRAM_FAULT;
        }

        struct sockaddr_in server_addr;
        memset_s(&server_addr, sizeof(server_addr), 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = ip;
        server_addr.sin_port = port;
        if (connect(*socket_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) < 0) {
            if (errno == EINPROGRESS) {
                return PROGRAM_INPROGRESS;
            } else {
                PRINT_ERROR("client can't connect to the server %d! ", errno);
                return PROGRAM_FAULT;
            }
        }
    } else {
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
    }
    return PROGRAM_OK;
}

// set the socket to unblock
int32_t set_socket_unblock(int32_t socket_fd)
{
    return fcntl(socket_fd, F_SETFL, fcntl(socket_fd, F_GETFD, 0) | O_NONBLOCK);
}
