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


// create the socket and listen
int32_t create_socket_and_listen(int32_t *socket_fd, in_addr_t ip, uint16_t port, const char *api)
{
    if (strcmp(api, "posix") == 0) {
        *socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (*socket_fd < 0) {
            PRINT_ERROR("can't create socket %d! ", *socket_fd);
            return PROGRAM_FAULT;
        }

        int32_t port_multi = 1;
        int32_t setsockopt_ret = setsockopt(*socket_fd, SOL_SOCKET, SO_REUSEPORT, (void *)&port_multi, sizeof(int32_t));
        if (setsockopt_ret < 0) {
            PRINT_ERROR("can't set the option of socket %d! ", setsockopt_ret);
            return PROGRAM_FAULT;
        }

        int32_t set_socket_unblock_ret = set_socket_unblock(*socket_fd);
        if (set_socket_unblock_ret < 0) {
            PRINT_ERROR("can't set the socket to unblock %d! ", set_socket_unblock_ret);
            return PROGRAM_FAULT;
        }

        struct sockaddr_in socket_addr;
        memset(&socket_addr, 0, sizeof(socket_addr));
        socket_addr.sin_family = AF_INET;
        socket_addr.sin_addr.s_addr = ip;
        socket_addr.sin_port = port;
        int32_t bind_ret = bind(*socket_fd, (struct sockaddr *)&socket_addr, sizeof(struct sockaddr_in));
        if (bind_ret < 0) {
            PRINT_ERROR("can't bind the address to socket %d! ", bind_ret);
            return PROGRAM_FAULT;
        }

        int32_t listen_ret = listen(*socket_fd, SERVER_SOCKET_LISTEN_BACKLOG);
        if (listen_ret < 0) {
            PRINT_ERROR("server socket can't lisiten %d! ", listen_ret);
            return PROGRAM_FAULT;
        }
    } else {

    }
    
    return PROGRAM_OK;
}

// create the socket and connect
int32_t create_socket_and_connect(int32_t *socket_fd, in_addr_t ip, uint16_t port, const char *api)
{
    if (strcmp(api, "posix") == 0) {
        *socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (*socket_fd < 0) {
            PRINT_ERROR("client can't create socket %d! ", *socket_fd);
            return PROGRAM_FAULT;
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = ip;
        server_addr.sin_port = port;
        int32_t connect_ret = connect(*socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (connect_ret < 0) {
            if (errno == EINPROGRESS) {
                return PROGRAM_INPROGRESS;
            } else {
                PRINT_ERROR("client can't connect to the server %d! ", errno);
                return PROGRAM_FAULT;
            }
        }
    } else {

    }
    return PROGRAM_OK;
}

// set the socket to unblock
int32_t set_socket_unblock(int32_t socket_fd)
{
    return fcntl(socket_fd, F_SETFL, fcntl(socket_fd, F_GETFD, 0) | O_NONBLOCK);
}
