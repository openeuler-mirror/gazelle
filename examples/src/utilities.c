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


// create the socket
int32_t socket_create(int32_t *socket_fd, const char *ip, uint32_t port)
{
    *socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*socket_fd < 0) {
        PRINT_ERROR("can't create socket! ");
        return PROGRAM_FAULT;
    }

    int32_t port_multi = 1;
    if (setsockopt(*socket_fd, SOL_SOCKET, SO_REUSEPORT, (void *)&port_multi, sizeof(int32_t)) < 0) {
        PRINT_ERROR("can't set the option of socket! ");
        return PROGRAM_FAULT;
    }

    if (set_socket_unblock(*socket_fd) < 0) {
        PRINT_ERROR("can't set the socket to unblock! ");
        exit(PROGRAM_FAULT);
    }

    struct sockaddr_in socket_addr;
    memset(&socket_addr, 0, sizeof(socket_addr));
    socket_addr.sin_family = AF_INET;
    socket_addr.sin_addr.s_addr = inet_addr(ip);
    socket_addr.sin_port = htons(port);
    if (bind(*socket_fd, (struct sockaddr *)&socket_addr, sizeof(struct sockaddr_in)) < 0) {
        PRINT_ERROR("can't bind the address to socket! ");
        exit(PROGRAM_FAULT);
    }
    
    return PROGRAM_OK;
}

// set the socket to unblock
int32_t set_socket_unblock(int32_t socket_fd)
{
    return fcntl(socket_fd, F_SETFL, fcntl(socket_fd, F_GETFD, 0) | O_NONBLOCK);
}
