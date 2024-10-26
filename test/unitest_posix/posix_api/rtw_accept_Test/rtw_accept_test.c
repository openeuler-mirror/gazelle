/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * gazelle is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "test_frame.h"
#include "common/gazelle_base_func.h"
#include "lstack_cfg.h"
#include "lstack_epoll.h"
#include "lstack_lwip.h"
#include "lstack_protocol_stack.h"

static struct netconn conn_sock;
static struct lwip_sock my_lwip_sock;

int lwip_accept4(int s, struct sockaddr* addr, socklen_t* addrlen, int flags)
{
    if (flags) {
        memset(addr, 0, sizeof(struct sockaddr_in));
        return -1;
    }

    struct sockaddr_in* client_addr_in;
    client_addr_in = (struct sockaddr_in*)addr;

    client_addr_in->sin_family = AF_INET;
    client_addr_in->sin_addr.s_addr = inet_addr(SERVER_ADDR);
    client_addr_in->sin_port = htons(SERVER_PORT);
    return CONN_FD;
}

static struct lwip_sock* get_min_accept_sock(int32_t fd)
{
    conn_sock.callback_arg.socket = CONN_FD;

    my_lwip_sock.conn = &conn_sock;
    return &my_lwip_sock;
}

static void inline del_accept_in_event(struct lwip_sock* sock)
{
    pthread_spin_lock(&sock->wakeup->event_list_lock);

    if (!NETCONN_IS_ACCEPTIN(sock)) {
        sock->events &= ~EPOLLIN;
        if (sock->events == 0) {
            list_del_node(&sock->event_list);
        }
    }

    pthread_spin_unlock(&sock->wakeup->event_list_lock);
}

static struct protocol_stack* my_get_protocol_stack_by_fd(int32_t fd)
{
    int socket_fd = rtw_socket(AF_INET, SOCK_STREAM, 0);

    return get_protocol_stack_by_fd(socket_fd);
}

#define get_protocol_stack_by_fd my_get_protocol_stack_by_fd
int32_t stack_broadcast_accept4(int32_t fd, struct sockaddr* addr,
                                socklen_t* addrlen, int flags)
{
    int32_t ret = -1;
    struct lwip_sock* min_sock = NULL;
    struct lwip_sock* sock = lwip_get_socket(fd);
    struct protocol_stack* stack = NULL;
    if (sock == NULL) {
        GAZELLE_RETURN(EBADF);
    }

    if (netconn_is_nonblocking(sock->conn)) {
        min_sock = get_min_accept_sock(fd);
    } else {
        while ((min_sock = get_min_accept_sock(fd)) == NULL) {
            lstack_block_wait(sock->wakeup, 0);
        }
    }
    if (min_sock && min_sock->conn) {
        stack = get_protocol_stack_by_fd(min_sock->conn->callback_arg.socket);
        if (stack == NULL) {
            GAZELLE_RETURN(EBADF);
        }
        rpc_queue* tmp = &stack->rpc_queue;
        ret = rpc_call_accept(&stack->rpc_queue,
                              min_sock->conn->callback_arg.socket, addr,
                              addrlen, flags);
    }

    if (min_sock && min_sock->wakeup &&
        min_sock->wakeup->type == WAKEUP_EPOLL) {
        del_accept_in_event(min_sock);
    }

    if (ret < 0) {
        errno = EAGAIN;
    }
    return ret;
}
#undef get_protocol_stack_by_fd

void stack_accept(struct rpc_msg* msg)
{
    int32_t fd = msg->args[MSG_ARG_0].i;
    msg->result = -1;
    struct protocol_stack* stack = get_protocol_stack();

    int32_t accept_fd =
        lwip_accept4(fd, msg->args[MSG_ARG_1].p, msg->args[MSG_ARG_2].p,
                     msg->args[MSG_ARG_3].i);
    if (accept_fd < 0) {
        stack->stats.accept_fail++;
        printf("LSTACK fd %d ret %d\n", fd, accept_fd);
        return;
    }

    msg->result = accept_fd;
}

void test_accept_success(void)
{
    int nonblock_mode = get_global_cfg_params()->nonblock_mode;

    // Test blocking mode
    get_global_cfg_params()->nonblock_mode = 0;
    int listen_fd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(listen_fd, -1);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd =
        rtw_accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
    LOG_ASSERT(client_fd == CONN_FD, "Accept client_fd should be %d", CONN_FD);
    LOG_ASSERT(client_addr.sin_family == AF_INET,
               "Accept client_fd sin_family should be AF_INET");
    LOG_ASSERT(client_addr.sin_addr.s_addr == inet_addr(SERVER_ADDR),
               "Accept client_fd s_addr should be %s",
               inet_ntoa((struct in_addr){client_addr.sin_addr.s_addr}));
    LOG_ASSERT(client_addr.sin_port == htons(SERVER_PORT),
               "Accept client_fd sin_port should be %d", SERVER_PORT);

    // Test non-blocking mode
    get_global_cfg_params()->nonblock_mode = 1;
    client_fd =
        rtw_accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
    LOG_ASSERT(client_fd == -1, "Accept none_block client_fd should be -1");
    LOG_ASSERT(client_addr.sin_addr.s_addr == INADDR_ANY,
               "Accept none_block client_fd s_addr should be %s",
               inet_ntoa((struct in_addr){client_addr.sin_addr.s_addr}));
    LOG_ASSERT(client_addr.sin_port == htons(0),
               "Accept none_block client_fd sin_port should be 0");

    // Restore nonblock_mode to the default value.
    get_global_cfg_params()->nonblock_mode = nonblock_mode;
}

void test_accept_failure(void)
{
    int client_fd = rtw_accept(-1, NULL, 0);
    LOG_ASSERT(client_fd == -1, "Accept failure for bad file descriptor!");
}
