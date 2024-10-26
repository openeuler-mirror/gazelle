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
#include "common/dpdk_common.h"
#include "lstack_cfg.h"
#include "lstack_epoll.h"
#include "lstack_lwip.h"
struct udp_read_params {
    void* buf;
    size_t len;
    bool noblock;
    struct sockaddr* addr;
    socklen_t* addrlen;
};

static const uint8_t fin_packet = 0;
static PER_THREAD uint16_t stack_sock_num[GAZELLE_MAX_STACK_NUM] = {0};
static PER_THREAD uint16_t max_sock_stack = 0;
static struct pbuf my_pbuf;
static char read_data[BUFFER_SIZE];

void calculate_lstack_latency(struct gazelle_stack_latency* stack_latency,
                              const struct pbuf* pbuf,
                              enum GAZELLE_LATENCY_TYPE type,
                              uint64_t time_record);
int lwip_sock_make_addr(struct netconn* conn, ip_addr_t* fromaddr, u16_t port,
                        struct sockaddr* from, socklen_t* fromlen);
ssize_t gazelle_same_node_ring_recv(struct lwip_sock* sock, const void* buf,
                                    size_t len, int32_t flags);

u16_t pbuf_copy_partial(const struct pbuf* p, void* dataptr, u16_t len,
                        u16_t offset)
{
    const char* mock_data = HELLO_STR;
    u16_t mock_data_len = strlen(mock_data);
    if (offset >= mock_data_len) {
        return 0;
    }

    u16_t copy_len = mock_data_len - offset;
    if (copy_len > len) {
        copy_len = len;
    }
    strncpy(dataptr, mock_data + offset, copy_len);
    return copy_len;
}

static int recv_ring_get_one(struct lwip_sock* sock, bool noblock,
                             struct pbuf** pbuf)
{
    my_pbuf.tot_len = strlen(HELLO_STR);
    *pbuf = &my_pbuf;

    return 0;
}

static bool recv_ring_handle_fin(struct lwip_sock* sock, struct pbuf* pbuf,
                                 ssize_t recvd)
{
    return 0;
}

static bool recv_break_for_err(struct lwip_sock* sock)
{
    bool break_wait = (sock->errevent > 0) && (!NETCONN_IS_DATAIN(sock));
    errno = err_to_errno(netconn_err(sock->conn));
    return break_wait;
}

static void thread_bind_stack(struct lwip_sock* sock)
{
    if (likely(sock->already_bind_numa || !sock->stack)) {
        return;
    }
    sock->already_bind_numa = 1;

    if (get_global_cfg_params()->app_bind_numa == 0) {
        return;
    }

    stack_sock_num[sock->stack->stack_idx]++;
    if (stack_sock_num[sock->stack->stack_idx] > max_sock_stack) {
        max_sock_stack = stack_sock_num[sock->stack->stack_idx];
        bind_to_stack_numa(sock->stack);
    }
}

static struct pbuf* pbuf_free_partial(struct pbuf* pbuf, uint16_t free_len)
{
    uint16_t free_len_tmp = free_len;
    uint32_t tot_len = pbuf->tot_len - free_len_tmp;

    while (free_len_tmp && pbuf) {
        if (free_len_tmp >= pbuf->len) {
            free_len_tmp = free_len_tmp - pbuf->len;
            pbuf = pbuf->next;
        } else {
            pbuf_remove_header(pbuf, free_len_tmp);
            break;
        }
    }

    if (pbuf) {
        pbuf->tot_len = tot_len;
    }
    return pbuf;
}

static ssize_t recv_ring_tcp_read(struct lwip_sock* sock, void* buf,
                                  size_t len, bool noblock)
{
    ssize_t recvd = 0;
    size_t recv_left = len;
    uint32_t copy_len;
    struct pbuf* pbuf = NULL;

    if (len == 0) {
        return 0;
    }

    while (recv_left > 0) {
        if (recv_ring_get_one(sock, noblock | recvd, &pbuf) != 0) {
            /* When the buffer should be empty, it will be returned directly
            if in non-blocking mode or if data has already been received */
            break;
        }
        if (unlikely((pbuf == NULL) || (pbuf == (void*)&fin_packet))) {
            if (recv_ring_handle_fin(sock, pbuf, recvd)) {
                return 0;
            } else {
                break; /* recvd > 0, pending fin, handle data */
            }
        }
        copy_len = (recv_left > pbuf->tot_len) ? pbuf->tot_len : recv_left;
        if (copy_len > UINT16_MAX) {
            copy_len = UINT16_MAX; /* it's impossible to get here */
        }
        pbuf_copy_partial(pbuf, (char*)buf + recvd, copy_len, 0);

        recvd += copy_len;
        recv_left -= copy_len;

        if (pbuf->tot_len > copy_len) {
            sock->recv_lastdata = pbuf_free_partial(pbuf, copy_len);
        } else {
            if (sock->wakeup) {
                sock->wakeup->stat.app_read_cnt += 1;
            }

            if (get_protocol_stack_group()->latency_start) {
                calculate_lstack_latency(&sock->stack->latency, pbuf,
                                         GAZELLE_LATENCY_READ_LSTACK, 0);
            }

            gazelle_ring_read_over(sock->recv_ring);
        }
    }

    if (recvd > 0) {
        errno = 0;
    } else {
        recvd = -1;
    }

    return recvd;
}

static ssize_t recv_ring_udp_read(struct lwip_sock* sock,
                                  struct udp_read_params* params)
{
    size_t recv_left = params->len;
    struct pbuf* pbuf = NULL;
    uint32_t copy_len;

    sock->recv_lastdata = NULL;

    if (recv_ring_get_one(sock, params->noblock, &pbuf) != 0) {
        /* errno have set */
        return -1;
    }

    copy_len = (recv_left > pbuf->tot_len) ? pbuf->tot_len : recv_left;
    pbuf_copy_partial(pbuf, (char*)params->buf, copy_len, 0);
    /* drop remaining data if have */
    gazelle_ring_read_over(sock->recv_ring);

    if (pbuf && params->addr && params->addrlen) {
        lwip_sock_make_addr(sock->conn, &(pbuf->addr), pbuf->port, params->addr,
                            params->addrlen);
    }

    if (copy_len < pbuf->tot_len) {
        sock->stack->stats.sock_rx_drop++;
    }

    if (sock->wakeup) {
        sock->wakeup->stat.app_read_cnt++;
    }
    if (get_protocol_stack_group()->latency_start) {
        calculate_lstack_latency(&sock->stack->latency, pbuf,
                                 GAZELLE_LATENCY_READ_LSTACK, 0);
    }

    return copy_len;
}

ssize_t do_lwip_read_from_stack(int32_t fd, void *buf, size_t len, int32_t flags,
                                struct sockaddr *addr, socklen_t *addrlen)
{
    ssize_t recvd = 0;
    struct lwip_sock* sock = lwip_get_socket(fd);
    /* Prevent operations on null sock */
    if (sock == NULL) {
        return -1;
    }

    bool noblock = (flags & MSG_DONTWAIT) || netconn_is_nonblocking(sock->conn);

    if (recv_break_for_err(sock)) {
        return -1;
    }

    thread_bind_stack(sock);

    if (sock->same_node_rx_ring != NULL) {
        return gazelle_same_node_ring_recv(sock, buf, len, flags);
    }

    if (NETCONN_IS_UDP(sock)) {
        struct udp_read_params params;
        params.addr = addr;
        params.addrlen = addrlen;
        params.buf = buf;
        params.len = len;
        params.noblock = noblock;
        recvd = recv_ring_udp_read(sock, &params);
    } else {
        recvd = recv_ring_tcp_read(sock, buf, len, noblock);
    }

    /* rte_ring_count reduce lock */
    if (sock->wakeup && sock->wakeup->type == WAKEUP_EPOLL &&
        (sock->events & EPOLLIN) && (!NETCONN_IS_DATAIN(sock))) {
        del_sock_event(sock, EPOLLIN);
    }

    if (recvd < 0) {
        if (sock->wakeup) {
            sock->wakeup->stat.read_null++;
        }
        return -1;
    }
    return recvd;
}

void read_tcp_test()
{
    /* TCP read test ---------------------------------------------*/
    int socket_fd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(socket_fd, -1);
    int result = rtw_read(socket_fd, read_data, strlen(HELLO_STR));

    /* make sure no garbled character */
    read_data[result] = '\0';
    LOG_ASSERT(result == strlen(HELLO_STR), "Read_Recv tcp result should be %d",
               strlen(HELLO_STR));
    LOG_ASSERT(strcmp(read_data, HELLO_STR) == 0, "Read_Recv tcp data should be %s",
               HELLO_STR);
    memset(read_data, 0, sizeof(read_data));
    if (socket_fd != -1) {
        rtw_close(socket_fd);
    }
}

void read_udp_test()
{
    /* UDP read test ---------------------------------------------*/
    int socket_fd = rtw_socket(AF_INET, SOCK_DGRAM, 0);
    CU_ASSERT_NOT_EQUAL(socket_fd, -1);
    int result = rtw_read(socket_fd, read_data, strlen(HELLO_STR));

    read_data[result] = '\0';
    LOG_ASSERT(result == strlen(HELLO_STR), "Read_Recv udp result should be %d",
               strlen(HELLO_STR));
    LOG_ASSERT(strcmp(read_data, HELLO_STR) == 0, "Read_Recv udp data should be %s",
               HELLO_STR);
    memset(read_data, 0, sizeof(read_data));
    if (socket_fd != -1) {
        rtw_close(socket_fd);
    }
}

void readv_test()
{
    /* rtw_readv test ---------------------------------------------*/
    struct iovec iov;
    iov.iov_base = read_data;
    iov.iov_len = LEN_HANDLE;
    int socket_fd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(socket_fd, -1);

    int result = rtw_readv(socket_fd, &iov, IOVLEN);
    read_data[result] = '\0';
    LOG_ASSERT(result == LEN_HANDLE, "Readv result should be %d", LEN_HANDLE);
    LOG_ASSERT(strcmp(read_data, READ_STR) == 0, "Readv data should be %s", READ_STR);
    memset(read_data, 0, sizeof(read_data));
    if (socket_fd != -1) {
        rtw_close(socket_fd);
    }
}

void test_read_success(void)
{
    read_tcp_test();
    read_udp_test();
    readv_test();
}

void recvmsg_test()
{
    struct iovec iov;
    iov.iov_base = read_data;
    iov.iov_len = LEN_HANDLE;

    /* rtw_recvmsg test ---------------------------------------------*/
    int socket_fd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(socket_fd, -1);

    struct msghdr msg;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = LWIP_CONST_CAST(struct iovec*, &iov);
    msg.msg_iovlen = IOVLEN;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    int result = rtw_recvmsg(socket_fd, &msg, 1);
    read_data[result] = '\0';
    LOG_ASSERT(result == LEN_HANDLE, "Recvmsg result should be %d", LEN_HANDLE);
    LOG_ASSERT(strcmp(read_data, READ_STR) == 0, "Recvmsg data should be %s",
               READ_STR);
    memset(read_data, 0, sizeof(read_data));
    if (socket_fd != -1) {
        rtw_close(socket_fd);
    }
}

void recvfrom_tcp_test()
{
    /* TCP rtw_recvfrom test ---------------------------------------------*/
    struct sockaddr_in address;
    struct sockaddr* addr;
    socklen_t addrlen = sizeof(address);

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    address.sin_port = htons(SERVER_PORT);
    addr = (struct sockaddr*)&address;

    int socket_fd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    CU_ASSERT_NOT_EQUAL(socket_fd, -1);
    int result = rtw_recvfrom(socket_fd, read_data, strlen(HELLO_STR), 1, addr,
                              &addrlen);
    read_data[result] = '\0';
    LOG_ASSERT(result == strlen(HELLO_STR), "Recvfrom tcp result should be %d",
               strlen(HELLO_STR));
    LOG_ASSERT(strcmp(read_data, HELLO_STR) == 0, "Recvfrom tcp data should be %s",
               HELLO_STR);
    memset(read_data, 0, sizeof(read_data));
    if (socket_fd != -1) {
        rtw_close(socket_fd);
    }
}

void recvfrom_udp_test()
{
    /* UDP rtw_recvfrom test ---------------------------------------------*/
    struct sockaddr_in address;
    struct sockaddr* addr;
    socklen_t addrlen = sizeof(address);

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    address.sin_port = htons(SERVER_PORT);
    addr = (struct sockaddr*)&address;

    int socket_fd = rtw_socket(AF_INET, SOCK_DGRAM, 0);
    CU_ASSERT_NOT_EQUAL(socket_fd, -1);
    int result = rtw_recvfrom(socket_fd, read_data, strlen(HELLO_STR), 1, addr,
                              &addrlen);
    read_data[result] = '\0';
    LOG_ASSERT(result == strlen(HELLO_STR), "Recvfrom ucp result should be %d",
               strlen(HELLO_STR));
    LOG_ASSERT(strcmp(read_data, HELLO_STR) == 0, "Recvfrom ucp data should be %s",
               HELLO_STR);
    memset(read_data, 0, sizeof(read_data));
    if (socket_fd != -1) {
        rtw_close(socket_fd);
    }
}

void test_rec_success(void)
{
    recvmsg_test();
    recvfrom_tcp_test();
    recvfrom_udp_test();
}

void test_read_recv_failure(void)
{
    char read_data[BUFFER_SIZE];
    int result = rtw_read(-1, read_data, strlen(HELLO_STR));
    LOG_ASSERT(result == -1, "Read_Recv failure for bad file descriptor");

    result = rtw_readv(-1, NULL, 0);
    LOG_ASSERT(result == -1, "Readv failure for bad file descriptor");

    result = rtw_recvmsg(-1, NULL, 0);
    LOG_ASSERT(result == -1, "Recvmsg failure for bad file descriptor");

    /* rtw_recvfrom should check the returned sock internally! */
    // result = rtw_recvfrom(-1, NULL, 0, 0, NULL, NULL);

    int socket_fd = rtw_socket(AF_INET, SOCK_STREAM, 0);
    result = rtw_recvfrom(socket_fd, NULL, 0, 0, NULL, NULL);
    LOG_ASSERT(result == 0, "Recvfrom failure for read nothing");

    if (socket_fd != -1) {
        rtw_close(socket_fd);
    }
}
