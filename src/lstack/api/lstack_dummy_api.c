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
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include <rte_config.h>
#include <rte_atomic.h>
#include <lwip/lwipgz_posix_api.h>

#define DUMMY_SLEEP_S 5

static inline ssize_t dummy_exit(void)
{
    sleep(DUMMY_SLEEP_S);
    errno = ENOTCONN;
    return -1;
}

static int dummy_socket(int domain, int type, int protocol)
{
    sleep(DUMMY_SLEEP_S);
    return -1;
}

static ssize_t dummy_write(int s, const void *mem, size_t size)
{
    return dummy_exit();
}

static ssize_t dummy_writev(int s, const struct iovec *iov, int iovcnt)
{
    return dummy_exit();
}

static ssize_t dummy_send(int sockfd, const void *buf, size_t len, int flags)
{
    return dummy_exit();
}

static ssize_t dummy_sendmsg(int s, const struct msghdr *message, int flags)
{
    return dummy_exit();
}

static ssize_t dummy_sendto(int sockfd, const void *buf, size_t len, int flags,
                            const struct sockaddr *addr, socklen_t addrlen)
{
    return dummy_exit();
}

void dummy_api_init(posix_api_t *api)
{
    api->socket_fn  = dummy_socket;
    api->send_fn    = dummy_send;
    api->write_fn   = dummy_write;
    api->writev_fn  = dummy_writev;
    api->sendmsg_fn = dummy_sendmsg;
    api->sendto_fn  = dummy_sendto;

    rte_wmb();
    /* 1: wait until app thread call send functio complete */
    sleep(1);
}
