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

#include "lstack_log.h"
#include "lstack_protocol_stack.h"
#include "common/gazelle_base_func.h"

#define DUMMY_WAIT_TIMEOUT_MS 5000
static void waiting_exit_msg(void)
{
    int time = 0;
    int sleep_interval = 10;

    while (time < DUMMY_WAIT_TIMEOUT_MS) {
        time += sleep_interval;
        usleep(sleep_interval * US_PER_MS);
        /* Must be in a secure context before close sockets */
        if (get_protocol_stack() &&  stack_polling(0) != 0) {
            /* Means stack has closed all fds */
            stack_wait();
            break;
        }
    }

    if (time >= DUMMY_WAIT_TIMEOUT_MS) {
        LSTACK_LOG(ERR, LSTACK, "APP thread doesn't recv 'stack_exit' message, will force quit within 5 seconds.\n");
        stack_wait();
    }

    usleep(DUMMY_WAIT_TIMEOUT_MS * US_PER_MS);
}

static inline ssize_t dummy_exit(void)
{
    waiting_exit_msg();
    errno = ENOTCONN;
    return -1;
}

static int dummy_socket(int domain, int type, int protocol)
{
    waiting_exit_msg();
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

void sock_dummy_api_init(posix_api_t *api)
{
    api->socket_fn  = dummy_socket;
    api->send_fn    = dummy_send;
    api->write_fn   = dummy_write;
    api->writev_fn  = dummy_writev;
    api->sendmsg_fn = dummy_sendmsg;
    api->sendto_fn  = dummy_sendto;

    rte_wmb();
}
