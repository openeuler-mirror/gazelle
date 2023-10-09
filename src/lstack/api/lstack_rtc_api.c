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

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <lwip/posix_api.h>
#include <lwip/lwipsock.h>
#include "posix/lstack_epoll.h"
#include "lstack_log.h"
#include "lstack_cfg.h"
#include "lstack_protocol_stack.h"
#include "lstack_rtc_api.h"

int rtc_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    return -1;
}

int rtc_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout)
{
    return -1;
}

int rtc_socket(int domain, int type, int protocol)
{
    int ret;

    if (stack_setup_app_thread() < 0) {
        LSTACK_EXIT(1, "stack_setup_app_thread failed!\n");
    }
    
    /* need call stack thread init function */
    ret = lwip_socket(domain, type, protocol);
    struct lwip_sock *sock = get_socket(ret);
    if (sock != NULL) {
        sock->stack = get_protocol_stack();
        sock->epoll_events = 0;
        sock->events = 0;
        sock->wakeup = NULL;
        init_list_node_null(&sock->event_list);
    }
    return ret;
}

int rtc_close(int s)
{
    return lwip_close(s);
}

int rtc_epoll_create(int flags)
{
    if (stack_setup_app_thread() < 0) {
        LSTACK_EXIT(1, "stack_setup_app_thread failed!\n");
    }

    return lstack_epoll_create(flags);
}

int rtc_epoll_create1(int flags)
{
    if (stack_setup_app_thread() < 0) {
        LSTACK_EXIT(1, "stack_setup_app_thread failed!\n");
    }

    return lstack_epoll_create1(flags);
}

int rtc_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return lstack_epoll_ctl(epfd, op, fd, event);
}
