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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <arch/sys_arch.h>
#include <lwip/sys.h>
#include <lwip/api.h>

int lwip_epoll_create(int size)
{
    return 0;
}
int lwip_epoll_ctl(int epfd, int op, int fd, const void *event)
{
    return 0;
}
int lwip_epoll_wait(int epfd, const void* events, int maxevents, int timeout)
{
    return 0;
}
void libnet_per_thread_init(void)
{
    return;
}
int lwip_sigaction(int signum, const void *act, const void *oldact)
{
    return 0;
}
int lwip_fork(void)
{
    return 0;
}
int del_epoll_event(const void *conn, int event)
{
    return 0;
}
int add_epoll_event(const void *conn, int event)
{
    return 0;
}
int rearm_accept_fd(int fd)
{
    return 0;
}
void clean_host_fd(int fd)
{
    return;
}
int rearm_host_fd(int fd)
{
    return 0;
}
int lwip_is_epfd(int epfd)
{
    return 0;
}
int lwip_epoll_close(int epfd)
{
    return 0;
}
int eth_dev_poll(void)
{
    return 0;
}
int vdev_reg_xmit(int type, const void *qtuple)
{
    return 0;
}

void *__wrap_memp_malloc(int type)
{
    void *memp;

    memp = malloc(5 * 1024 * 1024); /* 5 * 1024 * 1024 = 5M */

    return memp;
}

int __wrap_sys_mbox_new(const struct sys_mbox **mb, int size)
{
    return 0;
}

int __wrap_netconn_prepare_delete(const struct netconn *conn)
{
    return 0;
}

int __wrap_netconn_delete(struct netconn *conn)
{
    if (conn != NULL) {
        free(conn->pcb.tcp);
        free(conn->op_completed);
        free(conn);
        conn = NULL;
    }
    return 0;
}
