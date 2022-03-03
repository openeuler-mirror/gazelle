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

#include "ltran_monitor.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ltran_base.h"
#include "ltran_log.h"
#include "ltran_stat.h"
#include "ltran_instance.h"
#include "gazelle_dfx_msg.h"

#define GAZELLE_LISTEN_BACKLOG          5

#define GAZELLE_EPOLL_SIZE              1024
#define GAZELLE_MAX_EVENTS_NUM          512
#define GAZELLE_MAX_DFX_FD_NUM          32

enum sockfd_type {
    GAZELLE_DFX_SERVER_FD = 0,
    GAZELLE_DFX_CONN_FD,
    GAZELLE_REG_SERVER_FD,
    GAZELLE_REG_CONN_FD,
    GAZELLE_FD_TYPE_MAX
};

struct sockfd_data {
    uint32_t pid;
    int32_t fd;
    enum sockfd_type type;
    void (*func)(uint32_t events, struct sockfd_data *data);
};

static struct sockfd_data g_sockfd_data[GAZELLE_EPOLL_SIZE] = {0};
static int32_t g_epoll_fd = -1;
static int32_t g_dfx_fd_cnt = 0;

static void dfx_conn_msg_proc(uint32_t events, struct sockfd_data *data);
static void dfx_server_msg_proc(uint32_t events, struct sockfd_data *data);
static void reg_conn_msg_proc(uint32_t events, struct sockfd_data *data);
static void reg_server_msg_proc(uint32_t events, struct sockfd_data *data);

static struct sockfd_data *sockfd_data_alloc(enum sockfd_type type, int32_t fd)
{
    struct sockfd_data *data = NULL;
    static int32_t head = 0;

    const int32_t old_head = head;
    while (g_sockfd_data[head].fd > 0) {
        head = (head + 1) % GAZELLE_EPOLL_SIZE;
        if (head == old_head) {
            return NULL;
        }
    }

    data = &g_sockfd_data[head];
    data->type = type;
    data->fd = fd;

    switch (type) {
        case GAZELLE_DFX_SERVER_FD:
            data->func = dfx_server_msg_proc;
            break;
        case GAZELLE_DFX_CONN_FD:
            data->func = dfx_conn_msg_proc;
            break;
        case GAZELLE_REG_SERVER_FD:
            data->func = reg_server_msg_proc;
            break;
        case GAZELLE_REG_CONN_FD:
            data->func = reg_conn_msg_proc;
            break;
        default:
            data->fd = 0;
            return NULL;
    }

    return data;
}

static inline void sockfd_data_free(struct sockfd_data *data)
{
    close(data->fd);
    (void)memset_s(data, sizeof(struct sockfd_data), 0, sizeof(*data));
}

static int32_t unix_server_create(const char *path, int32_t *server_fd)
{
    struct sockaddr_un addr;
    int32_t fd = -1;
    int32_t ret;

    ret = unlink(path);
    if (ret != 0) {
        LTRAN_WARN("unlink %s failed, just skip it. errno: %d ret=%d.\n", path, errno, ret);
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        LTRAN_ERR("create unix socket failed on %s. errno: %d ret=%d.\n", path, errno, ret);
        return GAZELLE_ERR;
    }

    (void)memset_s(&addr, sizeof(struct sockaddr_un), 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    ret = strncpy_s(addr.sun_path, sizeof(addr.sun_path), path, sizeof(addr.sun_path) - 1);
    if (ret != 0) {
        LTRAN_ERR("strncpy failed on %s. ret=%d.\n", path, ret);
        goto ERROR;
    }

    ret = bind(fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    if (ret == -1) {
        LTRAN_ERR("bind unix socket failed on %s. errno: %d ret=%d.\n", path, errno, ret);
        goto ERROR;
    }

    ret = listen(fd, GAZELLE_LISTEN_BACKLOG);
    if (ret == -1) {
        LTRAN_ERR("listen unix socket failed on %s. errno: %d ret=%d.\n", path, errno, ret);
        goto ERROR;
    }

    *server_fd = fd;
    return GAZELLE_OK;
ERROR:
    close(fd);
    return GAZELLE_ERR;
}

static int32_t gazelle_ep_event_init(struct epoll_event* event, enum sockfd_type type, int32_t listenfd)
{
    event->data.ptr = sockfd_data_alloc(type, listenfd);
    event->events = EPOLLIN;
    if (event->data.ptr == NULL) {
        LTRAN_ERR("sockfd_data_alloc for event failed..\n");
        return GAZELLE_ERR;
    }
    return GAZELLE_OK;
}

static int32_t gazelle_ctl_init(void)
{
    struct epoll_event event_reg = {0};
    struct epoll_event event_dfx = {0};
    int32_t listenfd, ret;

    g_epoll_fd = epoll_create(GAZELLE_EPOLL_SIZE);
    if (g_epoll_fd < 0) {
        LTRAN_ERR("epoll_create ERROR, errno: %d\n", errno);
        return GAZELLE_ERR;
    }

    ret = check_and_set_run_dir();
    if (ret != GAZELLE_OK) {
        LTRAN_ERR("dir not exist and create fail. ret=%d.\n", ret);
        return GAZELLE_ERR;
    }
    ret = unix_server_create(GAZELLE_DFX_SOCK_PATHNAME, &listenfd);
    if (ret != GAZELLE_OK) {
        LTRAN_ERR("unix_server_create failed. ret=%d.\n", ret);
        return GAZELLE_ERR;
    }

    ret = gazelle_ep_event_init(&event_dfx, GAZELLE_DFX_SERVER_FD, listenfd);
    if (ret != GAZELLE_OK) {
        return GAZELLE_ERR;
    }

    ret = epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, listenfd, &event_dfx);
    if (ret < 0) {
        LTRAN_ERR("epoll_ctl ERROR, errno: %d. ret=%d.\n", errno, ret);
        sockfd_data_free(event_dfx.data.ptr);
        return GAZELLE_ERR;
    }

    ret = unix_server_create(GAZELLE_REG_SOCK_PATHNAME, &listenfd);
    if (ret != GAZELLE_OK) {
        LTRAN_ERR("unix_server_create failed. ret=%d.\n", ret);
        sockfd_data_free(event_dfx.data.ptr);
        return GAZELLE_ERR;
    }

    ret = gazelle_ep_event_init(&event_reg, GAZELLE_REG_SERVER_FD, listenfd);
    if (ret != GAZELLE_OK) {
        sockfd_data_free(event_dfx.data.ptr);
        return GAZELLE_ERR;
    }
    ret = epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, listenfd, &event_reg);
    if (ret < 0) {
        LTRAN_ERR("epoll_ctl ERROR, errno: %d. ret=%d.\n", errno, ret);
        sockfd_data_free(event_reg.data.ptr);
        sockfd_data_free(event_dfx.data.ptr);
        return GAZELLE_ERR;
    }

    return GAZELLE_OK;
}

static void gazelle_ctl_destroy(void)
{
    int32_t ret;
    struct sockfd_data *data = NULL;

    for (int32_t i = 0; i < GAZELLE_EPOLL_SIZE; i++) {
        data = &g_sockfd_data[i];
        if (data->fd > 0) {
            close(data->fd);
        }
    }
    close(g_epoll_fd);
    g_epoll_fd = -1;

    ret = unlink(GAZELLE_DFX_SOCK_PATHNAME);
    if (ret != 0) {
        LTRAN_WARN("unlink %s ERROR. errno: %d. ret=%d\n", GAZELLE_DFX_SOCK_PATHNAME, errno, ret);
    }
    ret = unlink(GAZELLE_REG_SOCK_PATHNAME);
    if (ret != 0) {
        LTRAN_WARN("unlink %s ERROR. errno: %d. ret=%d\n", GAZELLE_REG_SOCK_PATHNAME, errno, ret);
    }
}

static void dfx_server_msg_proc(uint32_t events, struct sockfd_data *data)
{
    int32_t fd = data->fd;
    int32_t conn_fd;
    int32_t ret;

    if ((events & EPOLLERR) != 0) {
        LTRAN_ERR("fd %d get ERROR events\n", fd);
        sockfd_data_free(data);
        return;
    }

    conn_fd = accept(fd, NULL, NULL);
    if (conn_fd < 0) {
        LTRAN_ERR("accept fd %d ERROR, errno: %d\n", fd, errno);
        return;
    }

    if (g_dfx_fd_cnt > GAZELLE_MAX_DFX_FD_NUM) {
        LTRAN_ERR("the number of dfx requests cannot exceed %d\n", GAZELLE_MAX_DFX_FD_NUM);
        close(conn_fd);
        return;
    }
    g_dfx_fd_cnt++;

    struct epoll_event event = {0};
    event.events = EPOLLIN;
    event.data.ptr = sockfd_data_alloc(GAZELLE_DFX_CONN_FD, conn_fd);
    if (event.data.ptr == NULL) {
        LTRAN_ERR("alloc sockfd_data ERROR\n");
        close(conn_fd);
        return;
    }

    ret = epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, conn_fd, &event);
    if (ret < 0) {
        LTRAN_ERR("epoll_ctl ERROR, errno: %d. ret=%d.\n", errno, ret);
        sockfd_data_free(event.data.ptr);
        close(conn_fd);
        return;
    }

    return;
}

static int32_t ltran_req_mode_process(int32_t fd, struct gazelle_stat_msg_request *req_msg)
{
    switch (req_msg->stat_mode) {
        case GAZELLE_STAT_LTRAN_SHOW_SOCKTABLE:
            handle_resp_ltran_sock(fd);
            break;
        case GAZELLE_STAT_LTRAN_SHOW_CONNTABLE:
            handle_resp_ltran_conn(fd);
            break;
        case GAZELLE_STAT_LTRAN_SHOW:       // fall through
        case GAZELLE_STAT_LTRAN_SHOW_RATE:  // fall through
        case GAZELLE_STAT_LTRAN_SHOW_BURST:
            handle_resp_ltran_total(fd);
            break;
        case GAZELLE_STAT_LTRAN_SHOW_INSTANCE:
            handle_resp_ltran_client(fd);
            break;
        case GAZELLE_STAT_LTRAN_SHOW_LATENCY:
            handle_resp_ltran_latency(fd);
            break;
        case GAZELLE_STAT_LTRAN_START_LATENCY:
            handle_cmd_to_lstack(req_msg);
            set_start_latency_flag(GAZELLE_ON);
            break;
        case GAZELLE_STAT_LTRAN_STOP_LATENCY:
            set_start_latency_flag(GAZELLE_OFF);
            handle_cmd_to_lstack(req_msg);
            break;
        case GAZELLE_STAT_LTRAN_QUIT:
            set_ltran_stop_flag(GAZELLE_TRUE);
            break;
        case GAZELLE_STAT_LTRAN_LOG_LEVEL_SET:
            set_ltran_log_level(req_msg);
            break;
        default:
            return -1;
    }
    return 0;
}
static int32_t lstack_req_mode_process(int32_t fd, const struct gazelle_stat_msg_request *req_msg)
{
    switch (req_msg->stat_mode) {
        case GAZELLE_STAT_LSTACK_LOG_LEVEL_SET:
            handle_cmd_to_lstack(req_msg);
            break;
        case GAZELLE_STAT_LSTACK_SHOW_RATE:
            handle_resp_lstack_total(req_msg, fd);
            break;
        case GAZELLE_STAT_LSTACK_SHOW:
            handle_resp_lstack_total(req_msg, fd);
            handle_resp_lstack_transfer(req_msg, fd);
            break;
        case GAZELLE_STAT_LSTACK_SHOW_SNMP:  // fall through
        case GAZELLE_STAT_LSTACK_SHOW_CONN:
        case GAZELLE_STAT_LSTACK_SHOW_LATENCY:
        case GAZELLE_STAT_LSTACK_LOW_POWER_MDF:
            handle_resp_lstack_transfer(req_msg, fd);
            break;
        default:
            return -1;
    }
    return 0;
}
static void req_mode_process(int32_t fd, struct gazelle_stat_msg_request req_msg)
{
    int32_t ret;

    ret = ltran_req_mode_process(fd, &req_msg);
    if (ret != 0) {
        ret = lstack_req_mode_process(fd, &req_msg);
    }
    if (ret != 0) {
        LTRAN_ERR("Unrecognize dfx msg mode %d, please check. ret=%d.\n", (int32_t)req_msg.stat_mode, ret);
    }
    (void)usleep(100000); // 100000 indicate sleep 100 ms
}

static void dfx_conn_msg_proc(uint32_t events, struct sockfd_data *data)
{
    struct gazelle_stat_msg_request req_msg;
    char addr[GAZELLE_INET_ADDRSTRLEN];
    int32_t fd = data->fd;
    int32_t ret;

    if ((events & EPOLLERR) != 0) {
        LTRAN_ERR("fd %d get ERROR events\n", fd);
        goto END;
    } else if ((events & EPOLLHUP) != 0) {
        goto END;
    }

    ret = read_specied_len(fd, (char *)&req_msg, sizeof(struct gazelle_stat_msg_request));
    if (ret != GAZELLE_OK) {
        goto END;
    }
    inet_ntop(AF_INET, &req_msg.ip, addr, sizeof(addr));
    LTRAN_DEBUG("ltran recv msg. mode: %d, ip: %s.\n", (int32_t)req_msg.stat_mode, addr);
    req_mode_process(fd, req_msg);
END:
    /* always close cmd_fd */
    g_dfx_fd_cnt--;
    sockfd_data_free(data);
    return;
}

static void reg_server_msg_proc(uint32_t events, struct sockfd_data *data)
{
    int32_t conn_fd;
    int32_t ret;

    if ((events & EPOLLERR) != 0) {
        LTRAN_ERR("fd %d get ERROR events\n", data->fd);
        sockfd_data_free(data);
        return;
    }

    conn_fd = accept(data->fd, NULL, NULL);
    if (conn_fd < 0) {
        LTRAN_ERR("accept fd %d ERROR, errno: %d\n", data->fd, errno);
        return;
    }

    struct timeval timeout = {0};
    timeout.tv_sec = 60; /* 60: timeout 60S */
    ret = setsockopt(conn_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (ret != 0) {
        LTRAN_ERR("setsockopt ERROR, errno: %d. ret=%d.\n", errno, ret);
    }

    struct epoll_event event = {0};
    event.data.ptr = sockfd_data_alloc(GAZELLE_REG_CONN_FD, conn_fd);
    event.events = EPOLLIN;
    if (event.data.ptr == NULL) {
        LTRAN_ERR("alloc sockfd_data ERROR\n");
        return;
    }

    ret = epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, conn_fd, &event);
    if (ret < 0) {
        LTRAN_ERR("epoll_ctl ERROR, errno: %d. ret=%d.\n", errno, ret);
        sockfd_data_free(event.data.ptr);
        return;
    }

    return;
}

static void reg_conn_msg_proc(uint32_t events, struct sockfd_data *data)
{
    struct reg_request_msg req_msg;
    int32_t fd = data->fd;
    int32_t ret;

    if ((events & EPOLLERR) != 0) {
        LTRAN_ERR("fd %d get ERROR events\n", fd);
        goto END;
    } else if ((events & EPOLLHUP) != 0) {
        goto END;
    }

    ret = read_specied_len(fd, (char *)&req_msg, sizeof(struct reg_request_msg));
    if (ret != GAZELLE_OK) {
        goto END;
    }

    switch (req_msg.type) {
        case RQT_REG_PROC_MEM:
            data->pid = req_msg.msg.proc.pid;
            ret = handle_reg_msg_proc_mem(fd, &req_msg);
            break;
        case RQT_REG_PROC_ATT:
            ret = handle_reg_msg_proc_att(fd, &req_msg);
            break;
        case RQT_REG_THRD_RING:
            /* thread reg failed, waiting for long connection disconnection to release resources */
            ret = handle_reg_msg_thrd_ring(fd, &req_msg);
            break;
        default:
            break;
    }

    if (ret != GAZELLE_OK) {
        goto END;
    }
    return;
END:
    if (data->pid != 0) {
        handle_instance_logout(data->pid);
    }
    sockfd_data_free(data);
    return;
}

static void gazelle_ctl_loop(void)
{
    int32_t num;
    struct epoll_event evt_array[GAZELLE_MAX_EVENTS_NUM];
    struct sockfd_data *fd_data = NULL;

    num = epoll_wait(g_epoll_fd, evt_array, GAZELLE_MAX_EVENTS_NUM, -1);
    if (num < 0) {
        LTRAN_ERR("epoll_wait ERROR, errno: %d\n", errno);
        return;
    }

    for (int32_t i = 0; i < num; i++) {
        fd_data = (struct sockfd_data *)evt_array[i].data.ptr;
        if (fd_data->func == NULL) {
            set_ltran_stop_flag(GAZELLE_TRUE);
            LTRAN_ERR("fd_data's func is empty\n");
            return;
        }

        fd_data->func(evt_array[i].events, fd_data);
        if (get_ltran_stop_flag() == GAZELLE_TRUE) {
            /* After ltran exits, no further events will be processed */
            break;
        }
    }
}

void *ctrl_thread_fn(void *unuse)
{
    int32_t ret;
    (void)unuse;

    ret = prctl(PR_SET_NAME, "monitor_thread");
    if (ret < 0)    {
        LTRAN_ERR("set monitor_thread name failed. errno: %d ret=%d.\n", errno, ret);
        return NULL;
    }

    ret = gazelle_ctl_init();
    if (ret != GAZELLE_OK) {
        LTRAN_ERR("gazelle_ctl_init failed. ret=%d.\n", ret);
        return NULL;
    }
    LTRAN_INFO("control thread init success.\n");

    while (get_ltran_stop_flag() != GAZELLE_TRUE) {
        gazelle_ctl_loop();
    }

    gazelle_ctl_destroy();
    return NULL;
}

