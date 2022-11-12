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

#include <sys/un.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <securec.h>

#include <lwip/tcp.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <lwip/posix_api.h>
#include <lwip/reg_sock.h>

#include "lstack_cfg.h"
#include "lstack_dpdk.h"
#include "gazelle_reg_msg.h"
#include "gazelle_base_func.h"
#include "lstack_stack_stat.h"
#include "lstack_log.h"
#include "lstack_thread_rpc.h"
#include "lstack_protocol_stack.h"
#include "lstack_control_plane.h"

/* intervals between two connection attempts and two registration attempts, in second */
#define CONNECT_TO_LTRAN_INFINITE       (-1)
#define CONNECT_TO_LTRAN_RETRY_INTERVAL 1
#define RECONNECT_TO_LTRAN_DELAY        (1)
#define GAZELLE_BADFD                    (-1)
#define GAZELLE_LISTEN_BACKLOG           5
#define GAZELLE_10MS                    (10000)

static int32_t g_data_fd = -1;
static volatile bool g_register_state = true;

static void set_register_state(bool val)
{
    g_register_state = val;
}

bool get_register_state(void)
{
    return g_register_state;
}

static int control_unix_sock(struct sockaddr_un *address)
{
    int32_t sockfd = posix_api->socket_fn(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "socket return error(%d)\n", errno);
        return -1;
    }

    if (memset_s(address, sizeof(struct sockaddr_un), 0, sizeof(struct sockaddr_un)) != 0) {
        posix_api->close_fn(sockfd);
        return -1;
    }

    struct cfg_params *global_params = get_global_cfg_params();

    address->sun_family = AF_UNIX;
    int ret = strncpy_s(address->sun_path, sizeof(address->sun_path), global_params->unix_socket_filename,
        strlen(global_params->unix_socket_filename) + 1);
    if (ret != EOK) {
        posix_api->close_fn(sockfd);
        return -1;
    }

    return sockfd;
}

static int32_t connect_to_ltran(int32_t times, int32_t interval)
{
    int32_t sockfd = -1;
    struct sockaddr_un address;
    int32_t tmp_times = times;

    if ((times < -1) || (times == 0)) {
        return -1;
    }

    while (1) {
        sockfd = control_unix_sock(&address);
        if (sockfd < 0) {
            return sockfd;
        }

        int32_t ret = posix_api->connect_fn(sockfd, (struct sockaddr*)&address, sizeof(address));
        if (ret == 0) {
            return sockfd;
        } else {
            sockfd = -1;
            posix_api->close_fn(sockfd);

            /* check timeout */
            if (tmp_times != -1) {
                tmp_times--;
            }
            if (tmp_times == 0) {
                return -1;
            }
        }

        sleep(interval);
    }

    return sockfd;
}

static int32_t msg_proc_init(enum request_type rqt_type, struct reg_request_msg *rqt_msg)
{
    int32_t ret;
    struct cfg_params *global_params = get_global_cfg_params();

    rqt_msg->type = rqt_type;
    struct client_proc_conf *conf = &rqt_msg->msg.proc;

    conf->pid = getpid();
    /* aleardy net byte order so that ltran can be used directly */
    conf->ipv4 = global_params->host_addr.addr;

    ret = strncpy_s(conf->file_prefix, PATH_MAX, global_params->sec_attach_arg.file_prefix, PATH_MAX - 1);
    if (ret != EOK) {
        return ret;
    }

    ret = memcpy_s(conf->mac_addr, ETHER_ADDR_LEN, global_params->mac_addr, ETHER_ADDR_LEN);
    if (ret != EOK) {
        return ret;
    }
    switch (rqt_type) {
        case RQT_REG_PROC_MEM:
            conf->socket_size = global_params->sec_attach_arg.socket_size;
            conf->base_virtaddr = global_params->sec_attach_arg.base_virtaddr;

            LSTACK_LOG(DEBUG, LSTACK, "type %d, pid %u, ip %u, file_prefix %s\n", (int32_t)rqt_type, conf->pid,
                conf->ipv4, conf->file_prefix);
            break;
        case RQT_REG_PROC_ATT:
            conf->argc = 0;
            ret = gazelle_copy_param(OPT_SOCKET_MEM, true, (int32_t *)&conf->argc, conf->argv);
            if (ret != EOK) {
                return ret;
            }
            ret = gazelle_copy_param(OPT_FILE_PREFIX, true, (int32_t *)&conf->argc, conf->argv);
            if (ret != EOK) {
                return ret;
            }
            ret = gazelle_copy_param(OPT_LEGACY_MEM, false, (int32_t *)&conf->argc, conf->argv);
            if (ret != EOK) {
                return ret;
            }

            break;
        default:
             LSTACK_LOG(DEBUG, LSTACK, "type invalid\n");
            return -1;
    }

    return 0;
}

static int32_t msg_thrd_init(enum request_type rqt_type, struct reg_request_msg *rqt_msg)
{
    struct protocol_stack *stack = get_protocol_stack();

    rqt_msg->type = rqt_type;
    struct client_thrd_conf *conf = &rqt_msg->msg.thrd;

    conf->pid = getpid();
    conf->tid = rte_gettid();

    switch (rqt_type) {
        case RQT_REG_THRD_RING:
            conf->rx_ring   = stack->rx_ring;
            conf->tx_ring   = stack->tx_ring;
            conf->reg_ring  = stack->reg_ring;
            break;
        default:
            return -1;
    }

    return 0;
}

static int32_t reg_communicate(const int32_t sockfd, struct reg_request_msg *send_msg,
    struct reg_response_msg *recv_msg)
{
    ssize_t size;

    size = posix_api->write_fn(sockfd, send_msg, sizeof(*send_msg));
    if (size <= 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "write failed, errno %d\n", errno);
        return -1;
    }

    char *buf = (char *)recv_msg;
    ssize_t recv_size = (ssize_t)sizeof(*recv_msg);
    while (recv_size > 0) {
        size = posix_api->read_fn(sockfd, buf, recv_size);
        if ((size < 0) && (errno != EINTR)  && (errno != EAGAIN)) {
            LSTACK_PRE_LOG(LSTACK_ERR, "read failed, errno %d\n", errno);
            return -1;
        } else if (size == 0) {
            LSTACK_PRE_LOG(LSTACK_ERR, "read failed, fd closed\n");
            return -1;
        }
        recv_size -= (size < 0) ? 0 : size;
        buf += size;
    }

    return 0;
}

/* change file permissions for security
   dpdk unix socket create mp_socket file permissions is default maybe not 700 */
static void chmod_dpdk_file(void)
{
    char dpdk_run_path[PATH_MAX] = {0};
    int32_t ret;

    ret = sprintf_s(dpdk_run_path, PATH_MAX, "%s/mp_socket", rte_eal_get_runtime_dir());
    if (ret < 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "snprintf failed ret=%d\n", ret);
    }

    ret = chmod(dpdk_run_path, S_IRUSR | S_IWUSR | S_IXUSR);
    if (ret < 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "chmod %s failed errno=%d ret=%d\n", dpdk_run_path, errno, ret);
    }
}

static int32_t proc_memory_init(const struct reg_response_msg *rsp_msg)
{
    int32_t ret;
    int32_t lc_argc = 0;
    struct cfg_params *global_params = get_global_cfg_params();
    char *lc_argv[GAZELLE_MAX_REG_ARGS] = {NULL};

    if (rsp_msg == NULL) {
        LSTACK_PRE_LOG(LSTACK_ERR, "input invalid\n");
        return -1;
    }

    if (global_params->sec_attach_arg.base_virtaddr != rsp_msg->msg.base_virtaddr) {
        global_params->sec_attach_arg.base_virtaddr = rsp_msg->msg.base_virtaddr;
    }

    ret = gazelle_param_init(&lc_argc, lc_argv);
    if (ret != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "gazelle_param_init failed before dpdk_init ret=%d\n", ret);
        return ret;
    }

    ret = rte_eal_init(lc_argc, lc_argv);
    if (ret < 0) {
        if (rte_errno == EALREADY)
            LSTACK_PRE_LOG(LSTACK_INFO, "rte_eal_init aleady init ret=%d\n", ret);
        else
            LSTACK_PRE_LOG(LSTACK_ERR, "rte_eal_init failed init, rte_errno %d ret=%d\n", rte_errno, ret);
        return -1;
    }

    chmod_dpdk_file();
    return 0;
}

static int32_t client_reg_proc_memory(bool is_reconnect)
{
    int32_t ret;
    int32_t sockfd = g_data_fd;
    struct reg_request_msg send_msg = {0};
    struct reg_response_msg recv_msg = {0};

    ret = msg_proc_init(RQT_REG_PROC_MEM, &send_msg);
    if (ret != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "%s msg_proc_init failed ret=%d\n", __func__, ret);
        return -1;
    }

    ret = reg_communicate(sockfd, &send_msg, &recv_msg);
    if (ret != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "%s reg_communicate failed ret=%d\n", __func__, ret);
        return -1;
    }

    if (recv_msg.type != RSP_OK) {
        LSTACK_PRE_LOG(LSTACK_ERR, "%s register response err ret=%d\n", __func__, ret);
        return -1;
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    stack_group->rx_offload = recv_msg.msg.rx_offload;
    stack_group->tx_offload = recv_msg.msg.tx_offload;

    if (!is_reconnect) {
        ret = proc_memory_init(&recv_msg);
        if (ret != 0) {
            LSTACK_PRE_LOG(LSTACK_ERR, "%s proc_memory_init failed ret=%d\n", __func__, ret);
            return -1;
        }
    }

    return 0;
}

static int32_t client_reg_proc_attach(__attribute__((__unused__)) bool is_reconnect)
{
    int32_t ret;
    int32_t sockfd = g_data_fd;
    struct reg_request_msg send_msg = {0};
    struct reg_response_msg recv_msg = {0};

    ret = msg_proc_init(RQT_REG_PROC_ATT, &send_msg);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "msg_proc_init failed ret=%d\n", ret);
        return -1;
    }

    ret = reg_communicate(sockfd, &send_msg, &recv_msg);
    if (ret != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "reg_communicate failed ret=%d\n", ret);
        return -1;
    }

    if (recv_msg.type != RSP_OK) {
        LSTACK_LOG(ERR, LSTACK, "register response err\n");
        return -1;
    }

    return 0;
}

static int32_t reg_conn(enum tcp_list_state table_state, enum reg_ring_type reg_type,
    const struct gazelle_stat_lstack_conn *conn)
{
    struct gazelle_quintuple qtuple;
    int32_t sent_pkts;
    uint32_t tbegin;

    for (uint32_t i = 0; i < conn->conn_num; i++) {
        if (conn->conn_list[i].state != table_state) {
            continue;
        }

        qtuple.protocol = 0;
        qtuple.src_ip = conn->conn_list[i].lip;
        qtuple.src_port = lwip_htons(conn->conn_list[i].l_port);
        qtuple.dst_ip = conn->conn_list[i].rip;
        qtuple.dst_port = lwip_htons(conn->conn_list[i].r_port);

        if ((table_state == LISTEN_LIST) &&
            (!match_host_addr(qtuple.src_ip))) {
            continue;
        }

        tbegin = sys_now();
        do {
            sent_pkts = vdev_reg_xmit(reg_type, &qtuple);
        } while ((sent_pkts < 1) && (ENQUEUE_RING_RETRY_TIMEOUT > sys_now() - tbegin));
        if (sent_pkts < 1) {
            return -1;
        }
    }

    return 0;
}

void thread_register_phase1(struct rpc_msg *msg)
{
    int32_t ret;

    ret = client_reg_thrd_ring();
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "reconnect client_reg_thrd_ring fail ret=%d\n", ret);
        msg->result = ret;
        return;
    }

    struct gazelle_stat_lstack_conn *conn = (struct gazelle_stat_lstack_conn *)msg->args[MSG_ARG_0].p;
    ret = reg_conn(ACTIVE_LIST, REG_RING_TCP_CONNECT, conn);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "ACTIVE_LIST rereg conn fail ret=%d\n", ret);
        msg->result = ret;
        return;
    }

    ret = reg_conn(TIME_WAIT_LIST, REG_RING_TCP_CONNECT, conn);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "TIME_WAIT_LIST rereg conn fail ret=%d\n", ret);
    }
    msg->result = ret;
}

void thread_register_phase2(struct rpc_msg *msg)
{
    struct gazelle_stat_lstack_conn *conn = (struct gazelle_stat_lstack_conn *)msg->args[MSG_ARG_0].p;

    int32_t ret = reg_conn(LISTEN_LIST, REG_RING_TCP_LISTEN, conn);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "LISTEN_LIST rereg conn fail ret=%d\n", ret);
    }

    msg->result = ret;
}

int32_t client_reg_thrd_ring(void)
{
    int32_t ret;
    int32_t sockfd;
    struct reg_request_msg send_msg = {0};
    struct reg_response_msg recv_msg = {0};

    sockfd = connect_to_ltran(CONNECT_TO_LTRAN_INFINITE, CONNECT_TO_LTRAN_RETRY_INTERVAL);
    if (sockfd < 0) {
        LSTACK_LOG(ERR, LSTACK, "connect_to_ltran failed sockfd=%d\n", sockfd);
        posix_api->close_fn(sockfd);
        return sockfd;
    }

    ret = msg_thrd_init(RQT_REG_THRD_RING, &send_msg);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "msg_thrd_init failed ret=%d\n", ret);
        posix_api->close_fn(sockfd);
        return ret;
    }

    ret = reg_communicate(sockfd, &send_msg, &recv_msg);
    if (ret != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "reg_communicate failed ret=%d\n", ret);
        posix_api->close_fn(sockfd);
        return ret;
    }

    if (recv_msg.type != RSP_OK) {
        LSTACK_LOG(ERR, LSTACK, "register response err\n");
        posix_api->close_fn(sockfd);
        return -1;
    }

    posix_api->close_fn(sockfd);
    return 0;
}

void control_fd_close(void)
{
    if (g_data_fd != 0) {
        close(g_data_fd);
        g_data_fd = -1;
        /* 200ms: wait ltran instance logout */
        rte_delay_ms(200);
    }

    struct cfg_params *global_params = get_global_cfg_params();
    if (!global_params->use_ltran) {
	int ret = unlink(global_params->unix_socket_filename);
	if (ret == -1) {
            LSTACK_LOG(ERR, LSTACK, "unlink failed, just skip it\n");
	}
    }
}

int32_t control_init_client(bool is_reconnect)
{
    int32_t ret;
    int32_t sockfd;

    sockfd = connect_to_ltran(CONNECT_TO_LTRAN_INFINITE, CONNECT_TO_LTRAN_RETRY_INTERVAL);
    if (sockfd < 0) {
        LSTACK_LOG(ERR, LSTACK, "connect to ltran failed\n");
        return -1;
    }
    g_data_fd = sockfd;

    ret = client_reg_proc_memory(is_reconnect);
    if (ret != 0) {
        posix_api->close_fn(g_data_fd);
        g_data_fd = -1;
        return -1;
    }

    ret = client_reg_proc_attach(is_reconnect);
    if (ret != 0) {
        posix_api->close_fn(g_data_fd);
        g_data_fd = -1;
        return -1;
    }

    return 0;
}

static int32_t set_lstack_log_level(const char* log_level)
{
    if (strcmp(log_level, "error") == 0) {
        rte_log_set_global_level(RTE_LOG_ERR);
        (void)rte_log_set_level(RTE_LOGTYPE_LSTACK, RTE_LOG_ERR);
        LSTACK_LOG(ERR, LSTACK, "lstack log set to error level!\n");
        return 0;
    }

    if (strcmp(log_level, "info") == 0) {
        rte_log_set_global_level(RTE_LOG_INFO);
        (void)rte_log_set_level(RTE_LOGTYPE_LSTACK, RTE_LOG_INFO);
        LSTACK_LOG(INFO, LSTACK, "lstack log set to info level!\n");
        return 0;
    }

    if (strcmp(log_level, "debug") == 0) {
        rte_log_set_global_level(RTE_LOG_DEBUG);
        (void)rte_log_set_level(RTE_LOGTYPE_LSTACK, RTE_LOG_DEBUG);
        LSTACK_LOG(DEBUG, LSTACK, "lstack log set to debug level!\n");
        return 0;
    }

    return -1;
}

static int32_t handle_proc_cmd(int32_t sockfd, struct gazelle_stat_msg_request *msg)
{
    struct cfg_params *cfg = get_global_cfg_params();
    struct gazelle_stack_dfx_data rsp = {0};
    int32_t ret;

    if (msg->stat_mode == GAZELLE_STAT_LSTACK_LOG_LEVEL_SET) {
        msg->data.log_level[GAZELLE_LOG_LEVEL_MAX - 1] = '\0';
        ret = set_lstack_log_level(msg->data.log_level);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "lstack log set log level fail ret=%d\n", ret);
        }
    }
    if (msg->stat_mode == GAZELLE_STAT_LSTACK_LOW_POWER_MDF) {
        cfg->low_power_mod = msg->data.low_power_mod;
        lstack_get_low_power_info(&(rsp.low_power_info));
    }

    rsp.eof = 1;
    ret = (int32_t)posix_api->write_fn(sockfd, (void *)&rsp, sizeof(rsp));
    if (ret <= 0) {
        LSTACK_LOG(ERR, LSTACK, "write msg from peer failed, errno %d. ret=%d\n", errno, ret);
        return -1;
    }
    return 0;
}

static int32_t handle_stat_request(int32_t sockfd)
{
    int32_t ret;
    struct gazelle_stat_msg_request msg;

    ret = (int32_t)posix_api->read_fn(sockfd, &msg, sizeof(struct gazelle_stat_msg_request));
    if (ret != (int32_t)sizeof(struct gazelle_stat_msg_request)) {
        LSTACK_LOG(ERR, LSTACK, "unknow wrong, we recieve something, ret %d\n", ret);
        return -1;
    }

    if (msg.stat_mode >= GAZELLE_STAT_MODE_MAX) {
        LSTACK_LOG(ERR, LSTACK, "recv wrong stat mode %d\n", (int32_t)msg.stat_mode);
        return 0;
    }

    if (msg.stat_mode == GAZELLE_STAT_LSTACK_LOG_LEVEL_SET ||
        msg.stat_mode == GAZELLE_STAT_LSTACK_LOW_POWER_MDF) {
        return handle_proc_cmd(sockfd, &msg);
    } else {
        ret = handle_stack_cmd(sockfd, msg.stat_mode);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "get_stats failed ret=%d\n", ret);
        }
        return 0;
    }
}

static int32_t thread_register(void)
{
    int32_t ret;

    struct gazelle_stat_lstack_conn *conn = malloc(sizeof(struct gazelle_stat_lstack_conn));
    if (conn == NULL) {
        LSTACK_LOG(ERR, LSTACK, "malloc fail\n");
        return -1;
    }

    /* register all connected conn before listen conn, avoid creating new conn */
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    for (int32_t i = 0; i < stack_group->stack_num; i++) {
        conn->conn_num = rpc_call_conntable(stack_group->stacks[i], conn->conn_list, GAZELLE_LSTACK_MAX_CONN);

        ret = rpc_call_thread_regphase1(stack_group->stacks[i], conn);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "thread_register_phase1  failed ret=%d!\n", ret);
            free(conn);
            return -1;
        }
    }

    for (int32_t i = 0; i < stack_group->stack_num; i++) {
        conn->conn_num = rpc_call_conntable(stack_group->stacks[i], conn->conn_list, GAZELLE_LSTACK_MAX_CONN);

        ret = rpc_call_thread_regphase2(stack_group->stacks[i], conn);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "thread_register_phase2  failed ret=%d!\n", ret);
            free(conn);
            return -1;
        }
    }

    free(conn);
    return 0;
}

static int32_t client_reg_proc_reconnect(int32_t epfd)
{
    int32_t ret, sockfd;
    struct epoll_event ev = {0};

    /* longterm connect g_data_fd; init process info */
    ret = control_init_client(true);
    if (ret != 0) {
        return -1;
    }
    sockfd = g_data_fd;

    ret = thread_register();
    if (ret != 0) {
        posix_api->close_fn(sockfd);
        g_data_fd = -1;
        return -1;
    }

    ev.events = EPOLLIN;
    ret = posix_api->epoll_ctl_fn(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "epoll_ctl_fn failed, errno is %d ret=%d\n", errno, ret);
        posix_api->close_fn(sockfd);
        g_data_fd = -1;
        return -1;
    }

    LSTACK_LOG(INFO, LSTACK, "lstack reconnect to ltran success!\n");
    return sockfd;
}

static int32_t init_epoll(int32_t sockfd)
{
    int32_t ret, epfd;
    struct epoll_event ev = {0};

    epfd = posix_api->epoll_create_fn(1);
    if (epfd < 0) {
        LSTACK_LOG(ERR, LSTACK, "epoll_create_fn failed, errno is %d\n", errno);
        return -1;
    }

    ev.events = EPOLLIN;
    ev.data.fd = sockfd;
    ret = posix_api->epoll_ctl_fn(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "epoll_ctl_fn failed, errno is %d ret=%d\n", errno, ret);
        posix_api->close_fn(epfd);
        return -1;
    }

    return epfd;
}

static int32_t control_init_server(void)
{
    struct sockaddr_un address;
    int32_t ret;

    ret = check_and_set_run_dir();
    if (ret == -1) {
        LSTACK_LOG(ERR, LSTACK, "create /var/run/gazelle failed\n");
        return -1;
    }

    ret = unlink(get_global_cfg_params()->unix_socket_filename);
    if (ret == -1) {
        LSTACK_LOG(ERR, LSTACK, "unlink failed, just skip it\n");
    }

    int32_t fd = control_unix_sock(&address);
    if (fd < 0) {
        LSTACK_LOG(ERR, LSTACK, "control_unix_sock failed\n");
        return fd;
    }

    ret = posix_api->bind_fn(fd, (const struct sockaddr *)&address, sizeof(struct sockaddr_un));
    if (ret == -1) {
        posix_api->close_fn(fd);
        LSTACK_LOG(ERR, LSTACK, "bind failed, errno is %d\n", errno);
        return ret;
    }

    ret = posix_api->listen_fn(fd, GAZELLE_LISTEN_BACKLOG);
    if (ret == -1) {
        posix_api->close_fn(fd);
        LSTACK_LOG(ERR, LSTACK, "listen failed\n");
        return ret;
    }

    return fd;
}

void control_server_thread(void *arg)
{
    int32_t listenfd = control_init_server();
    if (listenfd < 0) {
        LSTACK_LOG(ERR, LSTACK, "control_init_server failed\n");
        return;
    }

    int32_t epfd = init_epoll(listenfd);
    if (epfd < 0) {
        posix_api->close_fn(listenfd);
        LSTACK_LOG(ERR, LSTACK, "init_epoll failed\n");
        return;
    }

    int32_t num, connfd;
    struct epoll_event evt_array;
    while (1) {
        /* wait init finish */
        if (posix_api->ues_posix) {
            usleep(GAZELLE_10MS);
            continue;
        }

        num = posix_api->epoll_wait_fn(epfd, &evt_array, 1, -1);
        if (num <= 0) {
            continue;
        }

        if ((evt_array.events & EPOLLERR) || (evt_array.events & EPOLLHUP)) {
            posix_api->close_fn(evt_array.data.fd);
            continue;
        }

        if (evt_array.data.fd == listenfd) {
            connfd = posix_api->accept_fn(listenfd, NULL, NULL);
            if (connfd < 0) {
                continue;
            }

            evt_array.data.fd = connfd;
            evt_array.events = EPOLLIN;
            if (posix_api->epoll_ctl_fn(epfd, EPOLL_CTL_ADD, connfd, &evt_array) < 0) {
                posix_api->close_fn(connfd);
            }
        } else {
            if (handle_stat_request(evt_array.data.fd) < 0) {
                posix_api->close_fn(evt_array.data.fd);
            }
        }
    }
}

void control_client_thread(void *arg)
{
    int32_t ret, num, epfd;
    struct epoll_event evt_array;
    int32_t sockfd = g_data_fd;

    epfd = init_epoll(sockfd);
    if (epfd < 0) {
        posix_api->close_fn(sockfd);
        LSTACK_LOG(ERR, LSTACK, "control_thread fail\n");
        return;
    }

    while (1) {
        /* wait init finish */
        if (posix_api->ues_posix) {
            usleep(GAZELLE_10MS);
            continue;
        }

        if (sockfd < 0) {
            set_register_state(false);
            sockfd = client_reg_proc_reconnect(epfd);
            if (sockfd < 0) {
                /* avoid trying too often */
                (void)sleep(RECONNECT_TO_LTRAN_DELAY);
            } else {
                set_register_state(true);
            }
            continue;
        }

        num = posix_api->epoll_wait_fn(epfd, &evt_array, 1, -1);
        if (num > 0) {
            if ((evt_array.events & EPOLLERR) || (evt_array.events & EPOLLHUP)) {
                LSTACK_LOG(WARNING, LSTACK, "lost connection to ltran, try reconnect %u\n", evt_array.events);
                posix_api->close_fn(sockfd);
                sockfd = -1;
                continue;
            }

            ret = handle_stat_request(sockfd);
            if (ret < 0) {
                LSTACK_LOG(WARNING, LSTACK, "lost connection to ltran, try reconnect ret=%d\n", ret);
                posix_api->close_fn(sockfd);
                sockfd = -1;
            }
        } else {
            LSTACK_LOG(WARNING, LSTACK, "epoll_wait_fn failed, errno is %d num=%d\n", errno, num);
        }
    }
}
