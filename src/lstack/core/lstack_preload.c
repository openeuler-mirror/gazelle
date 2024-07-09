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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <securec.h>

#include <lwip/posix_api.h>
#include <lwip/lwipsock.h>
#include <lwip/lwipopts.h>

#include "lstack_log.h"
#include "lstack_preload.h"

#define LSTACK_PRELOAD_ENV_SYS      "LD_PRELOAD"
#define LSTACK_SO_NAME              "liblstack.so"
#define LSTACK_PRELOAD_NAME_LEN     PATH_MAX
#define LSTACK_PRELOAD_ENV_PROC     "GAZELLE_BIND_PROCNAME"
#define LSTACK_PRELOAD_ENV_THRD     "GAZELLE_THREAD_NAME"

#define EXCLUDE_THRD_CNT            1
const static char *g_exclude_thread[EXCLUDE_THRD_CNT] = {"eal-intr-thread"};
static PER_THREAD enum KERNEL_LWIP_PATH g_preload_thrdpath = PATH_UNKNOW;

struct lstack_preload {
    int32_t preload_switch;
    char env_procname[LSTACK_PRELOAD_NAME_LEN];
    bool get_thrdname;
    char env_thrdname[LSTACK_PRELOAD_NAME_LEN];
};
static struct lstack_preload g_preload_info = {0};

static int32_t preload_check_bind_proc(void)
{
    char proc_path[PATH_MAX] = {0};

    if (!g_preload_info.preload_switch) {
        return 0;
    }

    if (readlink("/proc/self/exe", proc_path, PATH_MAX - 1) <= 0) {
        return -1;
    }

    char *proc_name = strrchr(proc_path, '/');
    if (!proc_name) {
        return -1;
    }

    if (strncmp(++proc_name, g_preload_info.env_procname, PATH_MAX) == 0) {
        return 0;
    }
    return -1;
}

static void preload_get_thrdname(void)
{
    g_preload_info.get_thrdname = true;

    char *enval = NULL;
    enval = getenv(LSTACK_PRELOAD_ENV_THRD);
    if (enval == NULL) {
        return;
    }
    if (strcpy_s(g_preload_info.env_thrdname, LSTACK_PRELOAD_NAME_LEN, enval) != EOK) {
        return;
    }

    LSTACK_PRE_LOG(LSTACK_INFO, "thread name=%s ok\n", g_preload_info.env_thrdname);
}

enum KERNEL_LWIP_PATH select_fd_posix_path(int32_t fd, struct lwip_sock **socket)
{
    struct lwip_sock *sock = get_socket_by_fd(fd);

    /* AF_UNIX case */
    if (!sock || !sock->conn || CONN_TYPE_IS_HOST(sock->conn)) {
        return PATH_KERNEL;
    }

    if (socket) {
        *socket = sock;
    }

    if (likely(CONN_TYPE_IS_LIBOS(sock->conn))) {
        return PATH_LWIP;
    }

    return PATH_UNKNOW;
}

enum KERNEL_LWIP_PATH select_posix_path(void)
{
    if (unlikely(posix_api == NULL)) {
        /*
        * posix api maybe call before gazelle init
        * So, we must call posix_api_init at the head of select_path
        */
        if (posix_api_init() != 0) {
            LSTACK_PRE_LOG(LSTACK_ERR, "posix_api_init failed\n");
        }
        return PATH_KERNEL;
    }

    if (unlikely(posix_api->ues_posix)) {
        return PATH_KERNEL;
    }

    if (g_preload_thrdpath != PATH_UNKNOW) {
        return g_preload_thrdpath;
    }

    if (!g_preload_info.get_thrdname) {
        preload_get_thrdname();
    }

    char thread_name[PATH_MAX] = {0};
    if (pthread_getname_np(pthread_self(), thread_name, PATH_MAX) != 0) {
        g_preload_thrdpath = PATH_KERNEL;
        return PATH_KERNEL;
    }

    /* exclude dpdk thread */
    for (int i = 0; i < EXCLUDE_THRD_CNT; i++) {
        if (strstr(thread_name, g_exclude_thread[i]) != NULL) {
            g_preload_thrdpath = PATH_KERNEL;
            return PATH_KERNEL;
        }
    }

    /* not set GAZELLE_THREAD_NAME, select all thread */
    if (g_preload_info.env_thrdname[0] == '\0') {
        g_preload_thrdpath = PATH_LWIP;
        return PATH_LWIP;
    }

    if (strstr(thread_name, g_preload_info.env_thrdname) == NULL) {
        g_preload_thrdpath = PATH_KERNEL;
        return PATH_KERNEL;
    }

    g_preload_thrdpath = PATH_LWIP;
    return PATH_LWIP;
}

int preload_info_init(void)
{
    char *enval = NULL;

    g_preload_info.preload_switch = 0;

    preload_get_thrdname();

    enval = getenv(LSTACK_PRELOAD_ENV_SYS);
    if (enval == NULL) {
        return 0;
    }

    if (strstr(enval, LSTACK_SO_NAME) == NULL) {
        return 0;
    }

    enval = getenv(LSTACK_PRELOAD_ENV_PROC);
    if (enval == NULL) {
        return -1;
    }
    if (strcpy_s(g_preload_info.env_procname, LSTACK_PRELOAD_NAME_LEN, enval) != EOK) {
        return -1;
    }

    enval = getenv(LSTACK_PRELOAD_ENV_THRD);
    if (enval != NULL) {
        if (strcpy_s(g_preload_info.env_thrdname, LSTACK_PRELOAD_NAME_LEN, enval) != EOK) {
            return -1;
        }
        g_preload_info.get_thrdname = true;
    }

    g_preload_info.preload_switch = 1;
    LSTACK_PRE_LOG(LSTACK_INFO, "LD_PRELOAD ok\n");
    return preload_check_bind_proc();
}
