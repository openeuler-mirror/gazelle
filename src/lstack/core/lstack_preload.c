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
#include <stdbool.h>

#include <lwip/lwipgz_posix_api.h>
#include <lwip/lwipgz_sock.h>
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
static PER_THREAD enum posix_type g_preload_thrdpath = POSIX_ALL;

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

enum posix_type select_sock_posix_path(struct lwip_sock *sock)
{
    if (unlikely(posix_api == NULL)) {
        /*
        * read/write/readv/writev may not be sockfd,
        * posix api maybe not init.
        */
        if (posix_api_init() != 0) {
            LSTACK_PRE_LOG(LSTACK_ERR, "posix_api_init failed\n");
        }
        return POSIX_KERNEL;
    }

    /* CLOSED means not sockfd, such as file fd or unix fd */
    if (POSIX_IS_CLOSED(sock) || POSIX_IS_TYPE(sock, POSIX_KERNEL)) {
        return POSIX_KERNEL;
    }

    if (likely(POSIX_IS_TYPE(sock, POSIX_LWIP))) {
        return POSIX_LWIP;
    }

    return POSIX_ALL;
}

enum posix_type select_posix_path(void)
{
    if (unlikely(posix_api == NULL)) {
        /*
        * posix api maybe call before gazelle init
        * So, we must call posix_api_init at the head of select_path
        */
        if (posix_api_init() != 0) {
            LSTACK_PRE_LOG(LSTACK_ERR, "posix_api_init failed\n");
        }
        return POSIX_KERNEL;
    }

    if (unlikely(posix_api->use_kernel)) {
        return POSIX_KERNEL;
    }

    if (likely(g_preload_thrdpath != POSIX_ALL)) {
        return g_preload_thrdpath;
    }

    if (!g_preload_info.get_thrdname) {
        preload_get_thrdname();
    }

    char thread_name[PATH_MAX] = {0};
    if (pthread_getname_np(pthread_self(), thread_name, PATH_MAX) != 0) {
        g_preload_thrdpath = POSIX_KERNEL;
        return POSIX_KERNEL;
    }

    /* exclude dpdk thread */
    for (int i = 0; i < EXCLUDE_THRD_CNT; i++) {
        if (strstr(thread_name, g_exclude_thread[i]) != NULL) {
            g_preload_thrdpath = POSIX_KERNEL;
            return POSIX_KERNEL;
        }
    }

    /* not set GAZELLE_THREAD_NAME, select all thread */
    if (g_preload_info.env_thrdname[0] == '\0') {
        g_preload_thrdpath = POSIX_LWIP;
        return POSIX_LWIP;
    }

    if (strstr(thread_name, g_preload_info.env_thrdname) == NULL) {
        g_preload_thrdpath = POSIX_KERNEL;
        return POSIX_KERNEL;
    }

    g_preload_thrdpath = POSIX_LWIP;
    return POSIX_LWIP;
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
