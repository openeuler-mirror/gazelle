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

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <semaphore.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <securec.h>
#include <numa.h>
#include <pthread.h>
#include <rte_pdump.h>
#include <unistd.h>

#include <lwip/def.h>
#include <lwip/init.h>
#include <lwip/lwipsock.h>
#include <lwip/tcpip.h>
#include <lwip/memp_def.h>
#include <lwip/lwipopts.h>
#include <lwip/posix_api.h>

#include "lstack_cfg.h"
#include "lstack_control_plane.h"
#include "lstack_ethdev.h"
#include "lstack_dpdk.h"
#include "lstack_stack_stat.h"
#include "lstack_log.h"
#include "dpdk_common.h"
#include "posix/lstack_epoll.h"
#include "posix/lstack_unistd.h"
#include "gazelle_base_func.h"
#include "lstack_protocol_stack.h"

#define LSTACK_PRELOAD_ENV_SYS      "LD_PRELOAD"
#define LSTACK_SO_NAME              "liblstack.so"
#define LSTACK_PRELOAD_NAME_LEN     PATH_MAX
#define LSTACK_PRELOAD_ENV_PROC     "GAZELLE_BIND_PROCNAME"
#define LSTACK_ENV_THREAD           "GAZELLE_THREAD_NAME"

static volatile bool g_init_fail = false;
static PER_THREAD int32_t g_thread_path = -1;

void set_init_fail(void)
{
    g_init_fail = true;
}

bool get_init_fail(void)
{
    return g_init_fail;
}

struct lstack_preload {
    int32_t preload_switch;
    char env_procname[LSTACK_PRELOAD_NAME_LEN];
    bool get_thread_name;
    char env_threadname[LSTACK_PRELOAD_NAME_LEN];
};
static struct lstack_preload g_preload_info = {0};

static void get_select_thread_name(void)
{
    g_preload_info.get_thread_name = true;

    char *enval = NULL;
    enval = getenv(LSTACK_ENV_THREAD);
    if (enval == NULL) {
        return;
    }
    if (strcpy_s(g_preload_info.env_threadname, LSTACK_PRELOAD_NAME_LEN, enval) != EOK) {
        return;
    }

    LSTACK_PRE_LOG(LSTACK_INFO, "thread name=%s ok\n", g_preload_info.env_threadname);
}

static int32_t preload_info_init(void)
{
    char *enval = NULL;

    g_preload_info.preload_switch = 0;
    
    get_select_thread_name();

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

    g_preload_info.preload_switch = 1;
    LSTACK_PRE_LOG(LSTACK_INFO, "LD_PRELOAD ok\n");
    return 0;
}

bool select_thread_path(void)
{
    if (g_thread_path >= 0) {
        return g_thread_path;
    }

    if (!g_preload_info.get_thread_name) {
        get_select_thread_name();
    }

    /* not set GAZELLE_THREAD_NAME, select all thread */
    if (g_preload_info.env_threadname[0] == '\0') {
        g_thread_path = 1;
        return true;
    }

    char thread_name[PATH_MAX] = {0};
    if (pthread_getname_np(pthread_self(), thread_name, PATH_MAX) != 0) {
        g_thread_path = 0;
        return false;
    }

    if (strstr(thread_name, g_preload_info.env_threadname) == NULL) {
        g_thread_path = 0;
        return false;
    }

    g_thread_path = 1;
    return true;
}

static int32_t check_process_conflict(void)
{
    int32_t ret;
    FILE *fp = NULL;
    char pathname[PATH_MAX];

    ret = sprintf_s(pathname, sizeof(pathname), "%s/%s",
                    GAZELLE_RUN_DIR, get_global_cfg_params()->sec_attach_arg.file_prefix);
    if (ret < 0) {
        return -1;
    }

    fp = fopen(pathname, "r");
    if (fp == NULL) {
        fp = fopen(pathname, "w");
        if (fp == NULL) {
            LSTACK_PRE_LOG(LSTACK_INFO, "open failed, errno %d\n", errno);
            return 0;
        }
    }

    ret = flock((fileno(fp)), LOCK_EX | LOCK_NB);
    (void)fclose(fp);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

static int32_t check_preload_bind_proc(void)
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

__attribute__((destructor)) void gazelle_network_exit(void)
{
    if (posix_api != NULL && !posix_api->ues_posix) {
        lwip_exit();
    }

    if (!use_ltran()) {
        int32_t ret = rte_pdump_uninit();
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "rte_pdump_uninit failed\n");
        }

        dpdk_kni_release();
    }
}

static void create_control_thread(void)
{
    int32_t ret;

    pthread_t tid;
    if (use_ltran()) {
	/* 
	 * The function call here should be in strict order. 
	 */
        dpdk_skip_nic_init();
        if (control_init_client(false) != 0) {
            LSTACK_EXIT(1, "control_init_client failed\n");
        }
        ret = pthread_create(&tid, NULL, (void *(*)(void *))control_client_thread, NULL);
        if (ret != 0) {
            LSTACK_EXIT(1, "pthread_create failed ret=%d errno=%d\n", ret, errno);
        }
    } else {
        ret = pthread_create(&tid, NULL, (void *(*)(void *))control_server_thread, NULL);
        if (ret != 0) {
            LSTACK_EXIT(1, "pthread_create failed ret=%d errno=%d\n", ret, errno);
        }
        ret = dpdk_eal_init();
        if (ret < 0) {
            LSTACK_EXIT(1, "dpdk_eal_init failed ret=%d errno=%d\n", ret, errno);
        }
    }

    if (pthread_setname_np(tid, CONTROL_THREAD_NAME) != 0) {
        LSTACK_LOG(ERR, LSTACK, "pthread_setname_np failed errno=%d\n", errno);
    }
    LSTACK_LOG(INFO, LSTACK, "create control_easy_thread success\n");
}

static void gazelle_signal_init(void)
{
    /* to prevent crash , just ignore SIGPIPE when socket is closed */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        LSTACK_PRE_LOG(LSTACK_ERR, "signal error, errno:%d.", errno);
        LSTACK_EXIT(1, "signal SIGPIPE SIG_IGN\n");
    }

    /*
    * register core sig handler func to dumped stack */
    lstack_signal_init();
}

__attribute__((constructor)) void gazelle_network_init(void)
{
    /*
    * Init POSXI API and prelog */
    lstack_prelog_init("LSTACK");
    if (posix_api_init() != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "posix_api_init failed\n");
        LSTACK_EXIT(1, "failed\n");
    }

    /*
    * Init LD_PRELOAD */
    if (preload_info_init() < 0) {
        return;
    }
    if (check_preload_bind_proc() < 0) {
        return;
    }

    /*
    * Read configure from lstack.cfg */
    if (cfg_init() != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "cfg_init failed\n");
        LSTACK_EXIT(1, "cfg_init failed\n");
    }
    LSTACK_PRE_LOG(LSTACK_INFO, "cfg_init success\n");

    /*
    * check conflict */
    if (check_process_conflict() < 0) {
        LSTACK_PRE_LOG(LSTACK_INFO, "Have another same primary process. WARNING: Posix API will use kernel mode!\n");
        return;
    }

    /*
    * save initial affinity */
    if (!get_global_cfg_params()->main_thread_affinity) {
        if (thread_affinity_default() < 0) {
            LSTACK_PRE_LOG(LSTACK_ERR, "pthread_getaffinity_np failed\n");
            LSTACK_EXIT(1, "pthread_getaffinity_np failed\n");
        }
    }

    gazelle_signal_init();

    /*
    * Init control plane and dpdk init */
    create_control_thread();
    dpdk_restore_pci();

    /*
    * cancel the core binding from DPDK initialization */
    if (!get_global_cfg_params()->main_thread_affinity) {
        if (thread_affinity_default() < 0) {
            LSTACK_EXIT(1, "pthread_setaffinity_np failed\n");
        }
    }

    lstack_log_level_init();
    lstack_prelog_uninit();

    if (init_protocol_stack() != 0) {
        LSTACK_EXIT(1, "init_protocol_stack failed\n");
    }

    /*
    * nic */
    if (!use_ltran()) {
        if (init_dpdk_ethdev() != 0) {
            LSTACK_EXIT(1, "init_dpdk_ethdev failed\n");
        }
    }

    /*
    * lwip initialization */
    lwip_sock_init();

    /* wait stack thread and kernel_event thread init finish */
    wait_sem_value(&get_protocol_stack_group()->all_init, get_protocol_stack_group()->stack_num);
    if (g_init_fail) {
        LSTACK_EXIT(1, "stack thread or kernel_event thread failed\n");
    }

    posix_api->ues_posix = 0;
    LSTACK_LOG(INFO, LSTACK, "gazelle_network_init success\n");
    rte_smp_mb();
}
