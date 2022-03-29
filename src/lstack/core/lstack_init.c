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
#include "lstack_signal.h"
#include "lstack_dpdk.h"
#include "lstack_stack_stat.h"
#include "lstack_log.h"
#include "posix/lstack_epoll.h"
#include "gazelle_base_func.h"
#include "lstack_protocol_stack.h"

#define LSTACK_PRELOAD_ENV_SYS      "LD_PRELOAD"
#define LSTACK_SO_NAME              "liblstack.so"
#define LSTACK_PRELOAD_NAME_LEN     PATH_MAX
#define LSTACK_PRELOAD_ENV_PROC     "GAZELLE_BIND_PROCNAME"

struct lstack_preload {
    int32_t preload_switch;
    char env_procname[LSTACK_PRELOAD_NAME_LEN];
};
static struct lstack_preload g_preload_info = {0};

static int32_t preload_info_init(void)
{
    char *enval = NULL;

    g_preload_info.preload_switch = 0;

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
    return 0;
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
    if (posix_api != NULL && !posix_api->is_chld) {
        lwip_exit();
    }

    if (!use_ltran()) {
        int32_t ret = rte_pdump_uninit();
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "rte_pdump_uninit failed\n");
        }
    }
}

__attribute__((constructor)) void gazelle_network_init(void)
{
    int32_t ret;

    /*
    * Phase 1: Init POSXI API and prelog */
    lstack_prelog_init("LSTACK");
    if (posix_api_init() != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "posix_api_init failed\n");
        LSTACK_EXIT(1, "failed\n");
    }

    /*
    * Phase 2: Init LD_PRELOAD */
    if (preload_info_init() < 0) {
        return;
    }
    if (check_preload_bind_proc() < 0) {
        return;
    }

    /*
    * Phase 3: Read configure from lstack.cfg */
    if (cfg_init() != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "cfg_init failed\n");
        LSTACK_EXIT(1, "cfg_init failed\n");
    }
    LSTACK_PRE_LOG(LSTACK_INFO, "cfg_init success\n");

    /*
    * Phase 4: check conflict */
    if (check_process_conflict() < 0) {
        LSTACK_PRE_LOG(LSTACK_INFO, "Have another same primary process. WARNING: Posix API will use kernel mode!\n");
        return;
    }

    /*
    * Phase 5: save initial affinity */
    if (thread_affinity_default() < 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "pthread_getaffinity_np failed\n");
        LSTACK_EXIT(1, "pthread_getaffinity_np failed\n");
    }

    /* to prevent crash , just ignore SIGPIPE when socket is closed */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        LSTACK_PRE_LOG(LSTACK_ERR, "signal error, errno:%d.", errno);
        LSTACK_EXIT(1, "signal SIGPIPE SIG_IGN\n");
    }

    /*
    * Phase 6: Init control plane and dpdk init */
    pthread_t tid;
    if (use_ltran()) {
        dpdk_skip_nic_init();
        if (control_init_client(false) != 0) {
            LSTACK_EXIT(1, "control_init_client failed\n");
        }
        ret = pthread_create(&tid, NULL, (void *(*)(void *))control_client_thread, NULL);
    } else {
        dpdk_eal_init();
        ret = pthread_create(&tid, NULL, (void *(*)(void *))control_server_thread, NULL);
    }
    if (ret != 0) {
        LSTACK_EXIT(1, "pthread_create failed errno=%d\n", errno);
    }
    if (pthread_setname_np(tid, CONTROL_THREAD_NAME) != 0) {
        LSTACK_LOG(ERR, LSTACK, "pthread_setname_np failed errno=%d\n", errno);
    }
    LSTACK_LOG(INFO, LSTACK, "create control_easy_thread success\n");

    /*
    * Phase 7: cancel the core binding from DPDK initialization */
    if (thread_affinity_default() < 0) {
        LSTACK_EXIT(1, "pthread_setaffinity_np failed\n");
    }

    lstack_log_level_init();

    ret = init_protocol_stack();
    if (ret != 0) {
        LSTACK_EXIT(1, "init_protocol_stack failed\n");
    }

    /*
    * Phase 8: nic */
    if (!use_ltran()) {
        ret = init_dpdk_ethdev();
        if (ret != 0) {
            LSTACK_EXIT(1, "init_dpdk_ethdev failed\n");
        }
    }

    /*
    * Phase 9: lwip initialization */
    lwip_sock_init();

    /*
    * Phase 10: register core sig handler func to dumped stack */
    lstack_signal_init();

    lstack_prelog_uninit();
    posix_api->is_chld = 0;
    LSTACK_LOG(INFO, LSTACK, "gazelle_network_init success\n");
}
