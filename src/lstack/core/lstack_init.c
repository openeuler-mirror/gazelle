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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <semaphore.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <securec.h>
#include <numa.h>
#include <pthread.h>
#include <unistd.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/resource.h>

#include <rte_pdump.h>

#include <lwip/init.h>
#include <lwip/lwipgz_sock.h>
#include <lwip/lwipopts.h>
#include <lwip/lwipgz_posix_api.h>

#include "lstack_log.h"
#include "lstack_cfg.h"
#include "lstack_control_plane.h"
#include "lstack_ethdev.h"
#include "lstack_dpdk.h"
#include "lstack_stack_stat.h"
#include "common/dpdk_common.h"
#include "lstack_unistd.h"
#include "common/gazelle_base_func.h"
#include "lstack_protocol_stack.h"
#include "lstack_preload.h"
#include "lstack_wrap.h"
#include "lstack_flow.h"
#include "lstack_interrupt.h"

static void check_process_start(void)
{
    if (get_global_cfg_params()->is_primary) {
        return;
    }

    while (!fopen(GAZELLE_PRIMARY_START_PATH, "r")) {
        LSTACK_LOG(INFO, LSTACK, "please make sure the primary process start already!\n");
        sleep(1);
    }
}

static int32_t set_process_start_flag(void)
{
    if (!get_global_cfg_params()->is_primary) {
        return 0;
    }

    FILE *fp = NULL;
    fp = fopen(GAZELLE_PRIMARY_START_PATH, "w");
    if (fp == NULL) {
        LSTACK_PRE_LOG(LSTACK_ERR, "set primary proceaa start flag failed!\n");
        return -1;
    }
    (void)fclose(fp);
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

void gazelle_exit(void)
{
    wrap_api_exit();
    stack_group_exit();
}

void dpdk_exit(void)
{
    if (!use_ltran()) {
        int ret = rte_pdump_uninit();
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "rte_pdump_uninit failed\n");
        }

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
        dpdk_kni_release();
#endif
    }
}

__attribute__((destructor)) void gazelle_network_exit(void)
{
    if (posix_api != NULL && !posix_api->use_kernel) {
        lwip_exit();
        gazelle_exit();
        dpdk_exit();
    }
}

static void create_control_thread(void)
{
    int32_t ret;

    pthread_t tid;
    if (use_ltran()) {
        /* The function call here should be in strict order. */
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
        dpdk_skip_nic_init();
#endif
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

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
static void set_kni_ip_mac()
{
    struct cfg_params *cfg = get_global_cfg_params();

    int32_t fd = posix_api->socket_fn(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct ifreq set_ifr = {0};
    struct sockaddr_in *sin = (struct sockaddr_in *)&set_ifr.ifr_addr;

    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = cfg->host_addr.addr;
    if (strcpy_s(set_ifr.ifr_name, sizeof(set_ifr.ifr_name), GAZELLE_KNI_NAME) != 0) {
        LSTACK_LOG(ERR, LSTACK, "strcpy_s fail \n");
    }

    if (posix_api->ioctl_fn(fd, SIOCSIFADDR, &set_ifr) < 0) {
        LSTACK_LOG(ERR, LSTACK, "set kni ip=%u fail\n", cfg->host_addr.addr);
    }

    sin->sin_addr.s_addr = cfg->netmask.addr;
    if (posix_api->ioctl_fn(fd, SIOCSIFNETMASK, &set_ifr) < 0) {
        LSTACK_LOG(ERR, LSTACK, "set kni netmask=%u fail\n", cfg->netmask.addr);
    }

    set_ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    /* 6: mac addr len */
    for (int i = 0; i < 6; i++) {
        set_ifr.ifr_hwaddr.sa_data[i] = cfg->mac_addr[i];
    }

    if (posix_api->ioctl_fn(fd, SIOCSIFHWADDR, &set_ifr) < 0) {
        LSTACK_LOG(ERR, LSTACK, "set kni macaddr=%hhx:%hhx:%hhx:%hhx:%hhx:%hhx fail\n",
            cfg->mac_addr[0], cfg->mac_addr[1],
            cfg->mac_addr[2], cfg->mac_addr[3],
            cfg->mac_addr[4], cfg->mac_addr[5]);
    }

    if (posix_api->ioctl_fn(fd, SIOCGIFFLAGS, &set_ifr) < 0) {
        LSTACK_LOG(ERR, LSTACK, "get kni state fail\n");
    }

    set_ifr.ifr_flags |= (IFF_RUNNING | IFF_UP);
    if (posix_api->ioctl_fn(fd, SIOCSIFFLAGS, &set_ifr) < 0) {
        LSTACK_LOG(ERR, LSTACK, "set kni state fail\n");
    }

    posix_api->close_fn(fd);
}
#endif

static int set_rlimit(void)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
        return -1;
    }
    return 0;
}

__attribute__((constructor)) void gazelle_network_init(void)
{
    /* Init POSXI API and prelog */
    lstack_prelog_init("LSTACK");
    if (posix_api_init() != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "posix_api_init failed\n");
        LSTACK_EXIT(1, "failed\n");
    }

    /* Init LD_PRELOAD */
    if (preload_info_init() < 0) {
        return;
    }

    /* to remove UDP umem size limit */
    if (set_rlimit() != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "set_rlimit failed\n");
        LSTACK_EXIT(1, "set_rlimit failed\n");
    }

    /* Read configure from lstack.cfg */
    if (cfg_init() != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "cfg_init failed\n");
        LSTACK_EXIT(1, "cfg_init failed\n");
    }
    LSTACK_PRE_LOG(LSTACK_INFO, "cfg_init success\n");

    wrap_api_init();

    /* check primary process start */
    check_process_start();

    /* check conflict */
    if (check_process_conflict() < 0) {
        LSTACK_PRE_LOG(LSTACK_INFO, "Have another same primary process. WARNING: Posix API will use kernel mode!\n");
        return;
    }

    /* check lstack num */
    if (check_params_from_primary() < 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "lstack num error, not same to primary process!\n");
        LSTACK_EXIT(1, "lstack num error, not same to primary process!\n");
    }

    /* save initial affinity */
    if (!get_global_cfg_params()->main_thread_affinity) {
        if (thread_affinity_default() < 0) {
            LSTACK_PRE_LOG(LSTACK_ERR, "pthread_getaffinity_np failed\n");
            LSTACK_EXIT(1, "pthread_getaffinity_np failed\n");
        }
    }

    /* register core sig handler func to dumped stack */
    if (lstack_signal_init() != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "signal init failed, errno %d\n", errno);
        LSTACK_EXIT(1, "signal init failed, errno %d\n", errno);
    }

    /* Init control plane and dpdk init */
    create_control_thread();
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
    dpdk_restore_pci();
#endif

    /* cancel the core binding from DPDK initialization */
    if (!get_global_cfg_params()->main_thread_affinity) {
        if (thread_affinity_default() < 0) {
            LSTACK_EXIT(1, "pthread_setaffinity_np failed\n");
        }
    }

    lstack_log_level_init();
    lstack_prelog_uninit();

    if (stack_group_init() != 0) {
        LSTACK_EXIT(1, "stack_group_init failed\n");
    }

    if (intr_init() < 0) {
        LSTACK_EXIT(1, "intr init failed\n");
    }

    if (!use_ltran()) {
        if (init_dpdk_ethdev() != 0) {
            LSTACK_EXIT(1, "init_dpdk_ethdev failed\n");
        }
    }

    if (!get_global_cfg_params()->stack_mode_rtc) {
        if (stack_setup_thread() != 0) {
            gazelle_exit();
            LSTACK_EXIT(1, "stack_setup_thread failed\n");
        }
    }

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
    if (get_global_cfg_params()->kni_switch) {
        set_kni_ip_mac();
    }
#endif

    if (set_process_start_flag() != 0) {
        gazelle_exit();
        LSTACK_EXIT(1, "set_process_start_flag failed\n");
    }

    posix_api->use_kernel = 0;
    LSTACK_LOG(INFO, LSTACK, "gazelle_network_init success\n");
    rte_smp_mb();
}
