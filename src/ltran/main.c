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

#include <pthread.h>
#include <execinfo.h>
#include <sys/stat.h>
#include <signal.h>
#include <syslog.h>
#include <sys/types.h>
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_version.h>

#include "common/dpdk_common.h"
#include "ltran_log.h"
#include "ltran_param.h"
#include "ltran_stat.h"
#include "ltran_stack.h"
#include "ltran_ethdev.h"
#include "ltran_instance.h"
#include "ltran_monitor.h"
#include "ltran_tcp_conn.h"
#include "ltran_tcp_sock.h"
#include "ltran_forward.h"

static int32_t g_critical_signal[] = { SIGTERM, SIGINT, SIGSEGV, SIGBUS, SIGILL };
#define CRITICAL_SIGNAL_COUNT (sizeof(g_critical_signal) / sizeof(g_critical_signal[0]))

static void print_stack(void)
{
    void *array[64];
    const int32_t size = 64;
    char **stacktrace = NULL;
    int32_t stack_num = backtrace(array, size);
    int32_t i;

    stacktrace = (char**)backtrace_symbols(array, stack_num);
    if (stacktrace == NULL) {
        perror("backtrace_symbols.");
        return;
    }

    for (i = 0; i < stack_num; i++) {
        LTRAN_ERR("%s.\n", stacktrace[i]);
    }
    free(stacktrace);
}

static void sig_default_handler(int32_t sig)
{
    LTRAN_ERR("ltran dumped, caught signal: %d.\n", sig);
    print_stack();
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
    dpdk_kni_release();
#endif
    int ret = 0;
    ret = unlink(get_ltran_config()->unix_socket_filename);
    if (ret) {
        LTRAN_WARN("unlink %s ERROR. errn: %d. ret=%d\n", get_ltran_config()->unix_socket_filename, errno, ret);
    }
    ret = unlink(get_ltran_config()->dfx_socket_filename);
    if (ret) {
	    LTRAN_WARN("unlink %s ERROR. errn: %d. ret=%d\n", get_ltran_config()->dfx_socket_filename, errno, ret);
    }
    kill(getpid(), sig);
}

static void signal_init(void)
{
    uint32_t i;
    struct sigaction act;

    sigemptyset(&act.sa_mask);
    act.sa_handler = sig_default_handler;
    act.sa_flags = (int32_t)(SA_NODEFER | SA_RESETHAND);
    for (i = 0; i < CRITICAL_SIGNAL_COUNT; i++) {
        sigaction(g_critical_signal[i], &act, NULL);
    }
}

static int32_t ltran_ignore_sigpipe(void)
{
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        LTRAN_ERR("signal error, errno:%d.", errno);
        return GAZELLE_ERR;
    }
    return GAZELLE_OK;
}

/**
 * Main init function for the multi-process server app,
 * calls subfunctions to do each stage of the initialisation.
 */
static int32_t ltran_core_init(int32_t argc, char *argv[])
{
    int32_t ret;

    openlog("ltran", LOG_CONS | LOG_PID, LOG_USER);
    ret = ltran_config_init(argc, argv);
    if (ret == GAZELLE_ERR) {
        syslog(LOG_ERR, "ltran config init failed. ret=%d.\n", ret);
        closelog();
        return ret;
    } else if (ret == GAZELLE_QUIT) {
        closelog();
        return GAZELLE_QUIT;
    }

    ret = ltran_ethdev_init();
    if (ret != GAZELLE_OK) {
        syslog(LOG_ERR, "ltran ethdev init failed. ret=%d.\n", ret);
        closelog();
        return ret;
    }

    struct gazelle_instance_mgr *mgr = gazelle_instance_mgr_create();
    if (mgr == NULL) {
        syslog(LOG_ERR, "create gazelle_instance_mgr failed\n");
        closelog();
        return -1;
    }
    set_instance_mgr(mgr);
    gazelle_set_stack_htable(gazelle_stack_htable_create(GAZELLE_MAX_STACK_NUM));
    gazelle_set_tcp_conn_htable(gazelle_tcp_conn_htable_create(GAZELLE_MAX_CONN_NUM));
    gazelle_set_tcp_sock_htable(gazelle_tcp_sock_htable_create(GAZELLE_MAX_TCP_SOCK_NUM));

    signal_init();
    /* to prevent crash of ltran, just ignore SIGPIPE when socket is closed */
    ret = ltran_ignore_sigpipe();

    closelog();
    return ret;
}

static void ltran_core_destroy(void)
{
    gazelle_instance_mgr_destroy();
    gazelle_stack_htable_destroy();
    gazelle_tcp_conn_htable_destroy();
    gazelle_tcp_sock_htable_destroy();
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
    dpdk_kni_release();
#endif
}

static void wait_thread_finish(pthread_t ctrl_thread, uint32_t next_core)
{
    int32_t ret = pthread_join(ctrl_thread, NULL);
    if (ret != 0) {
        LTRAN_ERR("pthread_join for ctrl_thead ret=%d.\n", ret);
    }

    /* wait downstream_forward */
    if (next_core < RTE_MAX_LCORE) {
        ret = rte_eal_wait_lcore(next_core);
        if (ret < 0) {
            LTRAN_ERR("rte_eal_wait_lcore for downstream_forward ret=%d next_core=%u.\n", ret, next_core);
        }
    }
}

int32_t main(int32_t argc, char *argv[])
{
    pthread_t ctrl_thread;
    uint32_t next_core;
    uint16_t index;

    syslog(LOG_INFO, "start ltran.");

    /* ltran create file permissions limit for security. 077:only owner have permissions */
    (void)umask(077);

    /* initialise the system */
    int32_t ret = ltran_core_init(argc, argv);
    if (ret != GAZELLE_OK) {
        ltran_core_destroy();
        return (ret == GAZELLE_QUIT) ? 0 : ret;
    }
    LTRAN_INFO("Finished Process ltran_core_init\n");

    if (pthread_create(&ctrl_thread, NULL, ctrl_thread_fn, NULL) != 0) {
        ltran_core_destroy();
        LTRAN_ERR("pthread_create failed for ctrl thread.\n");
        return GAZELLE_ERR;
    }

    LTRAN_INFO("Finished Process ctrl_thread_fn\n");
    do {
        /* create one thread for bond port 0 send packet */
        next_core = rte_get_next_lcore(-1, 1, 0);
        if (next_core == RTE_MAX_LCORE) {
            LTRAN_ERR("there is no more core!\n");
            ret = GAZELLE_ERR;
            break;
        }

        index = 0;
        ret = rte_eal_remote_launch((lcore_function_t *)downstream_forward, &index, next_core);
        if (ret != 0) {
            LTRAN_ERR("rte_eal_remote_launch  downstream_forwarding_by_port error ret:%d.\n", ret);
            break;
        }

        /* create multi thread to receive and send packet for multi bond port */
        LTRAN_INFO("Running Process forward\n");
        /* main thread is for port 0 receive packet */
        index = 0;
        upstream_forward((const void *)&index);
    } while (0);

    set_ltran_stop_flag(GAZELLE_TRUE);
    wait_thread_finish(ctrl_thread, next_core);

    ltran_core_destroy();
    LTRAN_INFO("all done, all quit.\n");

    return ret;
}
