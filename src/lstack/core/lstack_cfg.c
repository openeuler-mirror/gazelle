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
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <securec.h>
#include <string.h>
#include <libconfig.h>
#include <limits.h>
#include <unistd.h>
#include <sched.h>

#include <lwip/lwipsock.h>
#include <lwip/posix_api.h>
#include <lwip/inet.h>

#include "gazelle_reg_msg.h"
#include "lstack_log.h"
#include "gazelle_base_func.h"
#include "lstack_protocol_stack.h"
#include "lstack_cfg.h"

#define DEFAULT_CONF_FILE "/etc/gazelle/lstack.conf"
#define LSTACK_CONF_ENV   "LSTACK_CONF_PATH"
#define NUMA_CPULIST_PATH "/sys/devices/system/node/node%u/cpulist"
#define DEV_MAC_LEN 17
#define CPUS_MAX_NUM 256

static struct cfg_params g_config_params;

static config_t g_config;

static int32_t parse_host_addr(void);
static int32_t parse_low_power_mode(void);
static int32_t parse_stack_cpu_number(void);
static int32_t parse_use_ltran(void);
static int32_t parse_mask_addr(void);
static int32_t parse_devices(void);
static int32_t parse_dpdk_args(void);
static int32_t parse_gateway_addr(void);
static int32_t parse_kni_switch(void);
static int32_t parse_listen_shadow(void);
static int32_t parse_app_bind_numa(void);
static int32_t parse_main_thread_affinity(void);
static int32_t parse_unix_prefix(void);
static int32_t parse_read_connect_number(void);
static int32_t parse_rpc_number(void);
static int32_t parse_nic_read_number(void);
static int32_t parse_tcp_conn_count(void);
static int32_t parse_mbuf_count_per_conn(void);
static int32_t parse_send_ring_size(void);
static int32_t parse_expand_send_ring(void);
static int32_t parse_num_process(void);
static int32_t parse_process_numa(void);
static int32_t parse_process_index(void);
static int32_t parse_seperate_sendrecv_args(void);
static int32_t parse_tuple_filter(void);
static int32_t parse_use_bond4(void);
static int32_t parse_bond4_slave_mac(void);
static int32_t parse_use_sockmap(void);

#define PARSE_ARG(_arg, _arg_string, _default_val, _min_val, _max_val, _ret) \
    do { \
        const config_setting_t *_config_arg = NULL; \
        _config_arg = config_lookup(&g_config, _arg_string); \
        if (_config_arg == NULL) { \
            (_arg) = (_default_val); \
            (_ret) = 0; \
            break; \
        } \
        int32_t _val = config_setting_get_int(_config_arg); \
        if (_val < (_min_val) || _val > (_max_val)) { \
            LSTACK_PRE_LOG(LSTACK_ERR, "cfg %s %d invaild, range is [%d, %d].\n", \
                (_arg_string), _val, (_min_val), (_max_val)); \
            (_ret) = -EINVAL; \
            break; \
        } \
        (_arg) = _val; \
        (_ret) = 0; \
    } while (0)

struct config_vector_t {
    const char *name;
    int32_t (*f)(void);
};

static struct config_vector_t g_config_tbl[] = {
    { "host_addr",    parse_host_addr },
    { "gateway_addr", parse_gateway_addr },
    { "mask_addr",    parse_mask_addr },
    { "use_ltran",    parse_use_ltran },
    { "devices",      parse_devices },
    { "dpdk_args",    parse_dpdk_args },
    { "seperate_send_recv",    parse_seperate_sendrecv_args },
    { "num_cpus",     parse_stack_cpu_number },
    { "low_power_mode", parse_low_power_mode },
    { "kni_switch",     parse_kni_switch },
    { "listen_shadow",  parse_listen_shadow },
    { "app_bind_numa",  parse_app_bind_numa },
    { "main_thread_affinity",  parse_main_thread_affinity },
    { "unix_prefix",    parse_unix_prefix },
    { "tcp_conn_count", parse_tcp_conn_count },
    { "mbuf_count_per_conn", parse_mbuf_count_per_conn },
    { "read_connect_number", parse_read_connect_number },
    { "rpc_number", parse_rpc_number },
    { "nic_read_number", parse_nic_read_number },
    { "send_ring_size", parse_send_ring_size },
    { "expand_send_ring", parse_expand_send_ring },
    { "num_process",  parse_num_process },
    { "process_numa", parse_process_numa },
    { "process_idx", parse_process_index },
    { "tuple_filter", parse_tuple_filter },
    { "use_bond4", parse_use_bond4 },
    { "bond4_slave_mac", parse_bond4_slave_mac },
    { "use_sockmap", parse_use_sockmap },
    { NULL,           NULL }
};

struct cfg_params *get_global_cfg_params(void)
{
    return &g_config_params;
}

static int32_t str_to_eth_addr(const char *src, unsigned char *dst)
{
    if (strlen(src) > DEV_MAC_LEN) {
        return -EINVAL;
    }

    uint8_t mac_addr[ETHER_ADDR_LEN];

    int32_t ret = sscanf_s(src, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &mac_addr[0], &mac_addr[1], &mac_addr[2], /* 0、1、2 mac byte index */
        &mac_addr[3], &mac_addr[4], &mac_addr[5]); /* 3、4、5 byte index */
    if (ret != ETHER_ADDR_LEN) {
        return -EINVAL;
    }
    ret = memcpy_s(dst, ETHER_ADDR_LEN, mac_addr, ETHER_ADDR_LEN);
    if (ret != EOK) {
        return -EINVAL;
    }
    return 0;
}

static int32_t parse_gateway_addr(void)
{
    char *value;
    bool ok;

    ok = config_lookup_string(&g_config, "gateway_addr", (const char **)&value);
    if (!ok) {
        return -EINVAL;
    }
    g_config_params.gateway_addr.addr = inet_addr(value);
    if (g_config_params.gateway_addr.addr == INADDR_NONE) {
        return -EINVAL;
    }
    return 0;
}

static int32_t parse_mask_addr(void)
{
    char *value = NULL;
    uint32_t mask;
    bool ok;

    ok = config_lookup_string(&g_config, "mask_addr", (const char **)&value);
    if (!ok) {
        return -EINVAL;
    }
    g_config_params.netmask.addr = inet_addr(value);
    if (g_config_params.netmask.addr == INADDR_NONE) {
        return -EINVAL;
    }
    mask = ntohl(g_config_params.netmask.addr);
    mask = ~mask;
    if ((mask & (mask + 1)) != 0) {
        return -EINVAL;
    }
    return 0;
}

static int32_t parse_host_addr(void)
{
    char *value = NULL;
    bool ok;

    ok = config_lookup_string(&g_config, "host_addr", (const char **)&value);
    if (!ok) {
        return -EINVAL;
    }

    g_config_params.host_addr.addr = inet_addr(value);
    if (g_config_params.host_addr.addr == INADDR_NONE) {
        return -EINVAL;
    }

    return 0;
}

int32_t match_host_addr(uint32_t addr)
{
    /* network byte order */
    if (addr == g_config_params.host_addr.addr) {
        return 1;
    }
    return 0;
}

static int32_t parse_devices(void)
{
    int32_t ret;
    const char *dev = NULL;
    const config_setting_t *devs = NULL;

    devs = config_lookup(&g_config, "devices");
    if (devs == NULL) {
        return -EINVAL;
    }
    dev = config_setting_get_string(devs);
    if (dev == NULL) {
        return 0;
    }

    /* add dev */
    ret = str_to_eth_addr(dev, g_config_params.mac_addr);
    if (ret != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "cfg: invalid device name %s ret=%d.\n", dev, ret);
    }
    return ret;
}

static int32_t get_param_idx(int32_t argc, char **argv, const char *param)
{
    int32_t idx;

    if ((argc <= 0) || (argv == NULL) || (param == NULL)) {
        return -EINVAL;
    }

    for (idx = 0; idx < argc; ++idx) {
        if (strncmp(argv[idx], param, strlen(param)) == 0) {
            return idx;
        }
    }
    return -1;
}

static bool have_corelist_arg(int32_t argc, char **argv)
{
    for (uint32_t i  = 0; i < argc; i++) {
        if (strncmp(argv[i], OPT_BIND_CORELIST, strlen(OPT_BIND_CORELIST)) == 0) {
            return true;
        }

        if (strncmp(argv[i], "--lcores", strlen("--lcores")) == 0) {
            return true;
        }
        
        if (strncmp(argv[i], "-c", strlen("-c")) == 0) {
            return true;
        }

        if (strncmp(argv[i], "-s", strlen("-s")) == 0) {
            return true;
        }

        if (strncmp(argv[i], "-S", strlen("-S")) == 0) {
            return true;
        }
    }

    return false;
}

static int32_t parse_stack_cpu_number(void)
{
    const config_setting_t *num_cpus = NULL;
    const char *args = NULL;

    if (!g_config_params.seperate_send_recv) {
        num_cpus = config_lookup(&g_config, "num_cpus");
        if (num_cpus == NULL) {
            return -EINVAL;
        }

        args = config_setting_get_string(num_cpus);
        if (args == NULL) {
            return -EINVAL;
        }

        if (!have_corelist_arg(g_config_params.dpdk_argc, g_config_params.dpdk_argv)) {
            int32_t idx = get_param_idx(g_config_params.dpdk_argc, g_config_params.dpdk_argv, OPT_BIND_CORELIST);
            if (idx < 0) {
                g_config_params.dpdk_argv[g_config_params.dpdk_argc] = strdup(OPT_BIND_CORELIST);
                g_config_params.dpdk_argc++;

                g_config_params.dpdk_argv[g_config_params.dpdk_argc] = strdup(args);
                g_config_params.dpdk_argc++;
            }
        }

        char *tmp_arg = strdup(args);
        int32_t cnt = separate_str_to_array(tmp_arg, g_config_params.cpus, CFG_MAX_CPUS, CFG_MAX_CPUS);
        free(tmp_arg);
        if (cnt <= 0 || cnt > CFG_MAX_CPUS) {
            return -EINVAL;
        }

        g_config_params.num_cpu = cnt;
        g_config_params.num_queue = (uint16_t)cnt;
        g_config_params.tot_queue_num = g_config_params.num_queue;
    } else {
        // send_num_cpus
        num_cpus = config_lookup(&g_config, "send_num_cpus");
        if (num_cpus == NULL) {
            return -EINVAL;
        }

        args = config_setting_get_string(num_cpus);
        if (args == NULL) {
            return -EINVAL;
        }

        if (!have_corelist_arg(g_config_params.dpdk_argc, g_config_params.dpdk_argv)) {
            int32_t idx = get_param_idx(g_config_params.dpdk_argc, g_config_params.dpdk_argv, OPT_BIND_CORELIST);
            if (idx < 0) {
                g_config_params.dpdk_argv[g_config_params.dpdk_argc] = strdup(OPT_BIND_CORELIST);
                g_config_params.dpdk_argc++;

                g_config_params.dpdk_argv[g_config_params.dpdk_argc] = strdup(args);
                g_config_params.dpdk_argc++;
            }
        }

        char *tmp_arg_send = strdup(args);
        int32_t send_cpu_cnt = separate_str_to_array(tmp_arg_send, g_config_params.send_cpus,
            CFG_MAX_CPUS, CFG_MAX_CPUS);
        free(tmp_arg_send);

        // recv_num_cpus
        num_cpus = config_lookup(&g_config, "recv_num_cpus");
        if (num_cpus == NULL) {
            return -EINVAL;
        }

        args = config_setting_get_string(num_cpus);
        if (args == NULL) {
            return -EINVAL;
        }

        if (!have_corelist_arg(g_config_params.dpdk_argc, g_config_params.dpdk_argv)) {
            int32_t idx = get_param_idx(g_config_params.dpdk_argc, g_config_params.dpdk_argv, OPT_BIND_CORELIST);
            if (idx < 0) {
                g_config_params.dpdk_argv[g_config_params.dpdk_argc] = strdup(OPT_BIND_CORELIST);
                g_config_params.dpdk_argc++;

                g_config_params.dpdk_argv[g_config_params.dpdk_argc] = strdup(args);
                g_config_params.dpdk_argc++;
            }
        }

        char *tmp_arg_recv = strdup(args);
        int32_t recv_cpu_cnt = separate_str_to_array(tmp_arg_recv, g_config_params.recv_cpus,
            CFG_MAX_CPUS, CFG_MAX_CPUS);
        free(tmp_arg_recv);

        if (send_cpu_cnt <= 0 || send_cpu_cnt > CFG_MAX_CPUS / 2 || send_cpu_cnt != recv_cpu_cnt) {
            return -EINVAL;
        }

        g_config_params.num_cpu = send_cpu_cnt;
        g_config_params.num_queue = (uint16_t)send_cpu_cnt * 2;
        g_config_params.tot_queue_num = g_config_params.num_queue;
    }

    return 0;
}

static int32_t numa_to_cpusnum(unsigned socket_id, uint32_t *cpulist, int32_t num)
{
    char path[PATH_MAX] = {0};
    char strbuf[PATH_MAX] = {0};

    int32_t ret = snprintf_s(path, sizeof(path), PATH_MAX - 1, NUMA_CPULIST_PATH, socket_id);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "snprintf numa_cpulist failed\n");
        return -1;
    }

    int32_t fd = open(path, O_RDONLY);
    if (fd < 0) {
        LSTACK_LOG(ERR, LSTACK, "open %s failed\n", path);
        return -1;
    }

    ret = read(fd, strbuf, sizeof(strbuf));
    close(fd);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "read %s failed\n", path);
        return -1;
    }

    int32_t count = separate_str_to_array(strbuf, cpulist, num, CFG_MAX_CPUS);
    return count;
}

static int32_t stack_idle_cpuset(struct protocol_stack *stack, cpu_set_t *exclude)
{
    uint32_t cpulist[CPUS_MAX_NUM];

    int32_t cpunum = numa_to_cpusnum(stack->socket_id, cpulist, CPUS_MAX_NUM);
    if (cpunum <= 0) {
        LSTACK_LOG(ERR, LSTACK, "numa_to_cpusnum failed\n");
        return -1;
    }

    CPU_ZERO(&stack->idle_cpuset);
    for (int32_t i = 0; i < cpunum; i++) {
        /* skip stack cpu */
        if (CPU_ISSET(cpulist[i], exclude)) {
            continue;
        }

        CPU_SET(cpulist[i], &stack->idle_cpuset);
    }

    return 0;
}

int32_t init_stack_numa_cpuset(struct protocol_stack *stack)
{
    int32_t ret;
    struct cfg_params *cfg = get_global_cfg_params();

    cpu_set_t stack_cpuset;
    CPU_ZERO(&stack_cpuset);
    for (int32_t idx = 0; idx < cfg->num_cpu; ++idx) {
        if (!cfg->seperate_send_recv) {
            CPU_SET(cfg->cpus[idx], &stack_cpuset);
        } else {
            CPU_SET(cfg->send_cpus[idx], &stack_cpuset);
            CPU_SET(cfg->recv_cpus[idx], &stack_cpuset);
        }
    }

    ret = stack_idle_cpuset(stack, &stack_cpuset);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "thread_get_cpuset stack(%u) failed\n", stack->tid);
        return -1;
    }

    return 0;
}

static int32_t gazelle_parse_base_virtaddr(const char *arg, uintptr_t *base_vaddr)
{
    uint64_t viraddr;
    char *end = NULL;

    errno = 0;
    viraddr = strtoull(arg, &end, BASE_HEX_SCALE);

    /* check for errors */
    if ((errno != 0) || (arg[0] == '\0') || (end == NULL) || (*end != '\0')) {
        return -EINVAL;
    }

    *base_vaddr = (uintptr_t)viraddr;
    return 0;
}

static int32_t gazelle_parse_socket_mem(const char *arg, struct secondary_attach_arg *sec_attach_arg)
{
    size_t mem_size = 0;
    char socket_mem[PATH_MAX];

    errno = 0;

    if ((arg == NULL) || (sec_attach_arg == NULL)) {
        return -1;
    }

    if (sprintf_s(socket_mem, sizeof(socket_mem), "%s", arg) < 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "cfg: socket_mem invalid.\n");
        return -1;
    }

    int32_t count = separate_str_to_array(socket_mem, sec_attach_arg->socket_per_size,
                                          GAZELLE_MAX_NUMA_NODES, INT32_MAX);
    if (count < 0) {
        return -1;
    }

    for (uint32_t i = 0; i < count; i++) {
        mem_size += sec_attach_arg->socket_per_size[i];
    }
    mem_size *= 1024LL;
    mem_size *= 1024LL;
    if (mem_size > (UINT64_MAX / 1024LL / 1024LL) || count > UINT8_MAX) {
        return -1;
    }
    sec_attach_arg->socket_num = count;
    sec_attach_arg->socket_size = mem_size;

    return 0;
}

int32_t parse_param(const char* param)
{
    if (g_config_params.dpdk_argc >= GAZELLE_MAX_REG_ARGS) {
        return -1;
    }

    g_config_params.dpdk_argv[g_config_params.dpdk_argc] = strdup(param);
    if (g_config_params.dpdk_argv[g_config_params.dpdk_argc] == NULL) {
        return -1;
    }
    g_config_params.dpdk_argc++;
    return 0;
}

static void print_dpdk_param(void)
{
    int32_t ret;
    int32_t skip = 0;

    printf("pid(%d) file_prefix(%s) args: ", getpid(), g_config_params.sec_attach_arg.file_prefix);
    for (int32_t i = 0; i < g_config_params.dpdk_argc; ++i) {
        /* BASE_VIRTADDR is sensitive information */
        ret = strncmp(g_config_params.dpdk_argv[i], OPT_BASE_VIRTADDR, strlen(OPT_BASE_VIRTADDR));
        if (ret == 0) {
            skip = 1;
            continue;
        }
        if (skip != 0) {
            skip = 0;
            continue;
        }

        printf("%s ", g_config_params.dpdk_argv[i]);
    }
    printf("\n");
}

static int32_t turn_args_to_config(int32_t argc, char **argv)
{
    int32_t ret;
    int32_t idx;

    if ((argc <= 0) || (argv == NULL)) {
        return -EINVAL;
    }

    // OPT_FILE_PREFIX
    idx = get_param_idx(argc, argv, OPT_FILE_PREFIX);
    if (idx < 0) {
        ret = sprintf_s(g_config_params.sec_attach_arg.file_prefix, sizeof(g_config_params.sec_attach_arg.file_prefix),
                        "gazelle_%d", getpid());
        if (ret < 0) {
            return -1;
        }
    } else {
        if (idx + 1 >= g_config_params.dpdk_argc) {
            return -1;
        }
        ret = sprintf_s(g_config_params.sec_attach_arg.file_prefix, sizeof(g_config_params.sec_attach_arg.file_prefix),
                        "%s", g_config_params.dpdk_argv[idx + 1]);
        if (ret < 0) {
            return -1;
        }
    }

    // OPT_SOCKET_MEM
    idx = get_param_idx(argc, argv, OPT_SOCKET_MEM);
    if ((idx < 0) || (idx + 1 >= argc)) {
        if (use_ltran()) {
            LSTACK_LOG(ERR, LSTACK, "Cannot find param %s\n", OPT_SOCKET_MEM);
            return idx;
        }
    } else {
        ret = gazelle_parse_socket_mem(argv[idx + 1], &g_config_params.sec_attach_arg);
        if (ret < 0) {
            return ret;
        }
    }

    // OPT_BASE_VIRTADDR
    idx = get_param_idx(argc, argv, OPT_BASE_VIRTADDR);
    if ((idx < 0) || (idx + 1 >= argc)) {
        g_config_params.sec_attach_arg.base_virtaddr = 0;
    } else {
        ret = gazelle_parse_base_virtaddr(argv[idx + 1], &g_config_params.sec_attach_arg.base_virtaddr);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

int32_t gazelle_copy_param(const char *param, bool is_double,
    int32_t *argc, char argv[][PATH_MAX])
{
    int32_t cnt = *argc;
    int32_t wanted_id;
    int32_t ret;

    wanted_id = get_param_idx(g_config_params.dpdk_argc, g_config_params.dpdk_argv, param);
    if (wanted_id < 0) {
        return wanted_id;
    }

    if (cnt >= GAZELLE_MAX_REG_ARGS) {
        LSTACK_LOG(ERR, LSTACK, "too many params\n");
        return -EINVAL;
    }

    ret = strcpy_s(argv[cnt++], PATH_MAX, g_config_params.dpdk_argv[wanted_id]);
    if (ret != EOK) {
        return ret;
    }
    if (is_double) {
        if ((wanted_id + 1 >= g_config_params.dpdk_argc) || (cnt >= GAZELLE_MAX_REG_ARGS)) {
            return -EINVAL;
        }
        ret = strcpy_s(argv[cnt++], PATH_MAX, g_config_params.dpdk_argv[wanted_id + 1]);
        if (ret != EOK) {
            return ret;
        }
    }

    *argc = cnt;
    return 0;
}

int32_t gazelle_param_init(int32_t *argc, char **argv)
{
    int32_t ret;
    int32_t wanted_id;
    char param_buf[PATH_MAX];

    if (argv == NULL) {
        return -1;
    }

    wanted_id = get_param_idx(g_config_params.dpdk_argc, g_config_params.dpdk_argv, OPT_FILE_PREFIX);
    if (wanted_id < 0) {
        if (parse_param(OPT_FILE_PREFIX) < 0 || parse_param(g_config_params.sec_attach_arg.file_prefix) < 0) {
            return -1;
        }
    }

    ret = sprintf_s(param_buf, sizeof(param_buf), "%lx", (uint64_t)g_config_params.sec_attach_arg.base_virtaddr);
    if (ret < 0) {
        return -1;
    }

    wanted_id = get_param_idx(g_config_params.dpdk_argc, g_config_params.dpdk_argv, OPT_BASE_VIRTADDR);
    if (wanted_id < 0) {
        if (parse_param(OPT_BASE_VIRTADDR) < 0 || parse_param(param_buf) < 0) {
            return -1;
        }
    } else {
        if (wanted_id + 1 >= g_config_params.dpdk_argc)
            return -1;
        GAZELLE_FREE(g_config_params.dpdk_argv[wanted_id + 1]);
        g_config_params.dpdk_argv[wanted_id + 1] = strdup(param_buf);
        if (g_config_params.dpdk_argv[wanted_id + 1] == NULL)
            return -1;
    }

    print_dpdk_param();
    for (int32_t i = 0; i < g_config_params.dpdk_argc; ++i) {
        argv[i] = g_config_params.dpdk_argv[i];
    }
    *argc = g_config_params.dpdk_argc;

    return 0;
}

static int32_t parse_dpdk_args(void)
{
    int32_t i;
    int32_t start_index;
    char *p = NULL;
    const char *arg = NULL;
    const config_setting_t *args = NULL;

    args = config_lookup(&g_config, "dpdk_args");
    if (args == NULL)
        return -EINVAL;

    g_config_params.dpdk_argc = config_setting_length(args);
    if ((g_config_params.dpdk_argc <= 0) || (g_config_params.dpdk_argc >= GAZELLE_MAX_REG_ARGS))
        return -EINVAL;

    /* Reserved for some required parameters, see gazelle_param_init() */
    g_config_params.dpdk_argv = calloc(GAZELLE_MAX_REG_ARGS, sizeof(char *));
    if (!g_config_params.dpdk_argv)
        return -EINVAL;

    (void)fprintf(stderr, "dpdk argv: ");

    g_config_params.dpdk_argv[0] = strdup("lstack");
    if (!g_config_params.dpdk_argv[0]) {
        goto free_dpdk_args;
    }
    start_index = 1;

    for (i = 0; i < g_config_params.dpdk_argc; i++) {
        arg = config_setting_get_string_elem(args, i);
        if (arg == NULL)
            continue;
        p = strdup(arg);
        if (p == NULL) {
            goto free_dpdk_args;
        }
        g_config_params.dpdk_argv[start_index + i] = p;

        const char *primary = "primary";
        if (strcmp(p, primary) == 0) {
            struct cfg_params *global_params = get_global_cfg_params();
            global_params->is_primary = 1;
        }

        (void)fprintf(stderr, "%s ", g_config_params.dpdk_argv[start_index + i]);
    }
    (void)fprintf(stderr, "\n");

    g_config_params.dpdk_argc++;
    if (turn_args_to_config(g_config_params.dpdk_argc, g_config_params.dpdk_argv))
        goto free_dpdk_args;

    return 0;

free_dpdk_args:
    for (i = 0; i < g_config_params.dpdk_argc; i++) {
        GAZELLE_FREE(g_config_params.dpdk_argv[i]);
    }
    GAZELLE_FREE(g_config_params.dpdk_argv);
    return -EINVAL;
}

static int32_t parse_low_power_mode(void)
{
    int32_t ret;
    /* Set parameter default value */
    g_config_params.lpm_detect_ms = LSTACK_LPM_DETECT_MS;
    g_config_params.lpm_rx_pkts = LSTACK_LPM_RX_PKTS;
    g_config_params.lpm_pkts_in_detect = LSTACK_LPM_PKTS_IN_DETECT;

    PARSE_ARG(g_config_params.low_power_mod, "low_power_mode", 0, 0, 1, ret);
    return ret;
}

static int32_t parse_use_ltran(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.use_ltran, "use_ltran", 1, 0, 1, ret);
    return ret;
}

static int32_t parse_tcp_conn_count(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.tcp_conn_count, "tcp_conn_count", TCP_CONN_COUNT, 1, TCP_CONN_COUNT, ret);
    return ret;
}

static int32_t parse_send_ring_size(void)
{
    int32_t ret;
    /* send ring size default value is 32 */
    PARSE_ARG(g_config_params.send_ring_size, "send_ring_size", 32, 1, SOCK_SEND_RING_SIZE_MAX, ret);
    return ret;
}

static int32_t parse_expand_send_ring(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.expand_send_ring, "expand_send_ring", 0, 0, 1, ret);
    return ret;
}

static int32_t parse_mbuf_count_per_conn(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.mbuf_count_per_conn, "mbuf_count_per_conn",
                     MBUF_COUNT_PER_CONN, 1, INT32_MAX, ret);
    return ret;
}

static int32_t parse_read_connect_number(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.read_connect_number, "read_connect_number",
              STACK_THREAD_DEFAULT, 1, INT32_MAX, ret);
    return ret;
}

static int32_t parse_rpc_number(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.rpc_number, "rpc_number",
              STACK_THREAD_DEFAULT, 1, INT32_MAX, ret);
    return ret;
}

static int32_t parse_nic_read_number(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.nic_read_number, "nic_read_number",
              STACK_NIC_READ_DEFAULT, 1, INT32_MAX, ret);
    return ret;
}

static int32_t parse_listen_shadow(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.listen_shadow, "listen_shadow", 0, 0, 1, ret);
    return ret;
}

static int32_t parse_app_bind_numa(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.app_bind_numa, "app_bind_numa", 1, 0, 1, ret);
    return ret;
}

static int32_t parse_main_thread_affinity(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.main_thread_affinity, "main_thread_affinity", 0, 0, 1, ret);
    return ret;
}

static int32_t parse_kni_switch(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.kni_switch, "kni_switch", 0, 0, 1, ret);
    if (ret != 0) {
        return ret;
    }

    if (g_config_params.use_ltran && g_config_params.kni_switch) {
        LSTACK_PRE_LOG(LSTACK_ERR, "kni_switch=1 when use_ltran=1, invaild.\n");
        return -1;
    }

    if (!g_config_params.use_ltran && !g_config_params.is_primary) {
        g_config_params.kni_switch = 0;
    }

    return 0;
}

static int32_t parse_conf_file(const char *path)
{
    char real_path[PATH_MAX];
    int32_t ret;

    if (realpath(path, real_path) == NULL) {
        return -1;
    }

    config_init(&g_config);

    ret = config_read_file(&g_config, real_path);
    if (ret == 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "Config file path error, Please check conf file path.\n");
        config_destroy(&g_config);
        return -EINVAL;
    }

    for (int32_t i = 0; g_config_tbl[i].name && g_config_tbl[i].f; ++i) {
        ret = g_config_tbl[i].f();
        if (ret != 0) {
            LSTACK_PRE_LOG(LSTACK_ERR, "error parsing parameter '%s' ret=%d\n.", g_config_tbl[i].name, ret);
            config_destroy(&g_config);
            return ret;
        }
    }

    config_destroy(&g_config);
    return 0;
}

int32_t cfg_init(void)
{
    int32_t ret;
    char *config_file = calloc(PATH_MAX, sizeof(char));
    if (config_file == NULL) {
        return -1;
    }
    char *enval = getenv(LSTACK_CONF_ENV);
    if (enval == NULL) {
        ret = sprintf_s(config_file, PATH_MAX, "%s", DEFAULT_CONF_FILE);
    } else {
        ret = sprintf_s(config_file, PATH_MAX, "%s", enval);
    }
    if (ret < 0) {
        free(config_file);
        return ret;
    }

    ret = parse_conf_file(config_file);

    free(config_file);
    return ret;
}

static int32_t parse_unix_prefix(void)
{
    const config_setting_t *unix_prefix = NULL;
    const char *args = NULL;
    int32_t ret = 0;

    ret = memset_s(g_config_params.unix_socket_filename, sizeof(g_config_params.unix_socket_filename),
            0, sizeof(g_config_params.unix_socket_filename));
    if (ret != EOK) {
        return ret;
    }

    ret = strncpy_s(g_config_params.unix_socket_filename, sizeof(g_config_params.unix_socket_filename),
           GAZELLE_RUN_DIR, strlen(GAZELLE_RUN_DIR) + 1);
    if (ret != EOK) {
        return ret;
    }

    unix_prefix = config_lookup(&g_config, "unix_prefix");
    if (unix_prefix) {
        args = config_setting_get_string(unix_prefix);
        if (filename_check(args)) {
            return -EINVAL;
        }

        ret = strncat_s(g_config_params.unix_socket_filename, sizeof(g_config_params.unix_socket_filename),
            args, strlen(args) + 1);
        if (ret != EOK) {
            return ret;
        }
    }

    ret = strncat_s(g_config_params.unix_socket_filename, sizeof(g_config_params.unix_socket_filename),
            GAZELLE_REG_SOCK_FILENAME, strlen(GAZELLE_REG_SOCK_FILENAME) + 1);
    if (ret != EOK) {
        return ret;
    }

    return 0;
}

static int32_t parse_seperate_sendrecv_args(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.seperate_send_recv, "seperate_send_recv", 0, 0, 1, ret);
    return ret;
}

static int32_t parse_num_process(void)
{
    if (g_config_params.use_ltran) {
        return 0;
    }

    const config_setting_t *num_process = NULL;

    num_process = config_lookup(&g_config, "num_process");
    if (num_process == NULL) {
        g_config_params.num_process = 1;
    } else {
        g_config_params.num_process = (uint8_t)config_setting_get_int(num_process);
    }

    g_config_params.tot_queue_num = g_config_params.num_queue * g_config_params.num_process;

    return 0;
}

static int32_t parse_process_numa(void)
{
    const config_setting_t *cfg_args = NULL;
    const char *args = NULL;

    int ret;
    cfg_args = config_lookup(&g_config, "process_numa");
    if (cfg_args == NULL)
        return 0;

    args = config_setting_get_string(cfg_args);
    if (args == NULL) {
        return -EINVAL;
    }

    ret = separate_str_to_array((char *)args, g_config_params.process_numa, PROTOCOL_STACK_MAX, GAZELLE_MAX_NUMA_NODES);
    if (ret <= 0) {
        return -EINVAL;
    }

    return 0;
}

static int parse_process_index(void)
{
    if (g_config_params.use_ltran) {
        return 0;
    }

    const config_setting_t *process_idx = NULL;
    process_idx = config_lookup(&g_config, "process_idx");
    if (process_idx == NULL) {
        if (g_config_params.num_process == 1) {
            g_config_params.process_idx = 0;
        } else {
            return -EINVAL;
        }
    } else {
        g_config_params.process_idx = (uint8_t)config_setting_get_int(process_idx);
        if ((g_config_params.is_primary && g_config_params.process_idx != 0) ||
            (!g_config_params.is_primary && g_config_params.process_idx == 0)) {
            return -EINVAL;
        }
    }

    return 0;
}

static int parse_tuple_filter(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.tuple_filter, "tuple_filter", 0, 0, 1, ret);
    if (ret != 0) {
        return ret;
    }
    if (g_config_params.tuple_filter == 0) {
        return 0;
    }
    if (g_config_params.use_ltran || g_config_params.listen_shadow) {
        return -EINVAL;
    }

    return 0;
}

static int32_t parse_use_bond4(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.use_bond4, "use_bond4", 0, 0, 1, ret);
    return ret;
}

static int32_t parse_bond4_slave_mac(void)
{
    if (g_config_params.use_bond4 == 0) {
        return 0;
    }

    int32_t ret;
    const char *slave_mac1 = NULL;
    const char *slave_mac2 = NULL;
    const config_setting_t *devs = NULL;

    devs = config_lookup(&g_config, "slave_mac1");
    if (devs == NULL) {
        return -EINVAL;
    }
    slave_mac1 = config_setting_get_string(devs);
    if (slave_mac1 == NULL) {
        return 0;
    }

    devs = config_lookup(&g_config, "slave_mac2");
    if (devs == NULL) {
        return -EINVAL;
    }
    slave_mac2 = config_setting_get_string(devs);
    if (slave_mac2 == NULL) {
        return 0;
    }

    /* add dev */
    ret = str_to_eth_addr(slave_mac1, g_config_params.bond4_slave1_mac_addr);
    if (ret != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "cfg: invalid device name %s ret=%d.\n", slave_mac1, ret);
        return ret;
    }

    ret = str_to_eth_addr(slave_mac2, g_config_params.bond4_slave2_mac_addr);
    if (ret != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "cfg: invalid device name %s ret=%d.\n", slave_mac2, ret);
    }
    return ret;
}

static int32_t parse_use_sockmap(void)
{
    int32_t ret;
    PARSE_ARG(g_config_params.use_sockmap, "use_sockmap", 0, 0, 1, ret);
    return ret;
}
