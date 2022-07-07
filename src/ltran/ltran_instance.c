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

#include "ltran_instance.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <securec.h>

#include "ltran_stack.h"
#include "ltran_tcp_sock.h"
#include "ltran_param.h"
#include "ltran_stat.h"
#include "ltran_log.h"
#include "gazelle_base_func.h"

volatile unsigned long g_tx_loop_count __rte_cache_aligned;
volatile unsigned long g_rx_loop_count __rte_cache_aligned;

struct gazelle_instance_mgr *g_instance_mgr = NULL;

static void gazelle_set_instance_null_by_pid(struct gazelle_instance_mgr *mgr, uint32_t pid);
static void handle_stack_logout(struct gazelle_instance *instance, const struct gazelle_stack *stack);
static int32_t simple_response(int32_t fd, enum response_type type);

void set_tx_loop_count(void)
{
    g_tx_loop_count++;
    return;
}

unsigned long get_tx_loop_count(void)
{
    return g_tx_loop_count;
}

void set_rx_loop_count(void)
{
    g_rx_loop_count++;
    return;
}

unsigned long get_rx_loop_count(void)
{
    return g_rx_loop_count;
}

struct gazelle_instance_mgr *get_instance_mgr(void)
{
    return g_instance_mgr;
}

void set_instance_mgr(struct gazelle_instance_mgr *instance)
{
    g_instance_mgr = instance;
    return;
}

struct gazelle_instance_mgr *gazelle_instance_mgr_create(void)
{
    struct gazelle_instance_mgr *mgr;

    mgr = malloc(sizeof(struct gazelle_instance_mgr));
    if (mgr == NULL) {
        return NULL;
    }
    (void)memset_s(mgr, sizeof(struct gazelle_instance_mgr), 0, sizeof(struct gazelle_instance_mgr));

    mgr->net_mask = htonl(get_ltran_config()->dispatcher.ipv4_net_mask);
    mgr->subnet_size = (uint32_t)(get_ltran_config()->dispatcher.ipv4_subnet_size);
    mgr->max_instance_num = get_ltran_config()->dispatcher.num_clients;

    mgr->ipv4_to_client = malloc(mgr->subnet_size * sizeof(*mgr->ipv4_to_client));
    if (mgr->ipv4_to_client == NULL) {
        free(mgr);
        return NULL;
    }

    for (uint32_t i = 0; i < mgr->subnet_size; i++) {
        mgr->ipv4_to_client[i] = GAZELLE_NULL_CLIENT;
    }

    return mgr;
}

void gazelle_instance_mgr_destroy(void)
{
    struct gazelle_instance_mgr *mgr = g_instance_mgr;
    if (mgr == NULL) {
        return;
    }

    for (int32_t i = 0; i < GAZELLE_MAX_INSTANCE_NUM; i++) {
        if (mgr->instances[i] != NULL) {
            (void)rte_eal_sec_detach(mgr->instances[i]->file_prefix, (int32_t)strlen(mgr->instances[i]->file_prefix));
            GAZELLE_FREE(mgr->instances[i]);
        }
    }
    GAZELLE_FREE(mgr->ipv4_to_client);
    GAZELLE_FREE(g_instance_mgr);
}

int32_t gazelle_instance_map_set(struct gazelle_instance_mgr *mgr, const struct gazelle_instance *instance)
{
    if (instance == NULL) {
        return GAZELLE_ERR;
    }

    uint32_t ip_idx = instance->ip_addr.s_addr & mgr->net_mask;

    for (uint8_t i = 0; i < GAZELLE_MAX_INSTANCE_ARRAY_SIZE; i++) {
        if (mgr->instances[i] == instance) {
            mgr->ipv4_to_client[ntohl(ip_idx)] = i;
            return GAZELLE_OK;
        }
    }

    return GAZELLE_ERR;
}

struct gazelle_instance *gazelle_instance_map_by_ip(const struct gazelle_instance_mgr *mgr, uint32_t ip)
{
    uint32_t ip_idx = ntohl(ip & mgr->net_mask);
    if (ip_idx < mgr->subnet_size) {
        uint8_t cl_idx = mgr->ipv4_to_client[ip_idx];
        return mgr->instances[cl_idx];
    }
    return NULL;
}

struct gazelle_instance *gazelle_instance_get_by_pid(const struct gazelle_instance_mgr *mgr, uint32_t pid)
{
    struct gazelle_instance *instance = NULL;

    for (int32_t i = 0; i < GAZELLE_MAX_INSTANCE_NUM; i++) {
        instance = mgr->instances[i];
        if (instance == NULL) {
            continue;
        }

        if (instance->pid == pid) {
            return instance;
        }
    }
    return NULL;
}

int32_t *instance_cur_tick_init_val(void)
{
    /* init val INSTANCE_CUR_TICK_INIT_VAL != INSTANCE_REG_TICK_INIT_VAL instance state off */
    static int32_t instance_cur_tick = INSTANCE_CUR_TICK_INIT_VAL;

    return &instance_cur_tick;
}

struct gazelle_instance *gazelle_instance_add_by_pid(struct gazelle_instance_mgr *mgr, uint32_t pid)
{
    struct gazelle_instance *instance = NULL;

    instance = gazelle_instance_get_by_pid(mgr, pid);
    if (instance != NULL) {
        return instance;
    }

    if (mgr->cur_instance_num >= mgr->max_instance_num) {
        LTRAN_ERR("instance num out of range max_num=%u.\n", mgr->max_instance_num);
        return NULL;
    }

    for (int32_t i = 0; i < GAZELLE_MAX_INSTANCE_NUM; i++) {
        if (mgr->instances[i] != NULL) {
            continue;
        }

        instance = malloc(sizeof(struct gazelle_instance));
        if (instance == NULL) {
            return NULL;
        }
        (void)memset_s(instance, sizeof(struct gazelle_instance), 0, sizeof(struct gazelle_instance));

        instance->pid = pid;
        mgr->instance_cur_tick[i]++;
        instance->instance_reg_tick = mgr->instance_cur_tick[i] - 1; /* init tick diffrent state off */
        instance->instance_cur_tick = &mgr->instance_cur_tick[i];

        mgr->instances[i] = instance;
        mgr->cur_instance_num++;
        return instance;
    }
    return NULL;
}

static void gazelle_set_instance_null_by_pid(struct gazelle_instance_mgr *mgr, uint32_t pid)
{
    for (int32_t i = 0; i < GAZELLE_MAX_INSTANCE_NUM; i++) {
        if (mgr->instances[i] == NULL) {
            continue;
        }

        if (mgr->instances[i]->pid == pid) {
            mgr->cur_instance_num--;
            mgr->instances[i] = NULL;
            return;
        }
    }
}

static int32_t instance_info_set(struct gazelle_instance *instance, const struct client_proc_conf *conf)
{
    int32_t ret;
    if ((instance == NULL) || (conf == NULL)) {
        return GAZELLE_ERR;
    }

    /* already net byte order in conf->ipv4 */
    instance->ip_addr.s_addr = conf->ipv4;
    instance->pid            = conf->pid;
    instance->base_virtaddr  = conf->base_virtaddr;
    instance->socket_size    = conf->socket_size;
    instance->stack_cnt      = 0;

    ret = strncpy_s(instance->file_prefix, PATH_MAX, conf->file_prefix, PATH_MAX - 1);
    if (ret != EOK) {
        return GAZELLE_ERR;
    }

    memset_s(instance->stack_array, sizeof(instance->stack_array), 0, sizeof(instance->stack_array));

    ret = memcpy_s(instance->ethdev.addr_bytes, RTE_ETHER_ADDR_LEN, conf->ethdev.addr_bytes, RTE_ETHER_ADDR_LEN);
    if (ret != EOK) {
        return GAZELLE_ERR;
    }

    return GAZELLE_OK;
}

int32_t instance_match_bond_port(const struct rte_ether_addr *mac)
{
    int32_t bond_index;

    for (bond_index = 0; bond_index < GAZELLE_MAX_BOND_NUM; bond_index++) {
        if (is_same_mac_addr(mac, &(get_ltran_config()->bond.mac[bond_index]))) {
            return bond_index;
        }
    }

    LTRAN_ERR("match_bond_port failed: [bond] mac=%02X:%02X:%02X:%02X:%02X:%02X\n",
        mac->addr_bytes[0], mac->addr_bytes[1], mac->addr_bytes[2], /* 0 1 2 is mac byte */
        mac->addr_bytes[3], mac->addr_bytes[4], mac->addr_bytes[5]); /* 3 4 5 is mac byte */
    return -1;
}

static int32_t instance_info_check(const struct client_proc_conf *conf)
{
    struct ltran_config *ltran_config = get_ltran_config();
    uint32_t in_ipv4 = ntohl(conf->ipv4);

    struct in_addr in = {
        .s_addr = conf->ipv4,
    };
    char addr[GAZELLE_INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &in, addr, sizeof(addr));

    if (in_ipv4 == NULL_CLIENT_IP) {
        LTRAN_ERR("pid %u, ip not set.\n", conf->pid);
        return GAZELLE_ERR;
    }

    if ((in_ipv4 & ltran_config->dispatcher.ipv4_net_mask)
        == (NULL_CLIENT_IP & ltran_config->dispatcher.ipv4_net_mask)) {
        LTRAN_ERR("pid %u: ip invalid.\n", conf->pid);
        return GAZELLE_ERR;
    }

    if ((in_ipv4 & ltran_config->dispatcher.ipv4_net_mask) == 0) {
        LTRAN_ERR("pid %u, ip cannot be zero.\n", conf->pid);
        return GAZELLE_ERR;
    }

    if ((in_ipv4 & ~(ltran_config->dispatcher.ipv4_net_mask)) !=
        ltran_config->dispatcher.ipv4_subnet_addr.s_addr) {
        LTRAN_ERR("pid %u: ip %s is not in subnet.\n", conf->pid, addr);
        return GAZELLE_ERR;
    }

    if (gazelle_instance_map_by_ip(get_instance_mgr(), in.s_addr) ||
        gazelle_instance_get_by_pid(get_instance_mgr(), conf->pid)) {
        LTRAN_ERR("pid %u: ip %s already exist.\n", conf->pid, addr);
        return GAZELLE_ERR;
    }

    if (instance_match_bond_port(&conf->ethdev) < 0) {
        return GAZELLE_ERR;
    }

    return GAZELLE_OK;
}

#define MAP_ADDR_TAIL       0x7fffffffffULL // 549GB
#define MAP_ADDR_HEAD       0x1000000000ULL // 68GB
#define MAP_RESERVE_SIZE    0x0008000000ULL // 128MB
#define MAX_HUGEPAGE_SIZE   0x0040000000ULL // 1024MB
#define MAP_ADDR_STEP       0x0008000000ULL // 128MB

__attribute__((always_inline)) inline static size_t map_size_align(size_t size, size_t page_sz)
{
    size_t map_size;

    map_size = MAP_RESERVE_SIZE + size;
    map_size = (map_size / MAX_HUGEPAGE_SIZE + 1) * MAX_HUGEPAGE_SIZE;
    if (page_sz > 0) {
        map_size = (map_size / page_sz + 1) * page_sz;
    }

    /* avoid Integer overflow flip */
    if (map_size < size) {
        map_size = size;
    }
    return map_size;
}

#ifdef gazelle_map_addr_nocheck
/* Ignore the virtual address check and return according to the address actually applied for by mmap.
   Scenarios: asan test
*/
static int32_t get_virtual_area(uintptr_t *need_addr, size_t *size)
{
    void *map_addr = NULL;
    void *map_head = NULL;
    size_t map_size;
    const size_t page_sz = (size_t)sysconf(_SC_PAGESIZE);
    if (page_sz == 0) {
        LTRAN_ERR("addr_nocheck sysconf failed, errno %d. \n", errno);
        return GAZELLE_ERR;
    }

    if ((need_addr == NULL) || (size == NULL)) {
        return -GAZELLE_EPARAM;
    }
    void *arg_addr = (void *)*need_addr;

    map_head = (arg_addr != NULL) ? arg_addr : (void *)MAP_ADDR_HEAD;
    map_size = map_size_align(*size, page_sz);

    map_head = RTE_PTR_ALIGN(map_head, page_sz);
    map_addr = mmap(map_head, map_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map_addr == MAP_FAILED) {
        LTRAN_ERR("addr_nocheck map size(%lu) failed, errno %d. \n", map_size, errno);
        return GAZELLE_ERR;
    }
    if (map_addr != map_head) {
        LTRAN_INFO("addr_nocheck map request size(%lu) addr not equal. \n", map_size);
    }

    if (map_addr == NULL) {
        LTRAN_ERR("addr_nocheck map size(%lu) failed.\n", *size);
        return GAZELLE_ERR;
    }

    *need_addr = (uintptr_t)map_addr;
    *size = map_size;
    return GAZELLE_OK;
}
#else
static int32_t get_virtual_area(uintptr_t *need_addr, size_t *size)
{
    void *map_addr = NULL;
    void *map_head = NULL;
    bool try_flags = false;
    size_t map_size;

    static void *next_addr = (void *)MAP_ADDR_HEAD;

    const size_t page_sz = (size_t)sysconf(_SC_PAGESIZE);
    if (page_sz == 0) {
        LTRAN_ERR("sysconf failed, errno %d.\n", errno);
        return GAZELLE_ERR;
    }

    if ((need_addr == NULL) || (size == NULL)) {
        return -GAZELLE_EPARAM;
    }
    void *arg_addr = (void *)*need_addr;

    map_head = (arg_addr != NULL) ? arg_addr : next_addr;
    map_size = map_size_align(*size, page_sz);

    do {
        if (map_head >= (void *)MAP_ADDR_TAIL) {
            try_flags = true;
            map_head = (void *)MAP_ADDR_HEAD;
        }

        map_head = RTE_PTR_ALIGN(map_head, page_sz);
        map_addr = mmap(map_head, map_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map_addr == MAP_FAILED) {
            LTRAN_ERR("map size(%lu) failed, errno %d. \n", map_size, errno);
            return GAZELLE_ERR;
        } else if (map_addr != map_head) {
            munmap(map_addr, map_size);
            map_addr = NULL;
            LTRAN_DEBUG("map request size(%lu), addr not equal. \n", map_size);
            if (arg_addr != NULL) {
                break;
            }

            next_addr = RTE_PTR_ADD(next_addr, MAP_ADDR_STEP);
            map_head = next_addr;
        } else {
            next_addr = RTE_PTR_ADD(map_addr, map_size);
            break;
        }
    } while ((!try_flags) || (map_head < (void *)MAP_ADDR_TAIL));

    if (map_addr == NULL) {
        LTRAN_ERR("map size(%lu) failed. \n", *size);
        return GAZELLE_ERR;
    }

    *size = map_size;
    *need_addr = (uintptr_t)map_addr;

    return GAZELLE_OK;
}
#endif
static void remove_virtual_area(uintptr_t addr, size_t size)
{
    if (size == 0 || addr == 0) {
        return;
    }

    if (munmap((void *)addr, size) < 0) {
        LTRAN_ERR("failed, errno %d. \n", errno);
    }
}

int32_t handle_reg_msg_proc_mem(int32_t fd, struct reg_request_msg *recv_msg)
{
    struct reg_response_msg send_msg;
    struct client_proc_conf *conf = &recv_msg->msg.proc;
    struct gazelle_instance *instance = NULL;
    struct ltran_config *ltran_config = get_ltran_config();

    (void)memset_s(&send_msg, sizeof(send_msg), 0, sizeof(send_msg));

    int32_t ret = instance_info_check(conf);
    if (ret != GAZELLE_OK) {
        goto END;
    }

    instance = gazelle_instance_add_by_pid(get_instance_mgr(), conf->pid);
    if (instance == NULL) {
        goto END;
    }
    /* set reg_state to release instance when logout */
    instance->reg_state = RQT_REG_PROC_MEM;

    ret = get_virtual_area(&conf->base_virtaddr, (size_t *)&conf->socket_size);
    if (ret != GAZELLE_OK) {
        LTRAN_ERR("pid %u, cannot get virtual area.ret=%d.\n", conf->pid, ret);
        goto END;
    }

    ret = instance_info_set(instance, conf);
    if (ret != GAZELLE_OK) {
        goto END;
    }
    instance->sockfd = fd;

    send_msg.msg.socket_size = instance->socket_size;
    send_msg.msg.base_virtaddr = instance->base_virtaddr;
    send_msg.msg.rx_offload = ltran_config->dpdk.rx_offload;
    send_msg.msg.tx_offload = ltran_config->dpdk.tx_offload;
    send_msg.type = RSP_OK;
    ret = write_specied_len(fd, (char *)&send_msg, sizeof(send_msg));
    if (ret != 0) {
        return GAZELLE_ERR;
    }
    return GAZELLE_OK;

END:
    (void)simple_response(fd, RSP_ERR);
    return GAZELLE_ERR;
}

static void print_client_args(int32_t argc, char *argv[])
{
    char arg_buf[GAZELLE_MAX_REG_ARGS * PATH_MAX];
    char *arg_tmp = arg_buf;
    for (int32_t i = 0; (i < argc) && (i < GAZELLE_MAX_REG_ARGS); ++i) {
        int32_t ret = snprintf_s(arg_tmp, PATH_MAX, strlen(argv[i]) + 1, "%s ", argv[i]);
        if (ret < 0) {
            LTRAN_ERR("snprintf_s client reg args failed. ret=%d.\n", ret);
            return;
        }

        arg_tmp = arg_buf + strlen(arg_buf);
    }

    LTRAN_INFO("recv client args: %s\n", arg_buf);
}

static int32_t simple_response(int32_t fd, enum response_type type)
{
    struct reg_response_msg send_msg = {0};
    send_msg.type = type;
    int32_t ret = write_specied_len(fd, (char *)&send_msg, sizeof(send_msg));

    return ret;
}

int32_t handle_reg_msg_proc_att(int32_t fd, struct reg_request_msg *recv_msg)
{
    int32_t ret;
    struct gazelle_instance *instance = NULL;
    struct client_proc_conf *conf = &recv_msg->msg.proc;

    int32_t argc = 0;
    char *argv[GAZELLE_MAX_REG_ARGS];

    instance = gazelle_instance_get_by_pid(get_instance_mgr(), conf->pid);
    if (instance == NULL) {
        LTRAN_ERR("pid %u, get instance failed. \n", conf->pid);
        goto END;
    }

    argc = (int32_t)conf->argc;
    if (argc < 0 || argc > GAZELLE_MAX_REG_ARGS) {
        LTRAN_ERR("pid %u, argc %d over limit. \n", conf->pid, argc);
        goto END;
    }

    for (int32_t i = 0; i < argc; ++i) {
        argv[i] = conf->argv[i];
    }
    print_client_args(argc, argv);

    remove_virtual_area(instance->base_virtaddr, (size_t)instance->socket_size);

    /* set reg_state to release attach resource when logout, whether or not rte_eal_sec_attach success */
    instance->reg_state = RQT_REG_PROC_ATT;
    ret = rte_eal_sec_attach(argc, argv);
    if (ret < 0) {
        LTRAN_RTE_ERR("pid %u, rte_eal_sec_attach failed. ret=%d.\n", conf->pid, ret);
        goto END;
    }

    ret = gazelle_instance_map_set(get_instance_mgr(), instance);
    if (ret != GAZELLE_OK) {
        LTRAN_RTE_ERR("pid %u, gazelle_instance_map_set failed. ret=%d.\n", conf->pid, ret);
        goto END;
    }

    ret = simple_response(fd, RSP_OK);
    if (ret != 0) {
        return GAZELLE_ERR;
    }
    rte_mb();
    instance->instance_reg_tick = *instance->instance_cur_tick;

    return GAZELLE_OK;
END:
    (void)simple_response(fd, RSP_ERR);
    return GAZELLE_ERR;
}

static int32_t gazelle_get_free_stack_idx(const struct gazelle_instance *inst, int32_t *idx)
{
    int32_t i;

    for (i = 0; i < GAZELLE_MAX_STACK_ARRAY_SIZE; i++) {
        if (inst->stack_array[i] == NULL) {
            break;
        }
    }

    if (i == GAZELLE_MAX_STACK_ARRAY_SIZE) {
        return GAZELLE_ERR;
    }

    *idx = i;
    return GAZELLE_OK;
}

int32_t handle_reg_msg_thrd_ring(int32_t fd, const struct reg_request_msg *recv_msg)
{
    const struct client_thrd_conf *conf = &recv_msg->msg.thrd;
    const struct gazelle_stack *exist_stack = NULL;
    struct gazelle_instance *instance = NULL;
    struct gazelle_stack *stack = NULL;
    int32_t ret, idx;

    /* avoid reinit */
    exist_stack = gazelle_stack_get_by_tid(gazelle_get_stack_htable(), conf->tid);
    if (exist_stack != NULL) {
        ret = simple_response(fd, RSP_OK);
        return ret;
    }

    instance = gazelle_instance_get_by_pid(get_instance_mgr(), conf->pid);
    if (instance == NULL) {
        LTRAN_ERR("pid %u, get instance failed.\n", conf->pid);
        goto END;
    }
    if (instance->stack_cnt > GAZELLE_MAX_STACK_ARRAY_SIZE - 1) {
        LTRAN_ERR("pid %u, instance stack_array overflow.\n", conf->pid);
        goto END;
    }

    stack = gazelle_stack_add_by_tid(gazelle_get_stack_htable(), conf->tid);
    if (stack == NULL) {
        goto END;
    }
    stack->reg_ring = conf->reg_ring;
    stack->tx_ring = conf->tx_ring;
    stack->rx_ring = conf->rx_ring;

    ret = gazelle_get_free_stack_idx(instance, &idx);
    if (ret != GAZELLE_OK) {
        LTRAN_ERR("pid %u, tid %u, get stack idx failed. ret=%d\n", conf->pid, conf->tid, ret);
        /* find stack by instance when logout. stack reg to instance after this failure */
        gazelle_stack_del_by_tid(gazelle_get_stack_htable(), conf->tid);
        goto END;
    }

    instance->stack_array[idx] = stack;
    instance->stack_cnt++;
    stack->index = idx;
    instance->reg_state = RQT_REG_THRD_RING;

    ret = simple_response(fd, RSP_OK);
    if (ret != 0) {
        return GAZELLE_ERR;
    }
    rte_mb();
    stack->instance_reg_tick = instance->instance_reg_tick;
    stack->instance_cur_tick = instance->instance_cur_tick;
    return GAZELLE_OK;
END:
    (void)simple_response(fd, RSP_ERR);;
    return GAZELLE_ERR;
}

static inline void wait_forward_done(void)
{
    /* wait tx_loop_count and rx_loop_count change to avoid free using memory */
    unsigned long tmp_rx_loop_count = get_rx_loop_count();
    unsigned long tmp_tx_loop_count = get_tx_loop_count();
    while ((tmp_tx_loop_count == get_tx_loop_count()) ||
           (tmp_rx_loop_count == get_rx_loop_count())) {
        continue;
    }
}

static void handle_stack_logout(struct gazelle_instance *instance, const struct gazelle_stack *stack)
{
    uint32_t tid = stack->tid;
    instance->stack_array[stack->index] = NULL;
    instance->stack_cnt--;

    gazelle_stack_del_by_tid(gazelle_get_stack_htable(), stack->tid);

    LTRAN_INFO("tid %u, stack logout successfully.\n", tid);
    return;
}

static void handle_inst_logout_for_reg_thrd_ring(struct gazelle_instance *instance)
{
    for (int32_t i = 0; i < GAZELLE_MAX_STACK_ARRAY_SIZE; i++) {
        if (instance->stack_cnt == 0) {
            break;
        }

        struct gazelle_stack *stack = instance->stack_array[i];
        if (stack == NULL) {
            continue;
        }

        handle_stack_logout(instance, stack);
    }

    return;
}

static int32_t handle_inst_logout_reg_proc_att(struct gazelle_instance *instance,
    struct gazelle_instance_mgr *instance_mgr)
{
    int32_t ret;

    instance->socket_size = 0;
    instance->base_virtaddr = 0;

    uint32_t ip_idx = instance->ip_addr.s_addr & instance_mgr->net_mask;
    instance_mgr->ipv4_to_client[ntohl(ip_idx)] = GAZELLE_NULL_CLIENT;

    ret = rte_eal_sec_detach(instance->file_prefix, (int32_t)strlen(instance->file_prefix));
    if (ret < 0) {
        LTRAN_RTE_ERR("rte_eal_sec_detach failed:%d.\n", ret);
        return GAZELLE_ERR;
    }
    return GAZELLE_OK;
}

static void handle_inst_logout_reg_proc_mem(struct gazelle_instance *instance)
{
    remove_virtual_area(instance->base_virtaddr, (size_t)instance->socket_size);

    free(instance);
    return;
}

void handle_instance_logout(uint32_t pid)
{
    int32_t ret = GAZELLE_OK;
    struct gazelle_instance_mgr *instance_mgr = get_instance_mgr();
    struct gazelle_instance *instance = NULL;

    instance = gazelle_instance_get_by_pid(instance_mgr, pid);
    if (instance == NULL) {
        LTRAN_ERR("pid %u, get instance failed. \n", pid);
        return;
    }

    (*instance->instance_cur_tick)++;
    gazelle_set_instance_null_by_pid(instance_mgr, pid);
    rte_mb();
    wait_forward_done();
    rte_mb();

    switch (instance->reg_state) {
        case RQT_REG_THRD_RING:
            handle_inst_logout_for_reg_thrd_ring(instance);
            /* fallthrough */
        case RQT_REG_PROC_ATT:
            ret = handle_inst_logout_reg_proc_att(instance, instance_mgr);
            /* fallthrough */
        case RQT_REG_PROC_MEM:
            /* instance ptr has been free after this func */
            handle_inst_logout_reg_proc_mem(instance);
            instance = NULL;
            break;
        default:
            break;
    }

    LTRAN_WARN("pid %u, instance logout ret:%d.\n", pid, ret);
}
