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
#include <sched.h>
#include <stdbool.h>
#include <securec.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_bus.h>
#include <rte_errno.h>
#include <rte_kni.h>
#include <rte_pdump.h>
#include <rte_thash.h>
#include <lwip/posix_api.h>
#include <lwipopts.h>
#include <lwip/pbuf.h>
#include <lwip/reg_sock.h>
#include <lwip/priv/tcp_priv.h>

#include "lstack_log.h"
#include "dpdk_common.h"
#include "lstack_dpdk.h"
#include "lstack_lockless_queue.h"
#include "lstack_protocol_stack.h"
#include "lstack_thread_rpc.h"
#include "lstack_lwip.h"
#include "lstack_cfg.h"

struct eth_params {
    uint16_t port_id;

    uint16_t nb_queues;
    uint16_t nb_rx_desc;
    uint16_t nb_tx_desc;

    struct rte_eth_conf conf;
    struct rte_eth_rxconf rx_conf;
    struct rte_eth_txconf tx_conf;
};
struct rte_kni;
static struct rte_bus *g_pci_bus = NULL;

#define RSS_HASH_KEY_LEN    40
static uint8_t g_default_rss_key[] = {
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
    0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
    0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

int32_t thread_affinity_default(void)
{
    static cpu_set_t cpuset;
    static bool first_flags = true;
    if (first_flags) {
        CPU_ZERO(&cpuset);
        if (pthread_getaffinity_np(pthread_self(), sizeof(cpuset), &cpuset) != 0) {
            return -1;
        }
        first_flags = false;
    } else {
        /* cancel the core binding from DPDK initialization */
        if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset) != 0) {
            return -1;
        }
    }
    return 0;
}

int32_t thread_affinity_init(int32_t cpu_id)
{
    int32_t ret;
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);

    ret = rte_thread_set_affinity(&cpuset);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "thread %d pthread_setaffinity_np failed ret=%d\n", rte_gettid(), ret);
    }

    return 0;
}

int32_t dpdk_eal_init(void)
{
    int32_t ret;
    struct cfg_params *global_params = get_global_cfg_params();
    
    ret = rte_eal_init(global_params->dpdk_argc, global_params->dpdk_argv);
    if (ret < 0) {
        if (rte_errno == EALREADY) {
            LSTACK_PRE_LOG(LSTACK_INFO, "rte_eal_init aleady init\n");
            /* maybe other program inited, merge init param share init */
            ret = 0;
        } else {
            LSTACK_PRE_LOG(LSTACK_ERR, "rte_eal_init failed init, rte_errno %d\n", rte_errno);
        }
    } else {
        LSTACK_PRE_LOG(LSTACK_INFO, "dpdk_eal_init success\n");
    }

    ret = rte_pdump_init();
    if (ret < 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "rte_pdump_init failed init, rte_errno %d\n", rte_errno);
	/* We do not care whether the pdump is successfully loaded. So, just print an alarm. */
    } else {
        LSTACK_PRE_LOG(LSTACK_INFO, "rte_pdump_init success\n");
    }

    return ret;
}

static struct rte_mempool *create_pktmbuf_mempool(const char *name, uint32_t nb_mbuf,
    uint32_t mbuf_cache_size, uint16_t queue_id)
{
    int32_t ret;
    char pool_name[PATH_MAX];
    struct rte_mempool *pool;

    ret = snprintf_s(pool_name, sizeof(pool_name), PATH_MAX - 1, "%s_%hu", name, queue_id);
    if (ret < 0) {
        return NULL;
    }

    /* time stamp before pbuf_custom as priv_data */
    uint16_t private_size = RTE_ALIGN(MBUF_PRIVATE_SIZE, RTE_CACHE_LINE_SIZE);
    pool = rte_pktmbuf_pool_create(pool_name, nb_mbuf, mbuf_cache_size, private_size, MBUF_SZ, rte_socket_id());
    if (pool == NULL) {
        LSTACK_LOG(ERR, LSTACK, "cannot create %s pool rte_err=%d\n", pool_name, rte_errno);
    }
    return pool;
}

static struct reg_ring_msg *create_reg_mempool(const char *name, uint16_t queue_id)
{
    int ret;
    char pool_name[PATH_MAX];
    struct reg_ring_msg *reg_buf;

    ret = snprintf_s(pool_name, sizeof(pool_name), PATH_MAX - 1, "%s_%hu", name, queue_id);
    if (ret < 0) {
        return NULL;
    }

    reg_buf = rte_malloc(name, VDEV_REG_QUEUE_SZ * sizeof(struct reg_ring_msg), RTE_CACHE_LINE_SIZE);
    if (reg_buf == NULL) {
        LSTACK_LOG(ERR, LSTACK, "cannot create %s pool rte_err=%d.\n", pool_name, rte_errno);
    }

    return reg_buf;
}

int32_t pktmbuf_pool_init(struct protocol_stack *stack, uint16_t stack_num)
{
    if (stack_num == 0) {
        LSTACK_LOG(ERR, LSTACK, "stack_num=0.\n");
        return -1;
    }

    stack->rxtx_pktmbuf_pool = create_pktmbuf_mempool("rxtx_mbuf",
        get_global_cfg_params()->mbuf_count_per_conn * get_global_cfg_params()->tcp_conn_count / stack_num,
        RXTX_CACHE_SZ,
        stack->queue_id);
    if (stack->rxtx_pktmbuf_pool == NULL) {
        return -1;
    }

    if (use_ltran()) {
        stack->reg_buf = create_reg_mempool("reg_ring_msg", stack->queue_id);
        if (stack->reg_buf == NULL) {
            return -1;
        }
    }

    return 0;
}

struct rte_ring *create_ring(const char *name, uint32_t count, uint32_t flags, int32_t queue_id)
{
    char ring_name[RTE_RING_NAMESIZE] = {0};
    struct rte_ring *ring;

    int32_t ret = snprintf_s(ring_name, sizeof(ring_name), RTE_RING_NAMESIZE - 1, "%s_%d", name, queue_id);
    if (ret < 0) {
        return NULL;
    }

    ring = rte_ring_create(ring_name, count, rte_socket_id(), flags);
    if (ring == NULL) {
        LSTACK_LOG(ERR, LSTACK, "%s create failed. errno: %d.\n", name, rte_errno);
    }

    return ring;
}

int32_t create_shared_ring(struct protocol_stack *stack)
{
    lockless_queue_init(&stack->rpc_queue);

    if (get_protocol_stack_group()->wakeup_enable) {
        stack->wakeup_ring = create_ring("WAKEUP_RING", VDEV_WAKEUP_QUEUE_SZ, RING_F_SP_ENQ | RING_F_SC_DEQ,
            stack->queue_id);
        if (stack->wakeup_ring == NULL) {
            return -1;
        }
    }

    if (use_ltran()) {
        stack->rx_ring = create_ring("RING_RX", VDEV_RX_QUEUE_SZ, RING_F_SP_ENQ | RING_F_SC_DEQ, stack->queue_id);
        if (stack->rx_ring == NULL) {
            return -1;
        }

        stack->tx_ring = create_ring("RING_TX", VDEV_TX_QUEUE_SZ, RING_F_SP_ENQ | RING_F_SC_DEQ, stack->queue_id);
        if (stack->tx_ring == NULL) {
            return -1;
        }

        stack->reg_ring = create_ring("SHARED_REG_RING", VDEV_REG_QUEUE_SZ, RING_F_SP_ENQ | RING_F_SC_DEQ,
            stack->queue_id);
        if (stack->reg_ring == NULL) {
            return -1;
        }
    }

    return 0;
}

int32_t fill_mbuf_to_ring(struct rte_mempool *mempool, struct rte_ring *ring, uint32_t mbuf_num)
{
    int32_t ret;
    uint32_t batch;
    uint32_t remain = mbuf_num;
    struct rte_mbuf *free_buf[FREE_RX_QUEUE_SZ];

    while (remain > 0) {
        batch = LWIP_MIN(remain, RING_SIZE(FREE_RX_QUEUE_SZ));

        ret = gazelle_alloc_pktmbuf(mempool, free_buf, batch);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "cannot alloc mbuf for ring, count: %u ret=%d\n", batch, ret);
            return -1;
        }

        ret = gazelle_ring_sp_enqueue(ring, (void **)free_buf, batch);
        if (ret == 0) {
            LSTACK_LOG(ERR, LSTACK, "cannot enqueue to ring, count: %u\n", batch);
            return -1;
        }

        remain -= batch;
    }
    return 0;
}

void lstack_log_level_init(void)
{
    int32_t ret;

    rte_log_set_global_level(RTE_LOG_INFO);

    ret = rte_log_set_level(RTE_LOGTYPE_LSTACK, RTE_LOG_INFO);
    if (ret != 0) {
        LSTACK_PRE_LOG(LSTACK_ERR, "rte_log_set_level failed  RTE_LOGTYPE_LSTACK RTE_LOG_INFO ret=%d\n", ret);
    }
}

static int32_t ethdev_port_id(uint8_t *mac)
{
    int32_t port_id;
    struct rte_ether_addr mac_addr;
    int32_t nr_eth_dev = rte_eth_dev_count_avail();

    for (port_id = 0; port_id < nr_eth_dev; port_id++) {
        rte_eth_macaddr_get(port_id, &mac_addr);
        if (!memcmp(mac, mac_addr.addr_bytes, ETHER_ADDR_LEN)) {
            break;
        }
        LSTACK_LOG(INFO, LSTACK, "nic mac:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx not match\n",
            mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2], // 0 1 2 mac addr
            mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]); // 3 4 5 mac addr
    }

    if (port_id >= nr_eth_dev) {
        LSTACK_LOG(ERR, LSTACK, "No NIC is matched\n");
        return -EINVAL;
    }

    return port_id;
}

static struct eth_params *alloc_eth_params(uint16_t port_id, uint16_t nb_queues)
{
    struct eth_params *eth_params = calloc(1, sizeof(struct eth_params));
    if (eth_params == NULL) {
        return NULL;
    }

    eth_params->port_id = port_id;
    eth_params->nb_queues = nb_queues;
    eth_params->nb_rx_desc = RTE_TEST_RX_DESC_DEFAULT;
    eth_params->nb_tx_desc = RTE_TEST_TX_DESC_DEFAULT;
    eth_params->conf.link_speeds = ETH_LINK_SPEED_AUTONEG;
    eth_params->conf.txmode.mq_mode = ETH_MQ_TX_NONE;
    eth_params->conf.rxmode.mq_mode = ETH_MQ_RX_NONE;

    return eth_params;
}

uint64_t get_eth_params_rx_ol(void)
{
    return get_protocol_stack_group()->rx_offload;
}

uint64_t get_eth_params_tx_ol(void)
{
    return get_protocol_stack_group()->tx_offload;
}

static int eth_params_rss(struct rte_eth_conf *conf, struct rte_eth_dev_info *dev_info)
{
    int rss_enable = 0;
    uint64_t def_rss_hf = ETH_RSS_TCP | ETH_RSS_IP;
    struct rte_eth_rss_conf rss_conf = {
        g_default_rss_key,
        RSS_HASH_KEY_LEN,
        def_rss_hf,
    };

    rss_conf.rss_hf &= dev_info->flow_type_rss_offloads;
    if (rss_conf.rss_hf != def_rss_hf) {
        LSTACK_LOG(INFO, LSTACK,"modified RSS hash function based on hardware support,"
            "requested:%#"PRIx64" configured:%#"PRIx64"\n", def_rss_hf, rss_conf.rss_hf);
    }

    if (rss_conf.rss_hf) {
        rss_enable = 1;
        conf->rx_adv_conf.rss_conf = rss_conf;
        conf->rxmode.mq_mode = ETH_MQ_RX_RSS;

        LSTACK_LOG(INFO, LSTACK, "set rss_hf: %lx\n", rss_conf.rss_hf);
    }

    return rss_enable;
}

static void rss_setup(const int port_id, const uint16_t nb_queues)
{
    int ret;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rss_reta_entry64 *reta_conf = NULL;
    uint16_t reta_conf_size, i;

    if (rte_eth_dev_info_get(port_id, &dev_info) != 0) {
        return;
    }

    if (nb_queues == 0) {
        return;
    }

    reta_conf_size = dev_info.reta_size / RTE_RETA_GROUP_SIZE;
    if (dev_info.reta_size % RTE_RETA_GROUP_SIZE) {
        reta_conf_size += 1;
    }

    reta_conf = calloc(reta_conf_size, sizeof(struct rte_eth_rss_reta_entry64));
    if (!reta_conf) {
        return;
    }
    for (i = 0; i < dev_info.reta_size; i++) {
        struct rte_eth_rss_reta_entry64 *one_reta_conf =
            &reta_conf[i / RTE_RETA_GROUP_SIZE];
        one_reta_conf->reta[i % RTE_RETA_GROUP_SIZE] = i % nb_queues;
    }

    for (i = 0; i < reta_conf_size; i++) {
        struct rte_eth_rss_reta_entry64 *one_reta_conf = &reta_conf[i];
        one_reta_conf->mask = 0xFFFFFFFFFFFFFFFFULL;
    }

    ret = rte_eth_dev_rss_reta_update(port_id, reta_conf, dev_info.reta_size);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "cannot update rss reta at port %d: %s\n",
            port_id, rte_strerror(-ret));
    }

    free(reta_conf);
}

int32_t dpdk_ethdev_init(void)
{
    uint16_t nb_queues = get_global_cfg_params()->num_cpu;
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    int32_t port_id = ethdev_port_id(get_global_cfg_params()->mac_addr);
    if (port_id < 0) {
        return port_id;
    }

    struct rte_eth_dev_info dev_info;
    int32_t ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "get dev info ret=%d\n", ret);
        return ret;
    }

    int32_t max_queues = LWIP_MIN(dev_info.max_rx_queues, dev_info.max_tx_queues);
    if (max_queues < nb_queues) {
        LSTACK_LOG(ERR, LSTACK, "port_id %d max_queues=%d\n", port_id, max_queues);
        return -EINVAL;
    }

    struct eth_params *eth_params = alloc_eth_params(port_id, nb_queues);
    if (eth_params == NULL) {
        return -ENOMEM;
    }
    eth_params_checksum(&eth_params->conf, &dev_info);
    int32_t rss_enable = eth_params_rss(&eth_params->conf, &dev_info);
    stack_group->eth_params = eth_params;
    stack_group->port_id = eth_params->port_id;
    stack_group->rx_offload = eth_params->conf.rxmode.offloads;
    stack_group->tx_offload = eth_params->conf.txmode.offloads;

    for (uint32_t i = 0; i < stack_group->stack_num; i++) {
	struct protocol_stack *stack = stack_group->stacks[i];
	if (likely(stack)) {
            stack->port_id = stack_group->port_id;
	} else {
            LSTACK_LOG(ERR, LSTACK, "empty stack at stack_num %d\n", i);
	    stack_group->eth_params = NULL;
	    free(eth_params);
	    return -EINVAL;
	}
    }

    ret = rte_eth_dev_configure(port_id, nb_queues, nb_queues, &eth_params->conf);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "cannot config eth dev at port %d: %s\n", port_id, rte_strerror(-ret));
        stack_group->eth_params = NULL;
        free(eth_params);
        return ret;
    }

    ret = dpdk_ethdev_start();
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "dpdk_ethdev_start failed\n");
        stack_group->eth_params = NULL;
        free(eth_params);
        return ret;
    }

    if (rss_enable) {
        rss_setup(port_id, nb_queues);
        stack_group->reta_mask = dev_info.reta_size - 1;
    }
    stack_group->nb_queues = nb_queues;

    return 0;
}

static int32_t dpdk_ethdev_setup(const struct eth_params *eth_params, const struct protocol_stack *stack)
{
    int32_t ret;

    ret = rte_eth_rx_queue_setup(eth_params->port_id, stack->queue_id, eth_params->nb_rx_desc, stack->socket_id,
        &eth_params->rx_conf, stack->rxtx_pktmbuf_pool);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "cannot setup rx_queue %hu: %s\n", stack->queue_id, rte_strerror(-ret));
        return -1;
    }

    ret = rte_eth_tx_queue_setup(eth_params->port_id, stack->queue_id, eth_params->nb_tx_desc, stack->socket_id,
        &eth_params->tx_conf);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "cannot setup tx_queue %hu: %s\n", stack->queue_id, rte_strerror(-ret));
        return -1;
    }

    return 0;
}

int32_t dpdk_ethdev_start(void)
{
    int32_t ret;
    const struct protocol_stack_group *stack_group = get_protocol_stack_group();
    const struct protocol_stack *stack = NULL;

    for (int32_t i = 0; i < stack_group->stack_num; i++) {
        stack = stack_group->stacks[i];

        ret = dpdk_ethdev_setup(stack_group->eth_params, stack);
        if (ret < 0) {
            return ret;
        }
    }

    ret = rte_eth_dev_start(stack_group->eth_params->port_id);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "cannot start ethdev: %d\n", (-ret));
        return ret;
    }

    return 0;
}

int32_t dpdk_init_lstack_kni(void)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    stack_group->kni_pktmbuf_pool = create_pktmbuf_mempool("kni_mbuf", KNI_NB_MBUF, 0, 0);
    if (stack_group->kni_pktmbuf_pool == NULL) {
        return -1;
    }

    int32_t ret = dpdk_kni_init(stack_group->port_id, stack_group->kni_pktmbuf_pool);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

void dpdk_skip_nic_init(void)
{
    /* when lstack init nic again, ltran can't read pkts from nic. unregister pci_bus to avoid init nic in lstack */
    g_pci_bus = rte_bus_find_by_name("pci");
    if (g_pci_bus != NULL) {
        rte_bus_unregister(g_pci_bus);
    }
}

void dpdk_restore_pci(void)
{
    if (g_pci_bus != NULL) {
        rte_bus_register(g_pci_bus);
    }
}

int32_t init_dpdk_ethdev(void)
{
    int32_t ret;

    ret = dpdk_ethdev_init();
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "dpdk_ethdev_init failed\n");
        return -1;
    }

    if (get_global_cfg_params()->kni_switch) {
        ret = dpdk_init_lstack_kni();
        if (ret < 0) {
            return -1;
        }
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    sem_post(&stack_group->ethdev_init);
    return 0;
}

bool port_in_stack_queue(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    if (stack_group->reta_mask == 0 || stack_group->nb_queues <= 1) {
        return true;
    }

    struct rte_ipv4_tuple tuple = {0};
    tuple.src_addr = rte_be_to_cpu_32(src_ip);
    tuple.dst_addr = rte_be_to_cpu_32(dst_ip);
    tuple.sport = src_port;
    tuple.dport = dst_port;

    uint32_t hash = rte_softrss((uint32_t *)&tuple, RTE_THASH_V4_L4_LEN, g_default_rss_key);

    uint32_t reta_index = hash & stack_group->reta_mask;

    struct protocol_stack *stack = get_protocol_stack();
    return (reta_index % stack_group->nb_queues) == stack->queue_id;
}

