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
#include <lwip/posix_api.h>

#include "lstack_log.h"
#include "dpdk_common.h"
#include "lstack_dpdk.h"
#include "lstack_lockless_queue.h"
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
        return -1;
    }

    return 0;
}

void dpdk_eal_init(void)
{
    int32_t ret;
    struct cfg_params *global_params = get_global_cfg_params();

    ret = rte_eal_init(global_params->dpdk_argc, global_params->dpdk_argv);
    if (ret < 0) {
        if (rte_errno == EALREADY)
            LSTACK_PRE_LOG(LSTACK_INFO, "rte_eal_init aleady init\n");
        else
            LSTACK_PRE_LOG(LSTACK_ERR, "rte_eal_init failed init, rte_errno %d\n", rte_errno);

        LSTACK_EXIT(1, "pthread_getaffinity_np failed\n");
    }
    LSTACK_PRE_LOG(LSTACK_INFO, "dpdk_eal_init success\n");
}

static struct rte_mempool *create_pktmbuf_mempool(const char *name, uint32_t nb_mbuf,
    uint32_t mbuf_cache_size, uint16_t queue_id)
{
    int32_t ret;
    char pool_name[PATH_MAX];
    struct rte_mempool *pool;

    ret = snprintf_s(pool_name, sizeof(pool_name), PATH_MAX - 1, "%s_%d", name, queue_id);
    if (ret < 0) {
        return NULL;
    }

    /* time stamp before pbuf_custom as priv_data */
    pool = rte_pktmbuf_pool_create(pool_name, nb_mbuf, mbuf_cache_size,
        sizeof(struct pbuf_custom) + GAZELLE_MBUFF_PRIV_SIZE, MBUF_SZ, rte_socket_id());
    if (pool == NULL) {
        LSTACK_LOG(ERR, LSTACK, "cannot create %s pool rte_err=%d\n", pool_name, rte_errno);
    }
    return pool;
}

static struct rte_mempool *create_rpc_mempool(const char *name, uint16_t queue_id)
{
    char pool_name[PATH_MAX];
    struct rte_mempool *pool;
    int32_t ret;

    ret = snprintf_s(pool_name, sizeof(pool_name), PATH_MAX - 1, "%s_%d", name, queue_id);
    if (ret < 0) {
        return NULL;
    }
    pool = rte_mempool_create(pool_name, CALL_POOL_SZ, sizeof(struct rpc_msg), CALL_CACHE_SZ, 0, NULL, NULL, NULL,
        NULL, rte_socket_id(), 0);
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

    ret = snprintf_s(pool_name, sizeof(pool_name), PATH_MAX - 1, "%s_%d", name, queue_id);
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

    stack->rx_pktmbuf_pool = create_pktmbuf_mempool("rx_mbuf", RX_NB_MBUF / stack_num, RX_MBUF_CACHE_SZ,
        stack->queue_id);
    if (stack->rx_pktmbuf_pool == NULL) {
        return -1;
    }

    stack->tx_pktmbuf_pool = create_pktmbuf_mempool("tx_mbuf", TX_NB_MBUF / stack_num, TX_MBUF_CACHE_SZ,
        stack->queue_id);
    if (stack->tx_pktmbuf_pool == NULL) {
        return -1;
    }

    stack->rpc_pool = create_rpc_mempool("rpc_msg", stack->queue_id);
    if (stack->rpc_pool == NULL) {
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

    stack->weakup_ring = create_ring("SHARED_WEAKUP_RING", VDEV_WEAKUP_QUEUE_SZ, 0, stack->queue_id);
    if (stack->weakup_ring == NULL) {
        return -1;
    }

    stack->send_idle_ring = create_ring("SEND_IDLE_RING", VDEV_IDLE_QUEUE_SZ, 0, stack->queue_id);
    if (stack->send_idle_ring == NULL) {
        return -1;
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
        batch = LWIP_MIN(remain, FREE_RX_QUEUE_SZ);

	ret = gazelle_alloc_pktmbuf(mempool, free_buf, batch);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "cannot alloc mbuf for ring, count: %d ret=%d\n", (int32_t)batch, ret);
            return -1;
        }

        ret = rte_ring_en_enqueue_bulk(ring, (void **)free_buf, batch);
        if (ret == 0) {
            LSTACK_LOG(ERR, LSTACK, "cannot enqueue to ring, count: %d\n", (int32_t)batch);
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
        if (!memcmp(mac, mac_addr.addr_bytes, RTE_ETHER_ADDR_LEN)) {
            break;
        }
        LSTACK_LOG(INFO, LSTACK, "nic mac:%02x:%02x:%02x:%02x:%02x:%02x not match\n",
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
    struct eth_params *eth_params = malloc(sizeof(struct eth_params));
    if (eth_params == NULL) {
        return NULL;
    }
    memset_s(eth_params, sizeof(struct eth_params), 0, sizeof(*eth_params));

    eth_params->port_id = port_id;
    eth_params->nb_queues = nb_queues;
    eth_params->nb_rx_desc = RTE_TEST_RX_DESC_DEFAULT;
    eth_params->nb_tx_desc = RTE_TEST_TX_DESC_DEFAULT;
    eth_params->conf.link_speeds = ETH_LINK_SPEED_AUTONEG;
    eth_params->conf.txmode.mq_mode = ETH_MQ_TX_NONE;
    eth_params->conf.rxmode.mq_mode = ETH_MQ_RX_NONE;

    return eth_params;
}

static int eth_params_checksum(struct rte_eth_conf *conf, struct rte_eth_dev_info *dev_info)
{
    uint64_t rx_ol = 0;
    uint64_t tx_ol = 0;

    uint64_t rx_ol_capa = dev_info->rx_offload_capa;
    uint64_t tx_ol_capa = dev_info->tx_offload_capa;

    // rx ip
    if (rx_ol_capa & DEV_RX_OFFLOAD_IPV4_CKSUM) {
#if CHECKSUM_CHECK_IP_HW
        rx_ol |= DEV_RX_OFFLOAD_IPV4_CKSUM;
	LSTACK_LOG(INFO, LSTACK, "DEV_RX_OFFLOAD_IPV4_CKSUM\n");
#endif
    }

    // rx tcp
    if (rx_ol_capa & DEV_RX_OFFLOAD_TCP_CKSUM) {
#if CHECKSUM_CHECK_TCP_HW
        rx_ol |= DEV_RX_OFFLOAD_TCP_CKSUM;
        LSTACK_LOG(INFO, LSTACK, "DEV_RX_OFFLOAD_TCP_CKSUM\n");
#endif
    }

    // tx ip
    if (tx_ol_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) {
#if CHECKSUM_GEN_IP_HW
        tx_ol |= DEV_TX_OFFLOAD_IPV4_CKSUM;
        LSTACK_LOG(INFO, LSTACK, "DEV_TX_OFFLOAD_IPV4_CKSUM\n");
#endif
    }

    // tx tcp
    if (tx_ol_capa & DEV_TX_OFFLOAD_TCP_CKSUM) {
#if CHECKSUM_GEN_TCP_HW
        tx_ol |= DEV_TX_OFFLOAD_TCP_CKSUM;
        LSTACK_LOG(INFO, LSTACK, "DEV_TX_OFFLOAD_TCP_CKSUM\n");
#endif
    }

    conf->rxmode.offloads = rx_ol;
    conf->txmode.offloads = tx_ol;

#if CHECKSUM_CHECK_IP_HW || CHECKSUM_CHECK_TCP_HW || CHECKSUM_GEN_IP_HW || CHECKSUM_GEN_TCP_HW
    LSTACK_LOG(INFO, LSTACK, "set checksum offloads\n");
#endif

    return 0;
}

static int eth_params_rss(struct rte_eth_conf *conf, struct rte_eth_dev_info *dev_info)
{
    int rss_enable = 0;
    uint64_t def_rss_hf = ETH_RSS_TCP | ETH_RSS_IP;
    struct rte_eth_rss_conf rss_conf = {
        NULL,
        40,
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

static int rss_setup(const int port_id, const uint16_t nb_queues)
{
    int i;
    int ret;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rss_reta_entry64 *reta_conf = NULL;

    rte_eth_dev_info_get(port_id, &dev_info);

    if (nb_queues == 0) {
        return ERR_VAL;
    }

    reta_conf = calloc(dev_info.reta_size / RTE_RETA_GROUP_SIZE,
                       sizeof(struct rte_eth_rss_reta_entry64));
    if (!reta_conf) {
        return ERR_MEM;
    }
    for (i = 0; i < dev_info.reta_size; i++) {
        struct rte_eth_rss_reta_entry64 *one_reta_conf =
            &reta_conf[i / RTE_RETA_GROUP_SIZE];
        one_reta_conf->reta[i % RTE_RETA_GROUP_SIZE] = i % nb_queues;
    }

    for (i = 0; i < dev_info.reta_size / RTE_RETA_GROUP_SIZE; i++) {
        struct rte_eth_rss_reta_entry64 *one_reta_conf = &reta_conf[i];
        one_reta_conf->mask = 0xFFFFFFFFFFFFFFFFULL;
    }

    ret = rte_eth_dev_rss_reta_update(port_id, reta_conf, dev_info.reta_size);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "cannot update rss reta at port %d: %s\n",
            port_id, rte_strerror(-ret));
    }

    free(reta_conf);
    return ERR_OK;
}

int32_t dpdk_ethdev_init(void)
{
    uint16_t nb_queues = get_global_cfg_params()->num_cpu;

    int32_t port_id = ethdev_port_id(get_global_cfg_params()->ethdev.addr_bytes);
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
        LSTACK_LOG(ERR, LSTACK, "port_id %u max_queues=%d\n", port_id, max_queues);
        return -EINVAL;
    }

    struct eth_params *eth_params = alloc_eth_params(port_id, nb_queues);
    if (eth_params == NULL) {
        return -ENOMEM;
    }
    eth_params_checksum(&eth_params->conf, &dev_info);
    int32_t rss_enable = eth_params_rss(&eth_params->conf, &dev_info);
    get_protocol_stack_group()->eth_params = eth_params;
    get_protocol_stack_group()->port_id = eth_params->port_id;

    ret = rte_eth_dev_configure(port_id, nb_queues, nb_queues, &eth_params->conf);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "cannot config eth dev at port %d: %s\n", port_id, rte_strerror(-ret));
        return ret;
    }

    if (rss_enable) {
        rss_setup(port_id, nb_queues);
    }

    return ERR_OK;
}

static int32_t dpdk_ethdev_setup(const struct eth_params *eth_params, const struct protocol_stack *stack)
{
    int32_t ret;

    ret = rte_eth_rx_queue_setup(eth_params->port_id, stack->queue_id, eth_params->nb_rx_desc, stack->socket_id,
        &eth_params->rx_conf, stack->rx_pktmbuf_pool);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "cannot setup rx_queue %d: %s\n", stack->queue_id, rte_strerror(-ret));
        return -1;
    }

    ret = rte_eth_tx_queue_setup(eth_params->port_id, stack->queue_id, eth_params->nb_tx_desc, stack->socket_id,
        &eth_params->tx_conf);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "cannot setup tx_queue %d: %s\n", stack->queue_id, rte_strerror(-ret));
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

static void set_kni_ip_mac(uint16_t port_id)
{
    struct cfg_params *cfg = get_global_cfg_params();

    int32_t fd = posix_api->socket_fn(AF_INET, SOCK_DGRAM, 0);
    struct ifreq set_ifr = {0};
    struct sockaddr_in *sin = (struct sockaddr_in *)&set_ifr.ifr_addr;

    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = cfg->host_addr.addr;
    strcpy_s(set_ifr.ifr_name, sizeof(set_ifr.ifr_name), GAZELLE_KNI_NAME);
    int32_t ret = posix_api->ioctl_fn(fd, SIOCSIFADDR, &set_ifr);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "set kni ip=%u fail\n", cfg->host_addr.addr);
    }

    posix_api->close_fn(fd);
}

int32_t dpdk_init_lstack_kni(void)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    stack_group->kni_pktmbuf_pool = create_pktmbuf_mempool("kni_mbuf", KNI_NB_MBUF, KNI_MBUF_CACHE_SZ, 0);
    if (stack_group->kni_pktmbuf_pool == NULL) {
        return -1;
    }

    int32_t ret = dpdk_kni_init(stack_group->port_id, stack_group->kni_pktmbuf_pool);
    if (ret < 0) {
        return -1;
    }

    set_kni_ip_mac(stack_group->port_id);

    return 0;
}

void dpdk_skip_nic_init(void)
{
    /* when lstack init nic again, ltran can't read pkts from nic. unregister pci_bus to avoid init nic in lstack */
    struct rte_bus *pci_bus = rte_bus_find_by_name("pci");
    if (pci_bus != NULL) {
        rte_bus_unregister(pci_bus);
    }
}

