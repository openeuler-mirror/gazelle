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

#include <sched.h>
#include <stdbool.h>
#include <securec.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <numa.h>

#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_bus.h>
#include <rte_errno.h>
#include <rte_version.h>
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
#include <rte_kni.h>
#endif
#include <rte_pdump.h>
#include <rte_thash.h>
#include <rte_eth_bond_8023ad.h>
#include <rte_eth_bond.h>
#include <rte_ethdev.h>

#include <lwip/pbuf.h>
#include <lwip/lwipgz_flow.h>

#include "lstack_log.h"
#include "common/dpdk_common.h"
#include "common/gazelle_base_func.h"
#include "lstack_protocol_stack.h"
#include "lstack_cfg.h"
#include "lstack_virtio.h"
#include "lstack_dpdk.h"
#include "mbox_ring.h"

struct eth_params {
    uint16_t port_id;

    uint16_t nb_queues;
    uint16_t nb_rx_desc;
    uint16_t nb_tx_desc;

    uint32_t reta_mask;

    struct rte_eth_conf conf;
    struct rte_eth_rxconf rx_conf;
    struct rte_eth_txconf tx_conf;
};

static struct eth_params g_eth_params;
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
struct rte_kni;
static struct rte_bus *g_pci_bus = NULL;
#endif

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
    int ret = 0;
    if (first_flags) {
        CPU_ZERO(&cpuset);
        ret = pthread_getaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "pthread_getaffinity_np fail ret=%d\n", ret);
            return -1;
        }
        first_flags = false;
    } else {
        /* cancel the core binding from DPDK initialization */
        ret = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "pthread_setaffinity_np fail ret=%d\n", ret);
            return -1;
        }
    }
    return 0;
}

int32_t dpdk_eal_init(void)
{
    int32_t ret;
    struct cfg_params *global_params = get_global_cfg_params();

    ret = rte_eal_init(global_params->dpdk_argc, global_params->dpdk_argv);
    /* rte_eal_init() would call __rte_thread_init(), and set _lcore_id. */
    RTE_PER_LCORE(_lcore_id) = LCORE_ID_ANY;
    if (ret < 0) {
        if (rte_errno == EALREADY) {
            LSTACK_PRE_LOG(LSTACK_INFO, "rte_eal_init aleady init\n");
            /* maybe other program inited, merge init param share init */
            ret = 0;
        } else {
            LSTACK_PRE_LOG(LSTACK_ERR, "rte_eal_init failed init, rte_errno %d\n", rte_errno);
        return ret;
        }
    } else {
        LSTACK_PRE_LOG(LSTACK_INFO, "dpdk_eal_init success\n");
    }

    if (get_global_cfg_params()->is_primary) {
        ret = rte_pdump_init();
        if (ret < 0) {
            LSTACK_PRE_LOG(LSTACK_ERR, "rte_pdump_init failed init, rte_errno %d\n", rte_errno);
	    /* We do not care whether the pdump is successfully loaded. So, just print an alarm. */
        } else {
            LSTACK_PRE_LOG(LSTACK_INFO, "rte_pdump_init success\n");
        }
    }

    return ret;
}

static struct reg_ring_msg *create_reg_mempool(const char *name, uint16_t queue_id)
{
    int ret;
    char pool_name[PATH_MAX];
    struct reg_ring_msg *reg_buf;

    ret = snprintf_s(pool_name, sizeof(pool_name), PATH_MAX - 1, "%s_%hu", name, queue_id);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "snprintf_s fail ret=%d\n", ret);
        return NULL;
    }

    reg_buf = rte_malloc(name, VDEV_REG_QUEUE_SZ * sizeof(struct reg_ring_msg), RTE_CACHE_LINE_SIZE);
    if (reg_buf == NULL) {
        LSTACK_LOG(ERR, LSTACK, "cannot create %s pool rte_err=%d.\n", pool_name, rte_errno);
    }

    return reg_buf;
}

int32_t create_shared_ring(struct protocol_stack *stack)
{
    if (!use_ltran()) {
        return 0;
    }

    stack->rx_ring = rte_ring_create_fast("RING_RX", VDEV_RX_QUEUE_SZ, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (stack->rx_ring == NULL) {
        return -1;
    }

    stack->tx_ring = rte_ring_create_fast("RING_TX", VDEV_TX_QUEUE_SZ, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (stack->tx_ring == NULL) {
        return -1;
    }

    stack->reg_ring = rte_ring_create_fast("SHARED_REG_RING", VDEV_REG_QUEUE_SZ, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (stack->reg_ring == NULL) {
        return -1;
    }

    stack->reg_buf = create_reg_mempool("reg_ring_msg", stack->queue_id);
    if (stack->reg_buf == NULL) {
        LSTACK_LOG(ERR, LSTACK, "reg_buf is NULL\n");
        return -1;
    }

    return 0;
}

int32_t fill_mbuf_to_ring(int stack_id, struct rte_ring *ring, uint32_t mbuf_num)
{
    int32_t ret;
    uint32_t batch;
    uint32_t remain = mbuf_num;
    struct rte_mbuf *free_buf[VDEV_RX_QUEUE_SZ];

    while (remain > 0) {
        batch = LWIP_MIN(remain, RING_SIZE(VDEV_RX_QUEUE_SZ));

        ret = mem_get_mbuf_bulk(stack_id, free_buf, batch, true);
        if (ret == 0) {
            LSTACK_LOG(ERR, LSTACK, "cannot alloc mbuf for ring, count: %u ret=%d\n", batch, ret);
            return -1;
        }

        ret = gazelle_ring_sp_enqueue(ring, (void **)free_buf, batch);
        if (ret < batch) {
            mem_put_mbuf_bulk(&free_buf[ret], batch - ret);
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

static int32_t pci_to_port_id(struct rte_pci_addr *pci_addr)
{
    uint16_t port_id;
    char device_name[RTE_DEV_NAME_MAX_LEN] = "";

    rte_pci_device_name(pci_addr, device_name, RTE_DEV_NAME_MAX_LEN);

    int ret = rte_eth_dev_get_port_by_name(device_name, &port_id);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "match failed: no NIC matches cfg:%04x:%02x:%02x.%x\n",
            pci_addr->domain, pci_addr->bus, pci_addr->devid, pci_addr->function);
        return -EINVAL;
    }

    return port_id;
}

static int eth_params_rss(struct rte_eth_conf *conf, struct rte_eth_dev_info *dev_info)
{
    int rss_enable = 0;
    uint64_t def_rss_hf = RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_IP;
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
        conf->rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;

        LSTACK_LOG(INFO, LSTACK, "set rss_hf: %lx\n", rss_conf.rss_hf);
    }

    return rss_enable;
}

static int eth_params_init(struct eth_params *eth_params, uint16_t port_id, uint16_t nb_queues, int *rss_enable)
{
    struct rte_eth_dev_info dev_info;
    int ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "get dev info ret=%d\n", ret);
        return ret;
    }

    int32_t max_queues = LWIP_MIN(dev_info.max_rx_queues, dev_info.max_tx_queues);
    if (max_queues < nb_queues) {
        LSTACK_LOG(ERR, LSTACK, "port_id %d max_queues=%d\n", port_id, max_queues);
        return -EINVAL;
    }

    memset_s(eth_params, sizeof(struct eth_params), 0, sizeof(struct eth_params));

    eth_params->port_id = port_id;
    eth_params->nb_queues = nb_queues;
    eth_params->nb_rx_desc = get_global_cfg_params()->rxqueue_size;
    eth_params->nb_tx_desc = get_global_cfg_params()->txqueue_size;
    eth_params->conf.link_speeds = RTE_ETH_LINK_SPEED_AUTONEG;
    eth_params->conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    eth_params->conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    /* used for tcp port alloc */
    eth_params->reta_mask = dev_info.reta_size - 1;
    eth_params->conf.intr_conf.rxq = get_global_cfg_params()->stack_interrupt;

    eth_params_checksum(&eth_params->conf, &dev_info);

    if (!get_global_cfg_params()->tuple_filter) {
        *rss_enable = eth_params_rss(&eth_params->conf, &dev_info);
    } else {
        *rss_enable = 0;
    }

    return 0;
}

uint64_t get_eth_params_rx_ol(void)
{
    return get_protocol_stack_group()->rx_offload;
}

uint64_t get_eth_params_tx_ol(void)
{
    return get_protocol_stack_group()->tx_offload;
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

    reta_conf_size = dev_info.reta_size / RTE_ETH_RETA_GROUP_SIZE;
    if (dev_info.reta_size % RTE_ETH_RETA_GROUP_SIZE) {
        reta_conf_size += 1;
    }

    reta_conf = calloc(reta_conf_size, sizeof(struct rte_eth_rss_reta_entry64));
    if (!reta_conf) {
        return;
    }
    for (i = 0; i < dev_info.reta_size; i++) {
        struct rte_eth_rss_reta_entry64 *one_reta_conf =
            &reta_conf[i / RTE_ETH_RETA_GROUP_SIZE];
        one_reta_conf->reta[i % RTE_ETH_RETA_GROUP_SIZE] = i % nb_queues;
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

int32_t dpdk_bond_primary_set(int port_id, int *slave_port_id, int count)
{
    int32_t primary_port_id = ethdev_port_id(get_global_cfg_params()->mac_addr);
    if (primary_port_id < 0) {
        LSTACK_LOG(ERR, LSTACK, "cannot get the port id of the cfg\n");
        return -1;
    }
    for (int i = 0; i < count; i++) {
        if (slave_port_id[i] == primary_port_id) {
            int32_t ret = rte_eth_bond_primary_set(port_id, primary_port_id);
            if (ret != 0) {
                LSTACK_LOG(ERR, LSTACK, "dpdk set bond primary port failed ret = %d\n", ret);
                return -1;
            }
            return ret;
        }
    }
    LSTACK_LOG(ERR, LSTACK, "cfg: devices must be in bond_slave_mac for BONDING_MODE_ACTIVE_BACKUP.\n");
    return -1;
}

int32_t dpdk_ethdev_init(int port_id)
{
    int ret;
    int32_t rss_enable = 0;
    uint16_t nb_queues = get_global_cfg_params()->num_cpu;

    if (!use_ltran()) {
        nb_queues = get_global_cfg_params()->tot_queue_num;
    }

    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    ret = eth_params_init(&g_eth_params, port_id, nb_queues, &rss_enable);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "eth_params_init failed ret=%d\n", ret);
        return ret;
    }

    stack_group->eth_params = &g_eth_params;
    stack_group->rx_offload = g_eth_params.conf.rxmode.offloads;
    stack_group->tx_offload = g_eth_params.conf.txmode.offloads;
    stack_group->port_id = port_id;

    if (get_global_cfg_params()->is_primary) {
        ret = rte_eth_dev_configure(port_id, nb_queues, nb_queues, &stack_group->eth_params->conf);
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "cannot config eth dev at port %d: %s\n", port_id, rte_strerror(-ret));
            return ret;
        }

        ret = dpdk_ethdev_start();
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "dpdk_ethdev_start failed ret=%d\n", ret);
            return ret;
        }

        if (rss_enable && !get_global_cfg_params()->tuple_filter) {
            rss_setup(port_id, nb_queues);
        }
    }

    /* after rte_eth_dev_configure */
    if ((get_global_cfg_params()->vlan_mode != -1) &&
        ((stack_group->rx_offload & RTE_ETH_RX_OFFLOAD_VLAN_FILTER) == RTE_ETH_RX_OFFLOAD_VLAN_FILTER)) {
        /*
         * vlan filter can be configured for switch,nic and software.
         * bond4/6 mode need enable promiscuous mode, it conflicts with nic vlan filter.
         * therefore, we can't use nic vlan filter in bond4/6 mode.
         * 1. use software: need disable vlan strip in nic, the corresponding GRO becomes invalid
         *    GRO does not support vlan pakckets, which affects performance.
         * 2. use switch: it's a good config
         */
        if ((get_global_cfg_params()->bond_mode != BONDING_MODE_8023AD) &&
            (get_global_cfg_params()->bond_mode != BONDING_MODE_ALB)) {
            ret = rte_eth_dev_vlan_filter(port_id, get_global_cfg_params()->vlan_mode, 1);
            if (ret != 0) {
                LSTACK_LOG(ERR, LSTACK, "dpdk add vlan filter failed ret = %d\n", ret);
                return -1;
            }
        } else {
            LSTACK_LOG(ERR, LSTACK, "bond4 and bond6 not support set vlan filter in nic\n");
        }
    }

    rte_eth_allmulticast_enable(port_id);

    return 0;
}

static int32_t dpdk_ethdev_setup(const struct eth_params *eth_params, uint16_t idx)
{
    int32_t ret;
    uint16_t numa_id = 0;
    struct cfg_params *cfg = get_global_cfg_params();
    struct rte_mempool *rxtx_mbuf_pool = mem_get_mbuf_pool(idx);

    if (!cfg->use_ltran && cfg->num_process == 1) {
        numa_id = (cfg->stack_num > 0) ? cfg->numa_id : numa_node_of_cpu(cfg->cpus[idx]);
    } else {
        numa_id = cfg->process_numa[idx];
    }
    ret = rte_eth_rx_queue_setup(eth_params->port_id, idx, eth_params->nb_rx_desc, numa_id,
        &eth_params->rx_conf, rxtx_mbuf_pool);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "cannot setup rx_queue %hu: %s\n", idx, rte_strerror(-ret));
        return -1;
    }

    ret = rte_eth_tx_queue_setup(eth_params->port_id, idx, eth_params->nb_tx_desc, numa_id,
        &eth_params->tx_conf);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "cannot setup tx_queue %hu: %s\n", idx, rte_strerror(-ret));
        return -1;
    }

    return 0;
}

int32_t dpdk_ethdev_start(void)
{
    int i;
    int32_t ret;
    const struct protocol_stack_group *stack_group = get_protocol_stack_group();

    for (i = 0; i < get_global_cfg_params()->tot_queue_num; i++) {
        ret = dpdk_ethdev_setup(stack_group->eth_params, i);
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "dpdk_ethdev_setup fail queueid=%d, ret=%d\n", i, ret);
            return ret;
        }
    }

    ret = rte_eth_dev_start(stack_group->eth_params->port_id);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "cannot start ethdev: %d\n", (-ret));
        return ret;
    }

    /* after rte_eth_dev_start */
    for (i = 0; i < get_global_cfg_params()->tot_queue_num; i++) {
        struct intr_dpdk_event_args intr_arg;
        intr_arg.port_id = stack_group->eth_params->port_id;
        intr_arg.queue_id = i;
        intr_register(i, INTR_DPDK_EVENT, &intr_arg);
    }

    return 0;
}

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
int32_t dpdk_init_lstack_kni(void)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();
    stack_group->kni_pktmbuf_pool = rte_pktmbuf_pool_create("kni_mbuf", KNI_NB_MBUF, 0, 0, MBUF_DATA_SIZE, rte_socket_id());
    if (stack_group->kni_pktmbuf_pool == NULL) {
        LSTACK_LOG(ERR, LSTACK, "kni_mbuf is NULL\n");
        return -1;
    }

    int32_t ret = dpdk_kni_init(stack_group->port_id, stack_group->kni_pktmbuf_pool);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "dpdk_kni_init fail ret=%d\n", ret);
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
#endif

static int dpdk_bond_create(uint8_t mode, int *slave_port_id, int count)
{
    int port_id = rte_eth_bond_create("net_bonding0", mode, rte_socket_id());
    struct cfg_params *cfg = get_global_cfg_params();
    int ret;

    if (port_id < 0) {
        LSTACK_LOG(ERR, LSTACK, "get bond port id failed ret=%d\n", port_id);
        return -1;
    }

    for (int i = 0; i < count; i++) {
               /* rte_dev_info_get can get correct devinfo after call bond_member_add */
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
        ret = rte_eth_bond_slave_add(port_id, slave_port_id[i]);
#else
        ret = rte_eth_bond_member_add(port_id, slave_port_id[i]);
#endif
        if (ret < 0) {
           LSTACK_LOG(ERR, LSTACK, "bond add slave devices failed, ret=%d\n", ret);
            return -1;
        }
    }

    if (cfg->bond_mode == BONDING_MODE_ACTIVE_BACKUP) {
        ret = dpdk_bond_primary_set(port_id, slave_port_id, count);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "dpdk set bond primary port failed ret = %d\n", ret);
            return -1;
        }
    }

    if (cfg->bond_mode == BONDING_MODE_8023AD) {
        ret = rte_eth_bond_8023ad_dedicated_queues_enable(port_id);
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "dpdk enable 8023 dedicated queues failed ret = %d\n", ret);
            return -1;
        }
    }

    if (dpdk_ethdev_init(port_id) < 0) {
        LSTACK_LOG(ERR, LSTACK, "dpdk_ethdev_init failed for bond port\n");
           return -1;
    }

    ret = rte_eth_bond_xmit_policy_set(port_id, BALANCE_XMIT_POLICY_LAYER34);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "dpdk set bond xmit policy failed ret = %d\n", ret);
        return -1;
    }

    ret = rte_eth_bond_link_monitoring_set(port_id, get_global_cfg_params()->bond_miimon);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "dpdk set bond link monitoring failed ret = %d\n", ret);
        return -1;
    }

    if ((cfg->bond_mode == BONDING_MODE_8023AD) || (cfg->bond_mode == BONDING_MODE_ALB)) {
        for (int i = 0; i < count; i++) {
            /* bond port promiscuous only enable primary port */
            /* we enable all ports */
            ret = rte_eth_promiscuous_enable(slave_port_id[i]);
            if (ret != 0) {
                LSTACK_LOG(ERR, LSTACK, "dpdk slave enable promiscuous failed ret = %d\n", ret);
                return -1;
            }
        }
    }

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "dpdk start bond port failed ret = %d\n", ret);
        return -1;
    }

    return 0;
}

int init_dpdk_ethdev(void)
{
    int ret;
    int slave_port_id[GAZELLE_MAX_BOND_NUM];
    int port_id = 0;
    struct cfg_params *cfg = get_global_cfg_params();
    int i;

    if (cfg->bond_mode >= 0) {
        for (i = 0; i < GAZELLE_MAX_BOND_NUM; i++) {
            if (cfg->bond_slave_addr[i].addr_type == DEV_ADDR_TYPE_EMPTY) {
                break;
            } else if (cfg->bond_slave_addr[i].addr_type == DEV_ADDR_TYPE_MAC) {
                slave_port_id[i] = ethdev_port_id(cfg->bond_slave_addr[i].addr.mac_addr.addr_bytes);
            } else {
                slave_port_id[i] = pci_to_port_id(&cfg->bond_slave_addr[i].addr.pci_addr);
            }
            if (slave_port_id[i] < 0) {
                LSTACK_LOG(ERR, LSTACK, "cfg->bond_slave_addr[%d] parsing failed.\n", i);
                return -1;
            }
            ret = dpdk_ethdev_init(slave_port_id[i]);
            if (ret < 0) {
                LSTACK_LOG(ERR, LSTACK, "slave port(%d) init failed, ret=%d\n", slave_port_id[i], ret);
                return -1;
            }
        }

        ret = dpdk_bond_create(cfg->bond_mode, slave_port_id, i);
        if (ret < 0) {
            LSTACK_LOG(ERR, LSTACK, "bond device create failed, ret=%d\n", ret);
            return -1;
        }
        port_id = rte_eth_bond_primary_get(get_protocol_stack_group()->port_id);
    } else {
        struct rte_eth_dev_info dev_info;
        port_id = ethdev_port_id(cfg->mac_addr);
        if (port_id < 0) {
            return -1;
        }

        if (rte_eth_dev_info_get(port_id, &dev_info) < 0) {
            return -1;
        }
        if (strcmp(dev_info.driver_name, "net_hinic") == 0 &&
            get_global_cfg_params()->stack_interrupt == true) {
            LSTACK_LOG(ERR, LSTACK, "hinic not support interrupt mode\n");
            return -1;
        }

        ret = dpdk_ethdev_init(port_id);
        if (ret != 0) {
            LSTACK_LOG(ERR, LSTACK, "dpdk_ethdev_init failed, port id=%d\n", port_id);
            return -1;
        }
    }

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
    if (cfg->kni_switch && cfg->is_primary) {
        ret = dpdk_init_lstack_kni();
        if (ret < 0) {
            return -1;
        }
    }
#endif
    if (cfg->flow_bifurcation) {
        if (cfg->kni_switch) {
            LSTACK_LOG(ERR, LSTACK, "flow_bifurcation and kni_switch cannot both be enabled, please check them\n");
            return -1;
        }
        if (virtio_port_create(port_id) != 0) {
            return -1;
        }
    }

    return 0;
}

bool port_in_stack_queue(gz_addr_t *src_ip, gz_addr_t *dst_ip, uint16_t src_port, uint16_t dst_port)
{
    struct protocol_stack_group *stack_group = get_protocol_stack_group();

    /* ltran mode */
    if (stack_group->eth_params == NULL) {
        return true;
    }

    if (stack_group->eth_params->reta_mask == 0 || stack_group->eth_params->nb_queues <= 1) {
        return true;
    }

    union rte_thash_tuple tuple;
    uint32_t hash = 0;
    if (IP_IS_V4_VAL(*src_ip)) {
        tuple.v4.src_addr = rte_be_to_cpu_32(src_ip->u_addr.ip4.addr);
        tuple.v4.dst_addr = rte_be_to_cpu_32(dst_ip->u_addr.ip4.addr);
        tuple.v4.sport = src_port;
        tuple.v4.dport = dst_port;
        hash = rte_softrss((uint32_t *)&tuple, RTE_THASH_V4_L4_LEN, g_default_rss_key);
    } else {
        int i;
        for (i = 0; i < 4; i++) {
            *((uint32_t *)tuple.v6.src_addr + i) = rte_be_to_cpu_32(*(src_ip->u_addr.ip6.addr + i));
            *((uint32_t *)tuple.v6.dst_addr + i) = rte_be_to_cpu_32(*(dst_ip->u_addr.ip6.addr + i));
        }
        tuple.v6.sport = src_port;
        tuple.v6.dport = dst_port;
        hash = rte_softrss((uint32_t *)&tuple, RTE_THASH_V6_L4_LEN, g_default_rss_key);
    }

    uint32_t reta_index = hash & stack_group->eth_params->reta_mask;

    struct protocol_stack *stack = get_protocol_stack();
    return (reta_index % stack_group->eth_params->nb_queues) == stack->queue_id;
}

static int dpdk_nic_xstats_value_get(uint64_t *values, unsigned int len, uint16_t *ports, unsigned int count)
{
    uint64_t tmp_values[RTE_ETH_XSTATS_MAX_LEN];
    int p_idx;
    int v_idx;
    int ret;
 
    for (p_idx = 0; p_idx < count; p_idx++) {
        ret = rte_eth_xstats_get_by_id(ports[p_idx], NULL, tmp_values, len);
        if (ret < 0 || ret > len)  {
            LSTACK_LOG(ERR, LSTACK, "rte_eth_xstats_get_by_id failed.\n");
            return -1;
        }

        for (v_idx = 0; v_idx < len; v_idx++) {
            values[v_idx] += tmp_values[v_idx];
        }
    }
    return 0;
}

static int dpdk_nic_xstats_name_get(struct nic_eth_xstats_name *names, uint16_t port_id)
{
    int len;

    len = rte_eth_xstats_get_names_by_id(port_id, NULL, 0, NULL);
    if (len < 0) {
        LSTACK_LOG(ERR, LSTACK, "rte_eth_xstats_get_names_by_id failed.\n");
        return -1;
    }

    if (len != rte_eth_xstats_get_names_by_id(port_id, (struct rte_eth_xstat_name *)names, len, NULL)) {
        LSTACK_LOG(ERR, LSTACK, "rte_eth_xstats_get_names_by_id failed.\n");
        return -1;
    }

    return len;
}

void dpdk_nic_bond_xstats_get(struct gazelle_stack_dfx_data *dfx, uint16_t port_id, uint16_t *slaves, int count)
{
    dfx->data.nic_xstats.bonding.mode = rte_eth_bond_mode_get(port_id);
    if (dfx->data.nic_xstats.bonding.mode < 0) {
        LSTACK_LOG(ERR, LSTACK, "rte_eth_bond_mode_get failed.\n");
        return;
    }

    dfx->data.nic_xstats.bonding.primary_port_id = rte_eth_bond_primary_get(port_id);
    if (dfx->data.nic_xstats.bonding.primary_port_id < 0) {
        LSTACK_LOG(ERR, LSTACK, "rte_eth_bond_primary_get failed.\n");
        return;
    }

    dfx->data.nic_xstats.bonding.miimon = rte_eth_bond_link_monitoring_get(port_id);
    if (dfx->data.nic_xstats.bonding.miimon <= 0) {
        LSTACK_LOG(ERR, LSTACK, "rte_eth_bond_link_monitoring_get failed.\n");
        return;
    }

    dfx->data.nic_xstats.bonding.slave_count = count;

    for (int i = 0; i < count; i++) {
        dfx->data.nic_xstats.bonding.slaves[i] = slaves[i];
    }
}

void dpdk_nic_xstats_get(struct gazelle_stack_dfx_data *dfx, uint16_t port_id)
{
    struct rte_eth_dev_info dev_info;
    int len;
    int ret;

    dfx->data.nic_xstats.len = -1;
    dfx->data.nic_xstats.port_id = port_id;
    dfx->data.nic_xstats.bonding.mode = -1;
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "rte_eth_dev_info_get failed.\n");
        return;
    }

    /* bond not support get xstats, we get xstats from slave device of bond */
    if (strcmp(dev_info.driver_name, "net_bonding") == 0) {
        uint16_t slaves[RTE_MAX_ETHPORTS];
        int slave_count;
#if RTE_VERSION >= RTE_VERSION_NUM(23, 11, 0, 0)
        slave_count = rte_eth_bond_members_get(port_id, slaves, RTE_MAX_ETHPORTS);
#else
        slave_count = rte_eth_bond_slaves_get(port_id, slaves, RTE_MAX_ETHPORTS);
#endif
        if (slave_count <= 0) {
            LSTACK_LOG(ERR, LSTACK, "rte_eth_bond_slaves_get failed.\n");
            return;
        }
        len = dpdk_nic_xstats_name_get(dfx->data.nic_xstats.xstats_name, slaves[0]);
        if (len <= 0) {
            return;
        }
        if (dpdk_nic_xstats_value_get(dfx->data.nic_xstats.values, len, slaves, slave_count) != 0) {
            return;
        }
        dpdk_nic_bond_xstats_get(dfx, port_id, slaves, slave_count);
    } else {
        len = dpdk_nic_xstats_name_get(dfx->data.nic_xstats.xstats_name, port_id);
        if (len <= 0) {
            return;
        }
        if (dpdk_nic_xstats_value_get(dfx->data.nic_xstats.values, len, &port_id, 1) != 0) {
            return;
        }
    }
    dfx->data.nic_xstats.len = len;
}

void dpdk_nic_features_get(struct gazelle_stack_dfx_data *dfx, uint16_t port_id)
{
    int ret;
    struct rte_eth_conf dev_conf;

    ret = rte_eth_dev_conf_get(port_id, &dev_conf);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "rte_eth_dev_conf_get failed:%d.\n", ret);
        return;
    }

    dfx->data.nic_features.port_id = port_id;
    dfx->data.nic_features.tx_offload = dev_conf.txmode.offloads;
    dfx->data.nic_features.rx_offload = dev_conf.rxmode.offloads;
    return;
}

uint32_t dpdk_pktmbuf_mempool_num(void)
{
    struct cfg_params *cfg = get_global_cfg_params();

    return (MBUFPOOL_RESERVE_NUM + MBUFPOOL_CACHE_NUM +
            cfg->rxqueue_size + cfg->txqueue_size +
            (cfg->tcp_conn_count * cfg->mbuf_count_per_conn) / cfg->num_queue);
}

uint32_t dpdk_total_socket_memory(void)
{
    uint32_t elt_size = 0;
    uint32_t per_pktmbuf_mempool_size = 0;
    uint32_t per_rpc_mempool_size = 0;
    uint32_t per_conn_ring_size = 0;
    /* the actual fixed memory is about 50M, and 100M is reserved here.
     * including all hugepages memory used by lwip.
     */
    uint32_t fixed_mem = 100;
    uint32_t total_socket_memory = 0;
    struct cfg_params *cfg = get_global_cfg_params();

    /* calculate the memory(bytes) of rxtx_mempool */
    elt_size = sizeof(struct rte_mbuf) + MBUF_DATA_SIZE + RTE_ALIGN(sizeof(struct mbuf_private), RTE_CACHE_LINE_SIZE);
    per_pktmbuf_mempool_size = rte_mempool_calc_obj_size(elt_size, 0, NULL);
    
    /* calculate the memory(bytes) of rpc_mempool, reserved num is (app threads + lstack threads + listen thread) */
    elt_size = sizeof(struct rpc_msg);
    per_rpc_mempool_size = rte_mempool_calc_obj_size(elt_size, 0, NULL);

    /* calculate the memory(bytes) of rings, reserved num is GAZELLE_LSTACK_MAX_CONN. */
    per_conn_ring_size = rte_ring_get_memsize(DEFAULT_SENDMBOX_SIZE) +
                         rte_ring_get_memsize(DEFAULT_ACCEPTMBOX_SIZE);

    total_socket_memory = fixed_mem + bytes_to_mb(
        (per_pktmbuf_mempool_size * dpdk_pktmbuf_mempool_num()) * cfg->num_queue +
        per_rpc_mempool_size * RPCPOLL_MAX_NUM +
        per_conn_ring_size * GAZELLE_LSTACK_MAX_CONN);

    return total_socket_memory;
}
