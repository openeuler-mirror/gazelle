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

#include "ltran_ethdev.h"

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_pdump.h>
#include <rte_bus_pci.h>
#include <rte_mempool.h>
#include <rte_eth_bond.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_kni.h>
#include <syslog.h>
#include <securec.h>

#include "dpdk_common.h"
#include "ltran_param.h"
#include "ltran_log.h"
#include "ltran_base.h"
#include "gazelle_opt.h"
#include "ltran_errno.h"
#include "gazelle_reg_msg.h"

uint32_t g_bond_num = 0;
FILE* g_log_file = NULL;
uint16_t g_bond_port[GAZELLE_MAX_BOND_NUM] = {GAZELLE_BOND_PORT_DEFAULT, GAZELLE_BOND_PORT_DEFAULT};
struct port_info g_port_info[GAZELLE_MAX_BOND_NUM];
struct rte_mempool *g_pktmbuf_rxpool[GAZELLE_MAX_BOND_NUM];
struct rte_mempool *g_pktmbuf_txpool[GAZELLE_MAX_BOND_NUM];

/* record bond num, check the num is match or not, or exceed */
void set_bond_num(const uint32_t bond_num)
{
    g_bond_num = bond_num;
}

uint32_t get_bond_num(void)
{
    return g_bond_num;
}

/* the port statistics information for debug */
struct port_info* get_port_info(void)
{
    return g_port_info;
}

uint16_t* get_bond_port(void)
{
    return g_bond_port;
}

/* The mbuf pool for packet tx */
struct rte_mempool** get_pktmbuf_txpool(void)
{
    return g_pktmbuf_txpool;
}

/* The mbuf pool for packet rx */
struct rte_mempool** get_pktmbuf_rxpool(void)
{
    return g_pktmbuf_rxpool;
}

static int32_t ltran_log_init(void);
static int32_t ltran_eal_init(void);
static int32_t ltran_pdump_init(void);
static int32_t ltran_log_level_init(void);
static struct rte_mempool *ltran_create_rx_mbuf_pool(uint32_t bond_port_index);
static struct rte_mempool *ltran_create_tx_mbuf_pool(uint32_t bond_port_index);
static int32_t ltran_parse_port(void);
static int32_t ltran_mbuf_pool_init(void);
static int32_t ltran_single_slave_port_init(uint16_t port_num, struct rte_mempool *pktmbuf_rxpool);
static int32_t ltran_single_bond_port_init(uint16_t port_num, struct rte_mempool *pktmbuf_rxpool);
static int32_t ltran_slave_port_init(void);
static int32_t ltran_kni_init(void);
static int32_t ltran_bond_port_init(void);

static int32_t ltran_eal_init(void)
{
    int32_t ret = rte_eal_init(get_ltran_config()->dpdk.dpdk_argc, get_ltran_config()->dpdk.dpdk_argv);
    if (ret < 0) {
        syslog(LOG_ERR, "Cannot initialize DPDK, please check dpdk args in conf. errno: %d \n", ret);
        return -GAZELLE_EEALINIT;
    }

    ret = rte_eal_process_type();
    if (ret != RTE_PROC_PRIMARY) {
        LTRAN_ERR("Process type is not PRIMARY, maybe another ltran is running. ret=%d \n", ret);
        return GAZELLE_ERR;
    }

    return GAZELLE_OK;
}

static int32_t ltran_log_level_init(void)
{
    rte_log_set_global_level(RTE_LOG_INFO);

    int32_t ret = rte_log_set_level(RTE_LOGTYPE_LTRAN, RTE_LOG_INFO);
    if (ret != 0) {
        LTRAN_ERR("rte_log_set_level failed RTE_LOGTYPE_LTRAN RTE_LOG_INFO ret=%d \n", ret);
        return ret;
    }

    return GAZELLE_OK;
}

static int32_t ltran_log_init(void)
{
    return ltran_log_level_init();
}

static int32_t ltran_pdump_init(void)
{
    int32_t ret = rte_pdump_init();
    if (ret < 0) {
        LTRAN_ERR("Cannot initialize DPDK pdump. errno: %d ret=%d \n", rte_errno, ret);
        return GAZELLE_ERR;
    }
    return GAZELLE_OK;
}

static struct rte_mempool *ltran_create_rx_mbuf_pool(uint32_t bond_port_index)
{
    uint32_t num_mbufs = get_ltran_config()->rx_mbuf_pool_size;

    char mbuf_pool_name[GAZELLE_PKT_MBUF_POOL_NAME_LENGTH] = {0};

    int32_t ret = snprintf_s(mbuf_pool_name, sizeof(mbuf_pool_name), sizeof(mbuf_pool_name) - 1,
                     GAZELLE_PKT_MBUF_RX_POOL_NAME_FMT, bond_port_index);
    if (ret < 0) {
        LTRAN_ERR("snprintf failed, errno: %d, port_index: %u \n",
            ret, bond_port_index);
        return NULL;
    }

    uint16_t private_size = RTE_ALIGN(sizeof(struct mbuf_private), RTE_CACHE_LINE_SIZE);
    return rte_pktmbuf_pool_create(mbuf_pool_name, num_mbufs, GAZELLE_MBUFS_CACHE_SIZE, private_size,
                                   RTE_MBUF_DEFAULT_BUF_SIZE, (int32_t)rte_socket_id());
}

static struct rte_mempool *ltran_create_tx_mbuf_pool(uint32_t bond_port_index)
{
    const uint32_t num_mbufs = get_ltran_config()->tx_mbuf_pool_size;

    char mbuf_pool_name[GAZELLE_PKT_MBUF_POOL_NAME_LENGTH] = {0};

    int32_t ret = snprintf_s(mbuf_pool_name, sizeof(mbuf_pool_name), sizeof(mbuf_pool_name) - 1,
                     GAZELLE_PKT_MBUF_TX_POOL_NAME_FMT, bond_port_index);
    if (ret < 0) {
        LTRAN_ERR("snprintf_s failed, errno: %d, port_index: %u \n", ret,
                  bond_port_index);
        return NULL;
    }

    uint16_t private_size = RTE_ALIGN(sizeof(struct mbuf_private), RTE_CACHE_LINE_SIZE);
    return rte_pktmbuf_pool_create(mbuf_pool_name, num_mbufs, GAZELLE_MBUFS_CACHE_SIZE, private_size,
                                   RTE_MBUF_DEFAULT_BUF_SIZE, (int32_t)rte_socket_id());
}

static int32_t ltran_mbuf_pool_init(void)
{
    uint32_t bond_num = get_bond_num();
    struct rte_mempool** rxpool = get_pktmbuf_rxpool();
    struct rte_mempool** txpool = get_pktmbuf_txpool();

    for (uint32_t i = 0; i < bond_num; i++) {
        rxpool[i] = ltran_create_rx_mbuf_pool(i);
        if (rxpool[i] == NULL) {
            LTRAN_ERR("rxpool[%u] is NULL, pktmbuf_pool init failed. rte_errno: %d. \n", i, rte_errno);
            return GAZELLE_ERR;
        }

        txpool[i] = ltran_create_tx_mbuf_pool(i);
        if (txpool[i] == NULL) {
            LTRAN_ERR("txpool[%u] is NULL, pktmbuf_pool init failed. rte_errno: %d. \n", i, rte_errno);
            return GAZELLE_ERR;
        }
    }
    return GAZELLE_OK;
}

static int32_t ltran_parse_port(void)
{
    uint16_t index = 0;
    struct port_info* port = get_port_info();
    uint32_t bond_num = get_bond_num();

    uint16_t avail_ports_num = rte_eth_dev_count_avail();
    if (avail_ports_num == 0) {
        LTRAN_ERR("No user-mode port available.\n");
        return GAZELLE_ERR;
    }

    for (uint32_t i = 0; i < bond_num; i++) {
        uint32_t mask = get_ltran_config()->bond.portmask[i];
        while (mask != 0) {
            if (index >= avail_ports_num) {
                LTRAN_WARN("Requested port %hu not present, ignoring. \n", index);
                break;
            }

            if ((mask & 0x01) != 0) {
                port[i].id[port[i].num_ports] = index;
                port[i].num_ports++;
            }

            mask >>= 1;
            index++;
        }

        if (port[i].num_ports == 0) {
            LTRAN_ERR("Port mask of %u bond port do not match any available port.\n", i);
            return GAZELLE_ERR;
        }
    }

    return GAZELLE_OK;
}

static int32_t ltran_single_slave_port_init(uint16_t port_num, struct rte_mempool *pktmbuf_rxpool)
{
    uint16_t rx_ring_size = GAZELLE_RX_DESC_DEFAULT;
    uint16_t tx_ring_size = GAZELLE_TX_DESC_DEFAULT;
    uint16_t rx_queue_num = (uint16_t)get_ltran_config()->bond.rx_queue_num;
    uint16_t tx_queue_num = (uint16_t)get_ltran_config()->bond.tx_queue_num;
    struct rte_eth_dev_info dev_info;
    uint16_t queue_id;

    rte_eth_dev_stop(port_num);

    if (rte_eth_dev_info_get(port_num, &dev_info) != 0) {
        LTRAN_ERR("Fail rte_eth_dev_info_get\n");
        return GAZELLE_ERR;
    }

    struct rte_eth_conf port_conf = {0};
    port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
    port_conf.link_speeds = ETH_LINK_SPEED_AUTONEG;
    eth_params_checksum(&port_conf, &dev_info);
    port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;

    struct ltran_config *ltran_config = get_ltran_config();
    ltran_config->dpdk.rx_offload = port_conf.rxmode.offloads;
    ltran_config->dpdk.tx_offload = port_conf.txmode.offloads;

    if (rte_eth_dev_configure(port_num, rx_queue_num, tx_queue_num, &port_conf)) {
        LTRAN_ERR("rte_eth_dev_configure failed in slave port initialize. errno: %d, port: %hu\n", errno, port_num);
        return GAZELLE_ERR;
    }

    int32_t ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_num, &rx_ring_size, &tx_ring_size);
    if (ret != 0) {
        LTRAN_ERR("rte_eth_dev_adjust_nb_rx_tx_desc failed in slave port initialize. errno: %d, port: %hu \n", ret,
                  port_num);
        return GAZELLE_ERR;
    }
    LTRAN_DEBUG("Adujst rx_ring_size: %hu, tx_ring_size: %hu.\n", rx_ring_size, tx_ring_size);

    for (queue_id = 0; queue_id < rx_queue_num; queue_id++) {
        ret = rte_eth_rx_queue_setup(port_num, queue_id, rx_ring_size, (uint32_t)rte_eth_dev_socket_id(port_num), NULL,
                                     pktmbuf_rxpool);
        if (ret < 0) {
            LTRAN_ERR("rte_eth_rx_queue_setup failed in slave port initialize. errno: %d, port: %hu\n", ret, port_num);
            return GAZELLE_ERR;
        }
    }

    for (queue_id = 0; queue_id < tx_queue_num; queue_id++) {
        ret = rte_eth_tx_queue_setup(port_num, queue_id, tx_ring_size, (uint32_t)rte_eth_dev_socket_id(port_num),
                                     &dev_info.default_txconf);
        if (ret < 0) {
            LTRAN_ERR("rte_eth_tx_queue_setup failed in slave port initialize. errno: %d, port: %hu\n", ret, port_num);
            return GAZELLE_ERR;
        }
    }

    return GAZELLE_OK;
}

static int32_t ltran_slave_port_init(void)
{
    struct port_info* port_info = get_port_info();
    uint32_t bond_num = get_bond_num();
    struct rte_mempool** pktmbuf_rxpool = get_pktmbuf_rxpool();

    for (uint32_t i = 0; i < bond_num; i++) {
        for (uint32_t j = 0; j < port_info[i].num_ports; j++) {
            int32_t ret = ltran_single_slave_port_init(port_info[i].id[j], pktmbuf_rxpool[i]);
            if (ret != GAZELLE_OK) {
                return ret;
            }
        }
    }
    return GAZELLE_OK;
}

static int32_t ltran_eth_bond_slave(const struct port_info *port_info, uint16_t port_num, uint16_t bond_port_id)
{
    for (uint32_t i = 0; i < port_info[port_num].num_ports; i++) {
        int32_t ret = rte_eth_bond_slave_add(bond_port_id, port_info[port_num].id[i]);
        if (ret < 0) {
            return ret;
        }
    }
    return GAZELLE_OK;
}

static int32_t ltran_eth_rx_queue_setup(uint16_t bond_port_id, struct rte_mempool *pktmbuf_rxpool,
    uint16_t rx_queue_num, uint16_t rx_ring_size)
{
    for (uint16_t queue_id = 0; queue_id < rx_queue_num; queue_id++) {
        int32_t ret = rte_eth_rx_queue_setup(bond_port_id, queue_id, rx_ring_size,
            (uint32_t)rte_eth_dev_socket_id(bond_port_id), NULL, pktmbuf_rxpool);
        if (ret < 0) {
            return ret;
        }
    }
    return GAZELLE_OK;
}

static int32_t ltran_eth_tx_queue_setup(uint16_t port_num, uint16_t bond_port_id, uint16_t tx_queue_num,
    uint16_t tx_ring_size)
{
    struct rte_eth_dev_info dev_info;

    rte_eth_dev_info_get(port_num, &dev_info);
    for (uint16_t queue_id = 0; queue_id < tx_queue_num; queue_id++) {
        int32_t ret = rte_eth_tx_queue_setup(bond_port_id, queue_id, tx_ring_size,
            (uint32_t)rte_eth_dev_socket_id(bond_port_id), &dev_info.default_txconf);
        if (ret < 0) {
            return ret;
        }
    }
    return GAZELLE_OK;
}

static int32_t ltran_bond_port_attr_set(uint16_t port_num, uint16_t bond_port_id, struct rte_mempool *pktmbuf_rxpool)
{
    uint16_t tx_ring_size = GAZELLE_TX_DESC_DEFAULT;
    uint16_t rx_ring_size = GAZELLE_RX_DESC_DEFAULT;
    struct port_info* port_info = get_port_info();
    struct ltran_config *ltran_config = get_ltran_config();
    uint16_t rx_queue_num = (uint16_t)ltran_config->bond.rx_queue_num;
    uint16_t tx_queue_num = (uint16_t)ltran_config->bond.tx_queue_num;

    int32_t ret = ltran_eth_bond_slave(port_info, port_num, bond_port_id);
    if (ret < 0) {
        LTRAN_ERR("rte_eth_bond_slave_add failed with bond port num: %hu, errno: %d \n", port_num, ret);
        return GAZELLE_ERR;
    }
    
    struct rte_eth_dev_info dev_info;
    if (rte_eth_dev_info_get(bond_port_id, &dev_info) != 0) {
        LTRAN_ERR("faile rte_eth_dev_info_get\n");
        return GAZELLE_ERR;
    }

    struct rte_eth_conf port_conf = {0};
    port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
    port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
    port_conf.link_speeds = ETH_LINK_SPEED_AUTONEG;
    eth_params_checksum(&port_conf, &dev_info);

    ret = rte_eth_dev_configure(bond_port_id, rx_queue_num, tx_queue_num, &port_conf);
    if (ret != 0) {
        LTRAN_ERR("rte_eth_dev_configure failed with bond port num: %hu, errno: %d \n", port_num, ret);
        return GAZELLE_ERR;
    }

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(bond_port_id, &rx_ring_size, &tx_ring_size);
    if (ret != 0) {
        LTRAN_ERR("rte_eth_dev_adjust_nb_rx_tx_desc failed with bond port num: %hu, errno: %d \n", port_num, ret);
        return GAZELLE_ERR;
    }
    LTRAN_DEBUG("Bond port adujst rx_ring_size: %hu, tx_ring_size: %hu. bond port num: %hu \n",
        rx_ring_size, tx_ring_size, port_num);

    ret = ltran_eth_rx_queue_setup(bond_port_id, pktmbuf_rxpool, rx_queue_num, rx_ring_size);
    if (ret < 0) {
        LTRAN_ERR("rte_eth_rx_queue_setup failed in bond port initialize. errno: %d, port: %hu \n", ret, port_num);
        return GAZELLE_ERR;
    }

    ret = ltran_eth_tx_queue_setup(port_num, bond_port_id, tx_queue_num, tx_ring_size);
    if (ret < 0) {
        LTRAN_ERR("rte_eth_tx_queue_setup failed in bond port initialize. errno: %d, port: %hu \n", ret, port_num);
        return GAZELLE_ERR;
    }
    return GAZELLE_OK;
}

static int32_t ltran_single_bond_port_init(uint16_t port_num, struct rte_mempool *pktmbuf_rxpool)
{
    int32_t ret;
    uint16_t bond_port_id;
    char bond_port_name[GAZELLE_BOND_NAME_LENGTH];
    uint16_t* bond_port = get_bond_port();
    struct ltran_config *ltran_config = get_ltran_config();

    ret = snprintf_s(bond_port_name, GAZELLE_BOND_NAME_LENGTH, GAZELLE_BOND_NAME_LENGTH - 1,
                     GAZELLE_BOND_DEV_NAME_FMT, port_num);
    if (ret < 0) {
        LTRAN_ERR("snprintf_s failed, errno: %d\n", ret);
        return GAZELLE_ERR;
    }

    ret = rte_eth_bond_create(bond_port_name, (uint8_t)ltran_config->bond.mode, (uint8_t)rte_socket_id());
    if (ret < 0) {
        LTRAN_ERR("rte_eth_bond_create failed with bond port num: %hu, errno: %d\n", port_num, ret);
        return GAZELLE_ERR;
    }
    bond_port_id = (uint16_t)ret;

    ret = ltran_bond_port_attr_set(port_num, bond_port_id, pktmbuf_rxpool);
    if (ret != GAZELLE_OK) {
        return GAZELLE_ERR;
    }

    struct rte_ether_addr addr = ltran_config->bond.mac[port_num];
    ret = rte_eth_bond_mac_address_set(bond_port_id, &addr);
    if (ret < 0) {
        LTRAN_ERR("rte_eth_bond_mac_address_set failed in bond port initialize. errno: %d, port: %hu\n", ret, port_num);
        return GAZELLE_ERR;
    }

    ret = rte_eth_bond_link_monitoring_set(bond_port_id, (uint32_t)ltran_config->bond.miimon);
    if (ret < 0) {
        LTRAN_ERR("rte_eth_bond_link_monitoring_set failed in bond port initialize. errno: %d, port: %hu\n", ret,
                  port_num);
        return GAZELLE_ERR;
    }

    ret = rte_eth_dev_start(bond_port_id);
    if (ret < 0) {
        LTRAN_ERR("rte_eth_dev_start failed in bond port initialize. errno: %d, port: %hu\n", ret, port_num);
        return GAZELLE_ERR;
    }

    bond_port[port_num] = bond_port_id;
    return GAZELLE_OK;
}

static int32_t ltran_bond_port_init(void)
{
    uint32_t bond_num = get_bond_num();
    struct rte_mempool** pktmbuf_rxpool = get_pktmbuf_rxpool();

    for (uint16_t i = 0; i < bond_num; i++) {
        int32_t ret = ltran_single_bond_port_init(i, pktmbuf_rxpool[i]);
        if (ret != GAZELLE_OK) {
            return ret;
        }
    }

    return GAZELLE_OK;
}

static int32_t ltran_kni_init(void)
{
    // if not use kni. skip kni init and return
    if (get_ltran_config()->dpdk.kni_switch == GAZELLE_OFF) {
        return GAZELLE_OK;
    }

    uint16_t *bond_port = get_bond_port();
    struct rte_mempool **txpool = get_pktmbuf_txpool();

    return dpdk_kni_init(bond_port[0], txpool[0]);
}

typedef int32_t (*ethdev_init_func)(void);

static ethdev_init_func g_ltran_ethdev_init_tbl[] = {
    ltran_eal_init,
    ltran_log_init,
    ltran_pdump_init,
    ltran_parse_port,
    ltran_mbuf_pool_init,
    ltran_slave_port_init,
    ltran_bond_port_init,
    ltran_kni_init,
};

int32_t ltran_ethdev_init(void)
{
    struct ltran_config *ltran_config = get_ltran_config();

    set_bond_num(ltran_config->bond.port_num);

    int32_t size = sizeof(g_ltran_ethdev_init_tbl) / sizeof(g_ltran_ethdev_init_tbl[0]);
    for (int32_t i = 0; i < size; i++) {
        int32_t ret = g_ltran_ethdev_init_tbl[i]();
        if (ret != GAZELLE_OK) {
            return ret;
        }
    }
    return GAZELLE_OK;
}
