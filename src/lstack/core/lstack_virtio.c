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
#include <rte_ethdev.h>
#include "lstack_cfg.h"
#include "lstack_log.h"
#include "lstack_port_map.h"
#include "lstack_virtio.h"

#define VIRTIO_USER_NAME "virtio_user0"
#define VIRTIO_DPDK_PARA_LEN 256
#define VIRTIO_TX_RX_RING_SIZE 1024

static struct virtio_instance g_virtio_instance = {0};

struct virtio_instance* virtio_instance_get(void)
{
    return &g_virtio_instance;
}

static int virtio_set_ipv6_addr(void)
{
    return 0;
}

static int virtio_cfg_ip(void)
{
    // set ipv4 adr()

    // set ipv6 addr
    virtio_set_ipv6_addr();
    return 0;
}

void virtio_tap_process_rx(uint16_t port, uint32_t queue_id)
{
    struct rte_mbuf *pkts_burst[VIRTIO_TX_RX_RING_SIZE];
    uint16_t lstack_net_port = port;
    uint32_t pkg_num;

    pkg_num = rte_eth_rx_burst(g_virtio_instance.virtio_port_id, queue_id, pkts_burst, VIRTIO_TX_RX_RING_SIZE);
    if (pkg_num > 0) {
        g_virtio_instance.rx_pkg[queue_id] += pkg_num;
        uint16_t nb_rx = rte_eth_tx_burst(lstack_net_port, queue_id, pkts_burst, pkg_num);
        for (uint16_t i = nb_rx; i < pkg_num; ++i) {
            rte_pktmbuf_free(pkts_burst[i]);
            g_virtio_instance.rx_drop[queue_id]++;
        }
    }
}

void virtio_tap_process_tx(uint16_t queue_id, struct rte_mbuf *mbuf_copy)
{
    int tx_num = rte_eth_tx_burst(g_virtio_instance.virtio_port_id, queue_id, &(mbuf_copy), 1);
    if (tx_num < 0) {
        rte_pktmbuf_free(mbuf_copy);
        g_virtio_instance.tx_drop[queue_id]++;
        LSTACK_LOG(ERR, LSTACK, "virtio_tap_process_tx failed %d, %d\n", queue_id, tx_num);
    }
    g_virtio_instance.tx_pkg[queue_id]++;
}

static int virtio_port_init(uint16_t port)
{
    int retval;
    uint16_t rx_queue_num = g_virtio_instance.rx_queue_num;
    uint16_t tx_queue_num = g_virtio_instance.tx_queue_num;

    LSTACK_LOG(INFO, LSTACK, "virtio_port_init port= %u rx_queue_num=%u tx_queue_num=%u \n",
               port, rx_queue_num, tx_queue_num);

    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    struct rte_eth_dev_info dev_info;
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        LSTACK_LOG(ERR, LSTACK, "rte_eth_dev_info_get failed(port %u) info: %d\n", port, retval);
        return retval;
    }

    retval = rte_eth_dev_configure(port, rx_queue_num, tx_queue_num, &port_conf);
    if (retval != 0) {
        LSTACK_LOG(ERR, LSTACK, "rte_eth_dev_configure failed retval=%d\n", retval);
        return retval;
    }

    for (uint16_t q = 0; q < tx_queue_num; q++) {
        retval = rte_eth_tx_queue_setup(port, q, VIRTIO_TX_RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);
        if (retval < 0) {
            LSTACK_LOG(ERR, LSTACK, "rte_eth_tx_queue_setup failed (queue %u) retval=%d \n", q, retval);
            return retval;
        }
    }

    for (uint16_t q = 0; q < rx_queue_num; q++) {
        struct rte_mempool *rxtx_mbuf_pool = get_protocol_stack_group()->total_rxtx_pktmbuf_pool[q];
        retval = rte_eth_rx_queue_setup(port, q, VIRTIO_TX_RX_RING_SIZE, rte_eth_dev_socket_id(port),
                                        NULL, rxtx_mbuf_pool);
        if (retval < 0) {
            LSTACK_LOG(ERR, LSTACK, "rte_eth_rx_queue_setup failed (queue %u) retval=%d \n", q, retval);
            return retval;
        }
    }
    return 0;
}

static int32_t virtio_port_start(uint16_t virtio_port)
{
    int retval = 0;
    if (virtio_port_init(virtio_port) < 0) {
        LSTACK_LOG(ERR, LSTACK, "virtio_port_init failed \n");
        return -1;
    }

    retval = rte_eth_dev_start(virtio_port);
    if (retval < 0) {
        LSTACK_LOG(ERR, LSTACK, "rte_eth_dev_start failed retval=%d\n", retval);
        return retval;
    }

    if (virtio_cfg_ip() != 0) {
        LSTACK_LOG(ERR, LSTACK, "virtio_cfg_ip_mac failed\n");
        return -1;
    }
    LSTACK_LOG(INFO, LSTACK, "virtio_user lstack_net_port=%u virtio_port=%u rx_queue_num = %u tx_queue_num = %u\n",
               g_virtio_instance.lstack_port_id, g_virtio_instance.virtio_port_id,
               g_virtio_instance.rx_queue_num, g_virtio_instance.tx_queue_num);
    return 0;
}
int virtio_port_create(int lstack_net_port)
{
    char portargs[VIRTIO_DPDK_PARA_LEN] = {0};

    struct rte_ether_addr addr;
    uint16_t virtio_port_id = 0xffff; // invalid val

    struct rte_eth_dev_info dev_info;
    int ret = rte_eth_dev_info_get(lstack_net_port, &dev_info);
    if (ret != 0) {
        LSTACK_LOG(ERR, LSTACK, "get dev info ret=%d\n", ret);
        return ret;
    }

    g_virtio_instance.rx_queue_num = dev_info.nb_rx_queues;
    g_virtio_instance.tx_queue_num = dev_info.nb_tx_queues;

    if (g_virtio_instance.rx_queue_num > VIRTIO_MAX_QUEUE_NUM ||
        g_virtio_instance.tx_queue_num > VIRTIO_MAX_QUEUE_NUM) {
        LSTACK_LOG(ERR, LSTACK, "virtio_port_create failed queue_num (%u %u) is bigger than %u\n",
                   g_virtio_instance.rx_queue_num, g_virtio_instance.tx_queue_num, VIRTIO_MAX_QUEUE_NUM);
        return -1;
    }

    int retval = rte_eth_macaddr_get(lstack_net_port, &addr); // virtio_user0'mac is same with lstack.conf MAC addr
    if (retval != 0) {
        LSTACK_LOG(ERR, LSTACK, " rte_eth_macaddr_get failed ret = %d\n", retval);
        return retval;
    }

    retval = snprintf(portargs, sizeof(portargs),
                      "path=/dev/vhost-net,queues=%u,queue_size=%u,iface=%s,mac=" RTE_ETHER_ADDR_PRT_FMT,
                      VIRTIO_MAX_QUEUE_NUM, VIRTIO_TX_RX_RING_SIZE, VIRTIO_USER_NAME, RTE_ETHER_ADDR_BYTES(&addr));
    if (retval < 0) {
        LSTACK_LOG(ERR, LSTACK, "virtio portargs snprintf failed ret=%d \n", retval);
        return retval;
    }
    LSTACK_LOG(INFO, LSTACK, "virtio portargs=%s \n", portargs);

    retval = rte_eal_hotplug_add("vdev", VIRTIO_USER_NAME, portargs);
    if (retval < 0) {
        LSTACK_LOG(ERR, LSTACK, "rte_eal_hotplug_add failed retval=%d : %s\n", retval, strerror(-retval));
        return retval;
    }

    retval = rte_eth_dev_get_port_by_name(VIRTIO_USER_NAME, &virtio_port_id);
    if (retval != 0) {
        rte_eal_hotplug_remove("vdev", VIRTIO_USER_NAME);
        LSTACK_LOG(ERR, LSTACK, "virtio_user0 not found\n");
        return -1;
    }

    g_virtio_instance.virtio_port_id = virtio_port_id;
    g_virtio_instance.lstack_port_id = lstack_net_port;

    retval = virtio_port_start(virtio_port_id);
    if (retval != 0) {
        LSTACK_LOG(ERR, LSTACK, "virtio_port_start failed ret=%d\n", retval);
        rte_eal_hotplug_remove("vdev", VIRTIO_USER_NAME);
        return retval;
    }
    return 0;
}