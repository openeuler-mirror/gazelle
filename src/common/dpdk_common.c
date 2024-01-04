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

#include <rte_kni.h>
#include <rte_bus_pci.h>
#include <rte_ethdev.h>
#include <rte_bus_pci.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <securec.h>

#include "dpdk_common.h"

#define GAZELLE_KNI_IFACES_NUM               1
#define GAZELLE_KNI_READ_SIZE                32
#define GAZELLE_MAX_PKT_SZ                   2048

#ifdef LTRAN_COMPILE
#include "ltran_log.h"
#define  COMMON_ERR(fmt, ...)    LTRAN_ERR(fmt, ##__VA_ARGS__)
#define  COMMON_INFO(fmt, ...)   LTRAN_INFO(fmt, ##__VA_ARGS__)
#else
#include "lstack_log.h"
#define  COMMON_ERR(fmt, ...)    LSTACK_LOG(ERR, LSTACK, fmt, ##__VA_ARGS__)
#define  COMMON_INFO(fmt, ...)   LSTACK_LOG(INFO, LSTACK, fmt, ##__VA_ARGS__)
#endif

struct rte_kni *g_pkni = NULL;
static volatile bool g_kni_started = false;

bool get_kni_started(void)
{
    return g_kni_started;
}

struct rte_kni* get_gazelle_kni(void)
{
    return g_pkni;
}

static int32_t kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
    int32_t ret = 0;
    static bool g_bond_dev_started = false;

    if (port_id >= rte_eth_dev_count_avail() || port_id >= GAZELLE_MAX_ETHPORTS) {
        COMMON_ERR("Invalid port id %hu \n", port_id);
        return -EINVAL;
    }

    if (if_up != 0) { /* Configure network interface up */
        if (!g_kni_started) {
            g_kni_started = true;
            if (!g_bond_dev_started) {
                rte_eth_dev_start(port_id);
                g_bond_dev_started = true;
            }
        } else {
            COMMON_INFO("Trying to start a started dev. \n");
        }
    } else {  /* Configure network interface down */
        if (g_kni_started) {
            g_kni_started = false;
        } else {
            COMMON_INFO("Trying to stop a stopped dev. \n");
        }
    }

    COMMON_INFO("Configure network interface of %hu %s \n", port_id, if_up ? "up" : "down");
    return ret;
}

void eth_params_checksum(struct rte_eth_conf *conf, struct rte_eth_dev_info *dev_info)
{
    uint64_t rx_ol = 0;
    uint64_t tx_ol = 0;
    uint64_t rx_ol_capa = dev_info->rx_offload_capa;
    uint64_t tx_ol_capa = dev_info->tx_offload_capa;

    // rx ip
    if (rx_ol_capa & DEV_RX_OFFLOAD_IPV4_CKSUM) {
        rx_ol |= DEV_RX_OFFLOAD_IPV4_CKSUM;
        COMMON_INFO("DEV_RX_OFFLOAD_IPV4_CKSUM\n");
    }

    // rx tcp
    if (rx_ol_capa & DEV_RX_OFFLOAD_TCP_CKSUM) {
        rx_ol |= DEV_RX_OFFLOAD_TCP_CKSUM;
        COMMON_INFO("DEV_RX_OFFLOAD_TCP_CKSUM\n");
    }

    // rx udp
    if (rx_ol_capa & DEV_RX_OFFLOAD_UDP_CKSUM) {
        rx_ol |= DEV_RX_OFFLOAD_UDP_CKSUM;
        COMMON_INFO("DEV_RX_OFFLOAD_UDP_CKSUM\n");
    }

    // rx vlan
    if (rx_ol_capa & DEV_RX_OFFLOAD_VLAN_STRIP) {
        rx_ol |= DEV_RX_OFFLOAD_VLAN_STRIP;
        COMMON_INFO("DEV_RX_OFFLOAD_VLAN_STRIP\n");
    }

    // tx ip
    if (tx_ol_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) {
        tx_ol |= DEV_TX_OFFLOAD_IPV4_CKSUM;
        COMMON_INFO("DEV_TX_OFFLOAD_IPV4_CKSUM\n");
    }

    // tx tcp
    if (tx_ol_capa & DEV_TX_OFFLOAD_TCP_CKSUM) {
        tx_ol |= DEV_TX_OFFLOAD_TCP_CKSUM;
        COMMON_INFO("DEV_TX_OFFLOAD_TCP_CKSUM\n");
    }

    // tx udp
    if (tx_ol_capa & DEV_TX_OFFLOAD_UDP_CKSUM) {
        tx_ol |= DEV_TX_OFFLOAD_UDP_CKSUM;
        COMMON_INFO("DEV_TX_OFFLOAD_UDP_CKSUM\n");
    }

    // tx tso
    if (tx_ol_capa & DEV_TX_OFFLOAD_TCP_TSO) {
        tx_ol |= (DEV_TX_OFFLOAD_TCP_TSO | DEV_TX_OFFLOAD_MULTI_SEGS);
        COMMON_INFO("DEV_TX_OFFLOAD_TCP_TSO\n");
    }

    // tx vlan
    if (tx_ol_capa & DEV_TX_OFFLOAD_VLAN_INSERT) {
        tx_ol |= DEV_TX_OFFLOAD_VLAN_INSERT;
        COMMON_INFO("DEV_TX_OFFLOAD_VLAN_INSERT\n");
    }

    if (!(rx_ol & DEV_RX_OFFLOAD_UDP_CKSUM) ||
        !(rx_ol & DEV_RX_OFFLOAD_TCP_CKSUM) ||
        !(rx_ol & DEV_RX_OFFLOAD_IPV4_CKSUM)) {
        rx_ol = 0;
    }
    if (!(tx_ol & DEV_TX_OFFLOAD_UDP_CKSUM) ||
        !(tx_ol & DEV_TX_OFFLOAD_TCP_CKSUM) ||
        !(tx_ol & DEV_TX_OFFLOAD_IPV4_CKSUM)) {
        tx_ol = 0;
    }

    conf->rxmode.offloads = rx_ol;
    conf->txmode.offloads = tx_ol;

    COMMON_INFO("Set checksum offloads\n");
}

int32_t dpdk_kni_init(uint16_t port, struct rte_mempool *pool)
{
    int32_t ret;
    struct rte_kni_ops ops = {0};
    struct rte_kni_conf conf = {0};
    const struct rte_bus *bus = NULL;
    struct rte_eth_dev_info dev_info = {0};
    const struct rte_pci_device *pci_dev = NULL;

    if (port >= GAZELLE_MAX_ETHPORTS) {
        COMMON_ERR("Bond port id out of range.\n");
        return -1;
    }

    ret = rte_kni_init(GAZELLE_KNI_IFACES_NUM);
    if (ret < 0) {
        COMMON_ERR("rte_kni_init failed, errno: %d.\n", ret);
        return -1;
    }

    ret = snprintf_s(conf.name, RTE_KNI_NAMESIZE, RTE_KNI_NAMESIZE - 1, "%s", GAZELLE_KNI_NAME);
    if (ret < 0) {
        COMMON_ERR("Snprintf_s failed. ret=%d\n", ret);
        return -1;
    }
    conf.mbuf_size = GAZELLE_MAX_PKT_SZ;
    conf.group_id = port;

    if (rte_eth_dev_info_get(port, &dev_info) != 0) {
        COMMON_ERR("Failed rte_eth_dev_info_get\n");
        return -1;
    }

    if (dev_info.device) {
        bus = rte_bus_find_by_device(dev_info.device);
    }
    if (bus && !strcmp(bus->name, "pci")) {
        pci_dev = RTE_DEV_TO_PCI(dev_info.device);
        conf.id = pci_dev->id;
        conf.addr = pci_dev->addr;
    }

    ops.change_mtu = NULL;
    ops.config_network_if = kni_config_network_interface;
    ops.port_id = port;
    g_pkni = rte_kni_alloc(pool, &conf, &ops);
    if (g_pkni == NULL) {
        COMMON_ERR("Failed to create kni for port: %hu \n", port);
        return -1;
    }
    return 0;
}

void dpdk_kni_release(void)
{
    if (g_pkni) {
        rte_kni_release(g_pkni);
    }

    g_pkni = NULL;
}

int32_t kni_process_tx(struct rte_mbuf **pkts_burst, uint32_t count)
{
    uint32_t i;
    if (!g_kni_started) {
        for (i = 0; i < count; i++) {
            rte_pktmbuf_free(pkts_burst[i]);
        }
        return 0;
    }

    for (i = 0; i < count; ++i) {
        struct rte_ipv4_hdr * ipv4_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(pkts_burst[i], char*)
            + pkts_burst[i]->l2_len);
        if (pkts_burst[i]->nb_segs > 1) {
            ipv4_hdr->hdr_checksum = 0;
            ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
        }
    }

    i = rte_kni_tx_burst(g_pkni, pkts_burst, count);
    for (; i < count; ++i) {
        rte_pktmbuf_free(pkts_burst[i]);
        pkts_burst[i] = NULL;
    }

    return 0;
}

void kni_process_rx(uint16_t port)
{
    uint16_t nb_kni_rx, nb_rx, i;
    struct rte_mbuf *pkts_burst[GAZELLE_KNI_READ_SIZE];

    nb_kni_rx = rte_kni_rx_burst(g_pkni, pkts_burst, GAZELLE_KNI_READ_SIZE);
    if (nb_kni_rx > 0) {
        nb_rx = rte_eth_tx_burst(port, 0, pkts_burst, nb_kni_rx);

        for (i = nb_rx; i < nb_kni_rx; ++i) {
            rte_pktmbuf_free(pkts_burst[i]);
            pkts_burst[i] = NULL;
        }
    }
}
