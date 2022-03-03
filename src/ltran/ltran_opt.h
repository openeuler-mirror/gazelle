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

#ifndef __GAZELLE_OPT_H__
#define __GAZELLE_OPT_H__

#define PROGRAM_NAME    "ltran"
#define VER_FMT         "gazelle version: %s\n"
#define VER_NAME        "1.0.0"

#define DEFAULT_LTRAN_CONF_PATH "/etc/gazelle/ltran.conf"

#define GAZELLE_PACKET_READ_SIZE     32

#define GAZELLE_MBUFS_RX_COUNT       (300 * 1024)
#define GAZELLE_MBUFS_TX_COUNT       (30 * 1024)
#define GAZELLE_MBUFS_CACHE_SIZE     512

#define GAZELLE_RX_QUEUES            1
#define GAZELLE_TX_QUEUES            1
#define GAZELLE_RX_DESC_DEFAULT      512
#define GAZELLE_TX_DESC_DEFAULT      512

#define GAZELLE_KNI_MAX_PACKET_SIZE          2048
#define GAZELLE_KNI_ETHERNET_HEADER_SIZE     14
#define GAZELLE_KNI_ETHERNET_FCS_SIZE        4

#define GAZELLE_PKT_MBUF_RX_POOL_NAME_FMT    "rx_pool%d"
#define GAZELLE_PKT_MBUF_TX_POOL_NAME_FMT    "tx_pool%d"
#define GAZELLE_PKT_MBUF_POOL_NAME_LENGTH    64

#define GAZELLE_BOND_NAME_LENGTH             64
#define GAZELLE_BOND_DEV_NAME_FMT            "net_bonding%d"
#define GAZELLE_BOND_QUEUE_MIN                1
#define GAZELLE_BOND_QUEUE_MAX                64

#define GAZELLE_CLIENT_RING_NAME_FMT         "MProc_Client_%u_mbuf_queue"
#define GAZELLE_CLIENT_DROP_RING_SIZE        20000

#define GAZELLE_LTRAN_LOG_FILE               "/var/run/gazelle/ltran.log"

// CONFIG OF DFX
#define GAZELLE_DFX_REQ_INTERVAL_S           1

#endif /* ifndef __GAZELLE_OPT_H__ */
