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

#ifndef __GAZELLE_BASE_H__
#define __GAZELLE_BASE_H__

#include <limits.h>

#include "gazelle_opt.h"

#define GAZELLE_CMD_BUFFER_SIZE          _POSIX_ARG_MAX
#define GAZELLE_PATH_BUFFER_SIZE         PATH_MAX
#define GAZELLE_PARAM_BUFFER_SIZE        32

#define GAZELLE_MAX_DPDK_ARGS_NUM        32
#define GAZELLE_MAX_ADDR_NUM             1024
#define GAZELLE_MAX_ETHERPORTS           32
#define GAZELLE_MAX_NAME_LEN             256
#define GAZELLE_MAX_RING_NAME_LEN        64
#define GAZELLE_MAX_CMD_NUM              1024

#define GAZELLE_CLIENT_INFO_CHECKSUM_NUM 137

#define GAZELLE_MAX_INSTANCE_HTABLE_SIZE 256
#define GAZELLE_MAX_INSTANCE_ARRAY_SIZE  GAZELLE_NULL_CLIENT

#define GAZELLE_MAX_TCP_SOCK_ARRAY_SIZE  256

#define GAZELLE_STACK_MAX_TCP_CON_NUM    (1024 * 1024 * 1024)

#define GAZELLE_SUBNET_CHECK_OFFSET      20
#define GAZELLE_SUBNET_LENGTH_MIN        1
#define GAZELLE_SUBNET_LENGTH_MAX        16

#define GAZELLE_BOND_MODE_MIN            1
#define GAZELLE_BOND_MODE_MAX            1
#define GAZELLE_BOND_MTU_MIN             68
#define GAZELLE_BOND_MTU_MAX             1500
#define GAZELLE_BOND_MIIMON_MIN          0
#define GAZELLE_BOND_MIIMON_MAX          INT_MAX
#define GAZELLE_BOND_PORT_MASK_MIN       0x1
#define GAZELLE_BOND_PORT_MASK_MAX       0xff
#define GAZELLE_BOND_PORT_DEFAULT        0xffff

#define PROGRAM_NAME                    "ltran"
#define VER_FMT                         "gazelle version: %s\n"
#define VER_NAME                        "1.0.0"

#define DEFAULT_LTRAN_CONF_PATH         "/etc/gazelle/ltran.conf"

#define GAZELLE_MBUFS_RX_COUNT          (300 * 1024)
#define GAZELLE_MBUFS_TX_COUNT          (30 * 1024)
#define GAZELLE_MBUFS_CACHE_SIZE        512

#define GAZELLE_RX_QUEUES               1
#define GAZELLE_TX_QUEUES               1
#define GAZELLE_RX_DESC_DEFAULT         512
#define GAZELLE_TX_DESC_DEFAULT         512

#define GAZELLE_KNI_MAX_PACKET_SIZE             2048
#define GAZELLE_KNI_ETHERNET_HEADER_SIZE        14
#define GAZELLE_KNI_ETHERNET_FCS_SIZE           4

#define GAZELLE_PKT_MBUF_RX_POOL_NAME_FMT       "rx_pool%u"
#define GAZELLE_PKT_MBUF_TX_POOL_NAME_FMT       "tx_pool%u"
#define GAZELLE_PKT_MBUF_POOL_NAME_LENGTH       64

#define GAZELLE_BOND_NAME_LENGTH                64
#define GAZELLE_BOND_DEV_NAME_FMT               "net_bonding%hu"
#define GAZELLE_BOND_QUEUE_MIN                  1
#define GAZELLE_BOND_QUEUE_MAX                  64

#define GAZELLE_CLIENT_RING_NAME_FMT            "MProc_Client_%u_mbuf_queue"
#define GAZELLE_CLIENT_DROP_RING_SIZE           20000

#define GAZELLE_LTRAN_LOG_FILE                  "/var/run/gazelle/ltran.log"

// CONFIG OF DFX
#define GAZELLE_DFX_REQ_INTERVAL_S              1

#define SEC_TO_USEC                                   1000000

#define GAZELLE_CONN_TIMEOUT                           5
#define GAZELLE_CONN_INTERVAL                          (1 * SEC_TO_USEC)

#define GAZELLE_TCP_CONN_SCAN_INTERVAL_DEFAULT_S       600      // 10 min
#define GAZELLE_TCP_CONN_SCAN_INTERVAL_MIN_S           0
#define GAZELLE_TCP_CONN_SCAN_INTERVAL_MAX_S           86400     // 1 day 24*60*60 = 86400

#define GAZELLE_INET_ADDRSTRLEN                         16

#endif /* ifndef __GAZELLE_BASE_H__ */
