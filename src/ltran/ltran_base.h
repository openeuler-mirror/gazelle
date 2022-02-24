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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include <limits.h>
#include <securec.h>

#include "ltran_opt.h"
#include "ltran_errno.h"
#include "gazelle_dfx_msg.h"

#define GAZELLE_OK       0
#define GAZELLE_ERR      (-1)
#define GAZELLE_QUIT     1

#define GAZELLE_ON       1
#define GAZELLE_OFF      0

#define GAZELLE_TRUE     1
#define GAZELLE_FALSE    0


#define GAZELLE_CMD_BUFFER_SIZE _POSIX_ARG_MAX
#define GAZELLE_PATH_BUFFER_SIZE PATH_MAX
#define GAZELLE_PARAM_BUFFER_SIZE        32

#define GAZELLE_MAX_DPDK_ARGS_NUM        32
#define GAZELLE_MAX_ADDR_NUM             1024
#define GAZELLE_MAX_BOND_NUM             2
#define GAZELLE_MAX_ETHERPORTS           32
#define GAZELLE_MAX_NAME_LEN             256
#define GAZELLE_MAX_RING_NAME_LEN        64
#define GAZELLE_MAX_CMD_NUM              1024
#define GAZELLE_MAX_PORT_NUM             16

#define GAZELLE_CLIENT_INFO_CHECKSUM_NUM 137

#define GAZELLE_MAX_INSTANCE_HTABLE_SIZE 256
#define GAZELLE_MAX_INSTANCE_ARRAY_SIZE  32
#define GAZELLE_MAX_INSTANCE_NUM         32

#define GAZELLE_MAX_STACK_ARRAY_SIZE     GAZELLE_CLIENT_NUM_MAX
#define GAZELLE_MAX_STACK_HTABLE_SIZE    32
#define GAZELLE_MAX_STACK_NUM            128

#define GAZELLE_MAX_TCP_SOCK_ARRAY_SIZE  256
#define GAZELLE_MAX_TCP_SOCK_HTABLE_SIZE 256
#define GAZELLE_MAX_TCP_SOCK_NUM         (GAZELLE_MAX_STACK_NUM * 32)

#define GAZELLE_STACK_MAX_TCP_CON_NUM    (1024*1024*1024)
#define GAZELLE_MAX_CONN_HTABLE_SIZE     2048
/* same as define (MAX_CLIENTS + RESERVED_CLIENTS) in lwip/lwipopts.h */
#define GAZELLE_MAX_CONN_NUM             (GAZELLE_MAX_STACK_NUM * (20000 + 2000))

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

#define SEC_TO_USEC                                   1000000

#define GAZELLE_CONN_TIMEOUT                           5
#define GAZELLE_CONN_INTERVAL                          (1 * SEC_TO_USEC)

#define GAZELLE_TCP_CONN_SCAN_INTERVAL_DEFAULT_S       600      // 10 min
#define GAZELLE_TCP_CONN_SCAN_INTERVAL_MIN_S           0
#define GAZELLE_TCP_CONN_SCAN_INTERVAL_MAX_S           86400     // 1 day 24*60*60 = 86400

#define GAZELLE_INET_ADDRSTRLEN          16

#define GAZELLE_DFX_SOCK_PATHNAME        "/var/run/gazelle/libos_cmd.sock"

#endif /* ifndef __GAZELLE_BASE_H__ */
