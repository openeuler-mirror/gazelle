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

#ifndef __GAZELLE_MSG_H__
#define __GAZELLE_MSG_H__

#include <stdint.h>

#include "gazelle_opt.h"

#define NULL_CLIENT_IP          UINT32_MAX
#define NULL_CLIENT_PORT        UINT16_MAX

#define GAZELLE_MAX_REG_ARGS     32

#define ENQUEUE_RING_RETRY_TIMEOUT  10 // ms

#define OPT_BASE_VIRTADDR       "--base-virtaddr"
#define OPT_FILE_PREFIX         "--file-prefix"
#define OPT_SOCKET_MEM          "--socket-mem"
#define OPT_LEGACY_MEM          "--legacy-mem"
#define OPT_HUGE_DIR            "--huge-dir"
#define OPT_BIND_CORELIST       "-l"

/* types for msg from lstack to ltran */
enum response_type {
    RSP_OK,
    RSP_ERR,
    RSP_MAX,
};

/* types for data buf from ltran to lstack */
enum request_type {
    RQT_CHECK,
    RQT_STOP,
    RQT_REG_PROC_MEM,
    RQT_REG_PROC_ATT,
    RQT_REG_THRD_RING,
    RQT_MAX,
};

/* reg msg */
struct client_proc_conf {
    enum request_type reg_state;

    uint32_t pid;
    uintptr_t base_virtaddr;
    uint64_t socket_size;
    char file_prefix[PATH_MAX];

    uint8_t mac_addr[ETHER_ADDR_LEN];
    uint32_t ipv4;

    char argv[GAZELLE_MAX_REG_ARGS][PATH_MAX];
    uint32_t argc;
};

struct client_thrd_conf {
    uint32_t tid;
    uint32_t pid;

    uint16_t port;
    uint32_t ipv4;

    void *reg_ring;
    void *tx_ring;
    void *rx_ring;
};

struct reg_request_msg {
    enum request_type type;
    union message {
        struct client_thrd_conf thrd;
        struct client_proc_conf proc;
    } msg;
};

struct reg_response_msg {
    enum response_type type;
    struct {
        uintptr_t base_virtaddr;
        uint64_t socket_size;
        uint64_t rx_offload;
        uint64_t tx_offload;
    } msg;
};

#endif /* ifndef __GAZELLE_MSG_H__ */
