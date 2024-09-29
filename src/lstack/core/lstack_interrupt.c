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

#include <sys/un.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <securec.h>

#include <rte_interrupts.h>
#include <rte_ethdev.h>

#include <lwip/lwipgz_posix_api.h>
#include <lwip/lwipopts.h>
#include <lwip/arch/sys_arch.h>

#include "common/dpdk_common.h"
#include "common/gazelle_opt.h"
#include "common/gazelle_dfx_msg.h"
#include "lstack_log.h"
#include "lstack_cfg.h"
#include "lstack_interrupt.h"

#define INTR_MAX_EVENT_NUM                       8

struct intr_dpdk_event {
    int rte_epfd;
#define INTR_PORT_NUM                            2
#define INTR_INVALID_PORT                        65535
    uint16_t port_id[INTR_PORT_NUM]; /* 0: nic port id, 1: virtio_user port id */
    uint16_t queue_id[INTR_PORT_NUM];
};

struct intr_local_event {
    bool (*get_event) (uint16_t stack_id);
};

struct intr_remote_event {
    int event_fd;
};

struct intr_policy {
#define INTR_LOOP_TIMES                          5
    uint8_t no_event_cnt;
};

struct intr_config {
    int epoll_fd;                    /* used for epoll */
    uint16_t stack_id;
    bool in_wait;

    struct intr_dpdk_event dpdk_event;
    struct intr_local_event local_event;
    struct intr_remote_event remote_event;

    struct intr_policy policy;
    struct interrupt_stats stats;
};

static struct intr_config g_intr_configs[PROTOCOL_STACK_MAX] = {0};

static inline struct intr_config *intr_config_get(uint16_t stack_id)
{
    return &g_intr_configs[stack_id];
}

int intr_init(void)
{
    int stack_id;
    struct cfg_params *cfg = get_global_cfg_params();
    if (!cfg->stack_interrupt) {
        return 0;
    }

    for (stack_id = 0; stack_id < cfg->num_queue; stack_id++) {
        struct intr_config *intr_config = intr_config_get(stack_id);
        intr_config->epoll_fd = posix_api->epoll_create_fn(1);
        if (intr_config->epoll_fd < 0) {
            LSTACK_LOG(ERR, LSTACK, "epoll create fd fialed, errno is %d\n", errno);
            return -1;
        }

        for (int i = 0; i < INTR_PORT_NUM; i++) {
            intr_config->dpdk_event.port_id[i] = INTR_INVALID_PORT;
        }

        if (intr_register(stack_id, INTR_REMOTE_EVENT, NULL) < 0) {
            LSTACK_LOG(ERR, LSTACK, "register intr failed\n");
            return -1;
        }
    }

    return 0;
}

static inline int add_fd_to_epoll(int fd, int epoll_fd)
{
    struct epoll_event event ;
    event.data.fd = fd ;
    event.events = EPOLLIN | EPOLLPRI | EPOLLRDHUP | EPOLLHUP ;
    int ret = posix_api->epoll_ctl_fn(epoll_fd, EPOLL_CTL_ADD, fd, &event);
    if (ret < 0) {
        LSTACK_LOG(ERR, LSTACK, "add fd %d to epoll fd %d failed errno:%d ret=%d.\n",
                   fd, epoll_fd, errno, ret);
        return ret;
    }

    return ret ;
}

static inline int intr_local_event_register(struct intr_config *config, void *priv)
{
    config->local_event.get_event = priv;
    return 0;
}

static int intr_dpdk_event_register(struct intr_config *config, void *priv)
{
    struct intr_dpdk_event_args *arg = priv;
    int i;

    if (arg == NULL) {
        return -1;
    }

    if (config->dpdk_event.rte_epfd <= 0) {
        config->dpdk_event.rte_epfd = posix_api->epoll_create_fn(1);
        if (config->dpdk_event.rte_epfd < 0) {
            LSTACK_LOG(ERR, LSTACK, "epoll create fd fialed, errno is %d\n", errno);
            return -1;
        }
        if (add_fd_to_epoll(config->dpdk_event.rte_epfd, config->epoll_fd) < 0) {
            return -1;
        }
    }

    for (i = 0; i < INTR_PORT_NUM; i++) {
        if (config->dpdk_event.port_id[i] == INTR_INVALID_PORT) {
            config->dpdk_event.port_id[i] = arg->port_id;
            break;
        }
    }
    config->dpdk_event.queue_id[i] = arg->queue_id;

    int data = ((arg->port_id) << CHAR_BIT) | arg->queue_id;
    if (rte_eth_dev_rx_intr_ctl_q(arg->port_id, arg->queue_id, config->dpdk_event.rte_epfd,
                                  RTE_INTR_EVENT_ADD, (void *)((uintptr_t)data)) < 0) {
        LSTACK_LOG(ERR, LSTACK, "rte_eth_dev_rx_intr_ctl_q failed, port(%d), queue(%d)\n",
                   arg->port_id, arg->queue_id);
        return -1;
    }
    return 0;
}

static int intr_remote_event_register(struct intr_config *config, void *priv)
{
    struct intr_remote_event *remote_event = &config->remote_event;
    if (remote_event->event_fd > 0) {
        return 0;
    }

    remote_event->event_fd = posix_api->eventfd_fn(0, 0);
    if (remote_event->event_fd < 0) {
        LSTACK_LOG(ERR, LSTACK, "event fd create failed\n");
        return -1;
    }
    return add_fd_to_epoll(remote_event->event_fd, config->epoll_fd);
}

int intr_register(uint16_t stack_id, enum intr_type type, void *priv)
{
    struct cfg_params *cfg = get_global_cfg_params();
    if (!cfg->stack_interrupt) {
        return 0;
    }

    struct intr_config *config = intr_config_get(stack_id);
    switch (type) {
        case INTR_DPDK_EVENT:
            return intr_dpdk_event_register(config, priv);
        case INTR_REMOTE_EVENT:
            return intr_remote_event_register(config, priv);
        case INTR_LOCAL_EVENT:
            return intr_local_event_register(config, priv);
        default:
            return -1;
    }
    return 0;
}

static inline void intr_remote_event_enable(struct intr_config *config)
{
    eventfd_t eventfd_num = 1;
    if (__atomic_load_n(&config->in_wait, __ATOMIC_ACQUIRE)) {
        posix_api->write_fn(config->remote_event.event_fd, &eventfd_num, sizeof(eventfd_t));
    }
}

static inline void intr_remote_event_disable(struct intr_config *config)
{
    eventfd_t read_num;
    posix_api->read_fn(config->remote_event.event_fd, &read_num, sizeof(eventfd_t));
}

static inline bool intr_local_event(struct intr_config *config)
{
    return config->local_event.get_event(config->stack_id);
}

void intr_wakeup(uint16_t stack_id, enum intr_type type)
{
    if (!get_global_cfg_params()->stack_interrupt) {
        return;
    }

    struct intr_config *config = intr_config_get(stack_id);
    switch (type) {
        case INTR_REMOTE_EVENT:
            intr_remote_event_enable(config);
            break;
        default:
            break;
    }
}

static inline void intr_dpdk_event_enable(struct intr_config *config)
{
    int i;
    int ret = 0;
    struct intr_dpdk_event *dpdk_event = &config->dpdk_event;

    for (i = 0; i < INTR_PORT_NUM; i++) {
        if (dpdk_event->port_id[i] != INTR_INVALID_PORT) {
            ret = rte_eth_dev_rx_intr_enable(dpdk_event->port_id[i], dpdk_event->queue_id[i]);
            if (ret != 0) {
                LSTACK_LOG(ERR, LSTACK, "port(%d) queue(%d) enable interrupt failed\n",
                           dpdk_event->port_id[i], dpdk_event->queue_id[i]);
                return;
            }
        }
    }
}

static inline void intr_dpdk_event_disable(struct intr_config *config)
{
    int i, n;
    void *data;
    uint16_t port_id;
    uint16_t queue_id;
    struct intr_dpdk_event *dpdk_event = &config->dpdk_event;
    struct rte_epoll_event event[INTR_MAX_EVENT_NUM];

    n = rte_epoll_wait(dpdk_event->rte_epfd, event, INTR_MAX_EVENT_NUM, 1);
    for (i = 0; i < n; i++) {
        data = event[i].epdata.data;
        port_id = ((uintptr_t)data) >> CHAR_BIT;
        queue_id = ((uintptr_t)data) & RTE_LEN2MASK(CHAR_BIT, uint8_t);

        rte_eth_dev_rx_intr_disable(port_id, queue_id);

        if (port_id == dpdk_event->port_id[0]) {
            config->stats.nic_event_cnt++;
        } else {
            config->stats.virtio_user_event_cnt++;
        }
    }
}

static inline void intr_policy_clear(struct intr_config *config)
{
    config->policy.no_event_cnt = 0;
}

static inline bool intr_policy(struct intr_config *config)
{
    if (config->policy.no_event_cnt++ < INTR_LOOP_TIMES) {
        return true;
    }
    config->policy.no_event_cnt = 0;
    return false;
}

static inline void intr_block(uint16_t stack_id, uint32_t timeout)
{
    struct epoll_event events[INTR_MAX_EVENT_NUM];
    struct intr_config *intr_config = intr_config_get(stack_id);

    /* in_wait need in here to avoid competion problem with remote event */
    __atomic_store_n(&intr_config->in_wait, true, __ATOMIC_RELEASE);
    if (intr_local_event(intr_config)) {
        intr_config->stats.local_event_cnt++;
        __atomic_store_n(&intr_config->in_wait, false, __ATOMIC_RELEASE);
        return;
    }

    intr_dpdk_event_enable(intr_config);

    int32_t event_cnt = posix_api->epoll_wait_fn(intr_config->epoll_fd, events, INTR_MAX_EVENT_NUM, timeout);
    __atomic_store_n(&intr_config->in_wait, false, __ATOMIC_RELEASE);
    for (int i = 0; i < event_cnt; i++) {
        if (events[i].data.fd == intr_config->dpdk_event.rte_epfd) {
            intr_dpdk_event_disable(intr_config);
        } else if (events[i].data.fd == intr_config->remote_event.event_fd) {
            intr_remote_event_disable(intr_config);
            intr_config->stats.remote_event_cnt++;
        } else {
            LSTACK_LOG(ERR, LSTACK, "unknow fd have event.\n");
        }
    }

    if (event_cnt < 0) {
        intr_config->stats.timeout_event_cnt++;
    }
}

void intr_wait(uint16_t stack_id, uint32_t timeout)
{
    struct intr_config *intr_config = intr_config_get(stack_id);

    if (intr_policy(intr_config)) {
        return;
    }

    intr_block(stack_id, timeout);

    intr_policy_clear(intr_config);
}

int intr_stats_get(uint16_t stack_id, void *ptr, int len)
{
    struct intr_config *config = intr_config_get(stack_id);
    if (len < sizeof(struct interrupt_stats)) {
        return -1;
    }

    return memcpy_s(ptr, len, &config->stats, sizeof(struct interrupt_stats));
}
