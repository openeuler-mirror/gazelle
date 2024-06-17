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

#include <rte_mbuf.h>

#include "lwip/sockets.h"
#include "lstack_ethdev.h"
#include "lstack_log.h"
#include "gazelle_opt.h"
#include "lstack_protocol_stack.h"
#include "lstack_tx_cache.h"

#define TX_CACHE_MAX              128
#define TX_CACHE_MASK             (TX_CACHE_MAX - 1)
#define TX_CACHE_INDEX(index)     ((index) & TX_CACHE_MASK)

struct tx_cache {
    uint16_t port_id;
    uint16_t queue_id;

    uint32_t send_start;
    uint32_t send_end;
    struct rte_mbuf *send_pkts[TX_CACHE_MAX];

    uint64_t send_pkts_fail;
    void *priv;
};
struct lstack_dev_ops g_tx_cache_dev_ops;

static uint32_t tx_cache_recv(struct protocol_stack *stack, struct rte_mbuf **pkts, uint32_t nr_pkts);

struct tx_cache *g_tx_cache[PROTOCOL_STACK_MAX];

int tx_cache_init(uint16_t queue_id, void *priv, struct lstack_dev_ops *dev_ops)
{
    struct tx_cache *tx_cache = calloc(1, sizeof(struct tx_cache));
    if (tx_cache == NULL) {
        LSTACK_LOG(ERR, LSTACK, "queue(%d) tx cache init failed\n", queue_id);
    }

    tx_cache->queue_id = queue_id;
    tx_cache->priv = priv;
    g_tx_cache[queue_id] = tx_cache;

    g_tx_cache_dev_ops.tx_xmit = dev_ops->tx_xmit;
    dev_ops->tx_xmit = tx_cache_recv;

    return 0;
}

int tx_cache_send(uint16_t queue_id)
{
    struct tx_cache *tx_cache = g_tx_cache[queue_id];
    if (tx_cache == NULL) {
        LSTACK_LOG(ERR, LSTACK, "queue(%d) tx cache get failed\n", queue_id);
        return 0;
    }

    uint32_t send_num = tx_cache->send_end - tx_cache->send_start;
    if (send_num == 0) {
        return 0;
    }

    uint32_t start = tx_cache->send_start & TX_CACHE_MASK;
    uint32_t end = tx_cache->send_end & TX_CACHE_MASK;
    uint32_t sent_pkts = 0;
    if (start < end) {
        sent_pkts = g_tx_cache_dev_ops.tx_xmit(tx_cache->priv, &tx_cache->send_pkts[start], send_num);
    } else {
        send_num = TX_CACHE_MAX - start;
        sent_pkts = g_tx_cache_dev_ops.tx_xmit(tx_cache->priv,  &tx_cache->send_pkts[start], send_num);
        if (sent_pkts == send_num) {
            sent_pkts += g_tx_cache_dev_ops.tx_xmit(tx_cache->priv, tx_cache->send_pkts, end);
        }
    }

    tx_cache->send_start += sent_pkts;
    return sent_pkts;
}

static uint32_t tx_cache_recv(struct protocol_stack *stack, struct rte_mbuf **pkts, uint32_t nr_pkts)
{
    if (nr_pkts != 1) {
        LSTACK_LOG(ERR, LSTACK, "arg not support, nr_pkts is %d\n", nr_pkts);
        return 0;
    }
    uint16_t queue_id = stack->queue_id;
    struct tx_cache *tx_cache = g_tx_cache[queue_id];
    if (tx_cache == NULL) {
        LSTACK_LOG(ERR, LSTACK, "queue(%d) tx cache get failed\n", queue_id);
        return 0;
    }

    do {
        if (TX_CACHE_INDEX(tx_cache->send_end + 1) != TX_CACHE_INDEX(tx_cache->send_start)) {
            tx_cache->send_pkts[TX_CACHE_INDEX(tx_cache->send_end)] = pkts[0];
            tx_cache->send_end++;
            return nr_pkts;
        }

        tx_cache_send(queue_id);
    } while (1);

    return 0;
}
