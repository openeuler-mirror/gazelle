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

#include <rte_arp.h>
#include <rte_eal.h>
#include <rte_common.h>
#include <rte_version.h>

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
#include <rte_kni.h>
#endif

#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_memory.h>
#include <rte_prefetch.h>
#include <rte_ring.h>
#include <securec.h>

#include "common/dpdk_common.h"
#include "ltran_instance.h"
#include "ltran_tcp_conn.h"
#include "ltran_tcp_sock.h"
#include "ltran_stat.h"
#include "ltran_stack.h"
#include "ltran_base.h"
#include "ltran_log.h"
#include "ltran_param.h"
#include "ltran_ethdev.h"
#include "ltran_timer.h"
#include "ltran_forward.h"

#define POINTER_PER_CACHELINE     (RTE_CACHE_LINE_SIZE / sizeof(void *))
#define UPSTREAM_LOOP_TIMES 64
#define UP_ADJUST_THRESH    (GAZELLE_PACKET_READ_SIZE - 1)

__thread uint16_t g_port_index;

static __rte_always_inline struct gazelle_stack *get_kni_stack(void)
{
    static struct gazelle_stack kni_stack = {0};
    return &kni_stack;
}

static void calculate_ltran_latency(struct gazelle_stack *stack, const struct rte_mbuf *mbuf)
{
    struct latency_timestamp *lt;
    uint64_t latency;

    lt = &mbuf_to_private(mbuf)->lt;
    // valid check
    if (lt->stamp != ~(lt->check)) {
        return;
    }

    // time stamp must > start time
    if (lt->stamp < get_start_time_stamp()) {
        lt->stamp = 0;
        return;
    }

    latency = gazelle_now_us() - lt->stamp;

    stack->stack_stats.latency_total += latency;
    stack->stack_stats.latency_pkts++;
    stack->stack_stats.latency_max = (stack->stack_stats.latency_max > latency) ?
        stack->stack_stats.latency_max : latency;
    stack->stack_stats.latency_min = (stack->stack_stats.latency_min < latency) ?
        stack->stack_stats.latency_min : latency;
}

static __rte_always_inline void flush_rx_mbuf(struct gazelle_stack *stack, struct rte_mbuf *dst, struct rte_mbuf *src)
{
    copy_mbuf(dst, src);
    stack->stack_stats.rx_bytes += src->data_len;
    if (get_start_latency_flag() == GAZELLE_ON) {
        calculate_ltran_latency(stack, src);
    }
    rte_pktmbuf_free(src);
}

static __rte_always_inline void backup_bufs_enque_rx_ring(struct gazelle_stack *stack)
{
    uint32_t free_cnt, index, flush_cnt;
    uint32_t backup_size = BACKUP_MBUF_SIZE;
    struct rte_mbuf *free_buf[RING_MAX_SIZE];

    flush_cnt = (stack->backup_pkt_cnt < RING_MAX_SIZE) ? stack->backup_pkt_cnt : RING_MAX_SIZE;
    free_cnt = gazelle_ring_read(stack->rx_ring, (void **)free_buf, flush_cnt);

    for (uint32_t j = 0; j < free_cnt; j++) {
        index = (stack->backup_start + j) % backup_size;
        flush_rx_mbuf(stack, free_buf[j], stack->backup_pkt_buf[index]);
    }

    stack->stack_stats.rx += free_cnt;
    stack->backup_pkt_cnt -= free_cnt;
    stack->backup_start = (stack->backup_start + free_cnt) % backup_size;
    gazelle_ring_read_over(stack->rx_ring);
}

static __rte_always_inline void pktbufs_move_to_backup_bufs(struct gazelle_stack *stack, struct rte_mbuf **mbuf,
    uint32_t mbuf_cnt)
{
    uint32_t backup_size = BACKUP_MBUF_SIZE;
    uint32_t backup_tail = (stack->backup_start + stack->backup_pkt_cnt) % backup_size;
    uint32_t index, j;
    uint32_t pkt_cnt = mbuf_cnt;

    if (stack->backup_pkt_cnt + mbuf_cnt > backup_size) {
        pkt_cnt = backup_size - stack->backup_pkt_cnt;
        stack->stack_stats.rx_drop += mbuf_cnt - pkt_cnt;
        for (j = pkt_cnt; j < mbuf_cnt; j++) {
            rte_pktmbuf_free(mbuf[j]);
            mbuf[j] = NULL;
        }
    }
    stack->backup_pkt_cnt += pkt_cnt;

    for (j = 0; j < pkt_cnt; j++) {
        index = (backup_tail + j) % backup_size;
        stack->backup_pkt_buf[index] = mbuf[j];
    }
}

static __rte_always_inline uint32_t pkt_bufs_enque_rx_ring(struct gazelle_stack *stack)
{
    uint32_t free_cnt, j;
    struct rte_mbuf **cl_buffer = stack->pkt_buf;
    struct rte_mbuf *free_buf[GAZELLE_PACKET_READ_SIZE];

    free_cnt = gazelle_ring_read(stack->rx_ring, (void **)free_buf, stack->pkt_cnt);
    stack->stack_stats.rx += free_cnt;

    /* this prefetch and copy code, only 50~60 instruction, but never spend less than 70 cycle.
        even if we enlarge the PREFETCH_OFFSET, I think it because memory&cache problem. */
#define COPY_PREFETCH_OFFSET        2
#define COPY_PREFETCH_OFFSET_FORWARD    (COPY_PREFETCH_OFFSET * 2)
    if (likely(free_cnt > COPY_PREFETCH_OFFSET_FORWARD)) {
        uint8_t *src_data = NULL;
        uint8_t *dst_data = NULL;
        uint32_t free_cnt_int = free_cnt;
        /* Prefetch first packets */
        for (j = 0; j < COPY_PREFETCH_OFFSET; j++) {
            rte_prefetch0(cl_buffer[j]);
            rte_prefetch0(free_buf[j]);
        }

        for (j = 0; j < COPY_PREFETCH_OFFSET_FORWARD; j++) {
            rte_prefetch0(cl_buffer[j + COPY_PREFETCH_OFFSET]);
            rte_prefetch0(free_buf[j + COPY_PREFETCH_OFFSET]);
            src_data = rte_pktmbuf_mtod(cl_buffer[j], void*);
            dst_data = rte_pktmbuf_mtod(free_buf[j], void*);
            rte_prefetch0(src_data);
            rte_prefetch0(dst_data);
        }

        /* Prefetch and forward already prefetched packets */
        for (j = 0; j < (free_cnt_int - COPY_PREFETCH_OFFSET_FORWARD); j++) {
            rte_prefetch0(cl_buffer[j + COPY_PREFETCH_OFFSET_FORWARD]);
            rte_prefetch0(free_buf[j + COPY_PREFETCH_OFFSET_FORWARD]);
            src_data = rte_pktmbuf_mtod(cl_buffer[j + COPY_PREFETCH_OFFSET], void*);
            dst_data = rte_pktmbuf_mtod(free_buf[j + COPY_PREFETCH_OFFSET], void*);
            rte_prefetch0(src_data);
            rte_prefetch0(dst_data);
            flush_rx_mbuf(stack, free_buf[j], cl_buffer[j]);
        }

        rte_prefetch0(&stack->rx_ring->prod.tail);
        rte_prefetch0(&stack->rx_ring->prod.head);
        rte_prefetch0(&stack->rx_ring->mask);

        /* Forward remaining prefetched packets */
        for (; j < free_cnt_int; j++) {
            flush_rx_mbuf(stack, free_buf[j], cl_buffer[j]);
        }
    } else {
        for (j = 0; j < free_cnt; j++) {
            flush_rx_mbuf(stack, free_buf[j], cl_buffer[j]);
        }
    }

    if (likely(free_cnt != 0)) {
        gazelle_ring_read_over(stack->rx_ring);
    }

    return free_cnt;
}

static __rte_always_inline void flush_rx_ring(struct gazelle_stack *stack)
{
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
    if (unlikely(stack == get_kni_stack())) {
        // if fail, free mbuf inside
        kni_process_tx(stack->pkt_buf, stack->pkt_cnt);
        get_statistics()->port_stats[g_port_index].kni_pkt += stack->pkt_cnt;
        stack->pkt_cnt = 0;
        return;
    }
#endif

    /* first flush backup mbuf pointer avoid packet disorder */
    if (unlikely(stack->backup_pkt_cnt > 0)) {
        backup_bufs_enque_rx_ring(stack);
        /* backup can't clear. mbuf into backup */
        if (stack->backup_pkt_cnt > 0) {
            pktbufs_move_to_backup_bufs(stack, stack->pkt_buf, stack->pkt_cnt);
            stack->pkt_cnt = 0;
            return;
        }
    }

    uint32_t flush_cnt = pkt_bufs_enque_rx_ring(stack);
    /* can't flush mbuf into backup */
    if (unlikely(flush_cnt < stack->pkt_cnt)) {
        pktbufs_move_to_backup_bufs(stack, &(stack->pkt_buf[flush_cnt]), stack->pkt_cnt - flush_cnt);
    }
    stack->pkt_cnt = 0;
}

static __rte_always_inline void enqueue_rx_packet(struct gazelle_stack* stack, struct rte_mbuf *buf)
{
    stack->pkt_buf[stack->pkt_cnt++] = buf;
    if (unlikely(stack->pkt_cnt >= GAZELLE_PACKET_READ_SIZE)) {
        rte_prefetch0(&stack->pkt_buf[0 * POINTER_PER_CACHELINE]);
        rte_prefetch0(&stack->pkt_buf[1 * POINTER_PER_CACHELINE]);
        rte_prefetch0(&stack->pkt_buf[2 * POINTER_PER_CACHELINE]);
        rte_prefetch0(stack->rx_ring);
        rte_prefetch0(&stack->rx_ring->prod.tail);
        rte_prefetch0(&stack->rx_ring->prod.head);
        rte_prefetch0(&stack->rx_ring->cons.head);
        rte_prefetch0(&stack->rx_ring->mask);

        flush_rx_ring(stack);
    }
}

static __rte_always_inline int32_t tcp_handle(struct rte_mbuf *m, const struct rte_ipv4_hdr *ipv4_hdr,
                                          const struct rte_tcp_hdr *tcp_hdr)
{
    struct gazelle_tcp_conn *tcp_conn = NULL;
    struct gazelle_tcp_sock *tcp_sock = NULL;
    struct gazelle_quintuple quintuple = {0};

    quintuple.dst_ip.u_addr.ip4.addr = ipv4_hdr->dst_addr;
    quintuple.src_ip.u_addr.ip4.addr = ipv4_hdr->src_addr;
    quintuple.dst_port = tcp_hdr->dst_port;
    quintuple.src_port = tcp_hdr->src_port;
    quintuple.protocol = 0;

    tcp_conn = gazelle_conn_get_by_quintuple(gazelle_get_tcp_conn_htable(), &quintuple);
    if (likely(tcp_conn != NULL)) {
        // conn already established
        enqueue_rx_packet(tcp_conn->stack, m);
        return GAZELLE_OK;
    }

    tcp_sock = gazelle_sock_get_by_min_conn(gazelle_get_tcp_sock_htable(),
                                                    quintuple.dst_ip.u_addr.ip4.addr, quintuple.dst_port);
    if (unlikely(tcp_sock == NULL)) {
        return GAZELLE_ERR;
    }

    tcp_conn = gazelle_conn_add_by_quintuple(gazelle_get_tcp_conn_htable(), &quintuple);
    if (unlikely(tcp_conn == NULL)) {
        return GAZELLE_ERR;
    }
    tcp_conn->conn_timeout = GAZELLE_CONN_TIMEOUT;
    tcp_conn->stack = tcp_sock->stack;
    tcp_conn->sock = tcp_sock;
    tcp_conn->tid = tcp_sock->tid;
    tcp_conn->instance_cur_tick = tcp_sock->instance_cur_tick;
    tcp_conn->instance_reg_tick = tcp_sock->instance_reg_tick;

    tcp_sock->tcp_con_num++;
    enqueue_rx_packet(tcp_sock->stack, m);
    return GAZELLE_OK;
}

static uint32_t get_vlan_offset(const struct rte_mbuf *m)
{
    uint32_t offset = 0;
    struct rte_ether_hdr *ethh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    u16_t type = ethh->ether_type;
    if (type == PP_HTONS(RTE_ETHER_TYPE_VLAN)) {
        offset += sizeof(struct rte_vlan_hdr);
    }
    return offset;
}

static struct gazelle_stack* get_icmp_handle_stack(const struct rte_mbuf *m)
{
    int32_t i;
    struct gazelle_stack** stack_array = NULL;
    struct rte_ipv4_hdr *ipv4_hdr = NULL;
    struct gazelle_instance *instance = NULL;
    uint32_t offset = get_vlan_offset(m);

    ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr) + offset);
    instance = gazelle_instance_get_by_ip(get_instance_mgr(), ipv4_hdr->dst_addr);
    if (instance == NULL) {
        return NULL;
    }

    stack_array = instance->stack_array;
    for (i = 0; i < GAZELLE_MAX_STACK_ARRAY_SIZE; i++) {
        if (stack_array[i] != NULL && INSTANCE_IS_ON(stack_array[i])) {
            return stack_array[i];
        }
    }

    return NULL;
}

static __rte_always_inline int32_t icmp_handle(struct rte_mbuf *m)
{
    struct gazelle_stack *icmp_stack = NULL;
    icmp_stack = get_icmp_handle_stack(m);

    if (icmp_stack != NULL) {
        enqueue_rx_packet(icmp_stack, m);
        return GAZELLE_OK;
    }

    return GAZELLE_ERR;
}

static __rte_always_inline int32_t ipv4_handle(struct rte_mbuf *m, struct rte_ipv4_hdr *ipv4_hdr)
{
    struct rte_tcp_hdr  *tcp_hdr = NULL;
    int32_t ret = -1;
    uint32_t offset = get_vlan_offset(m);

    if (likely(ipv4_hdr->next_proto_id == IPPROTO_TCP)) {
        tcp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) +
                                          sizeof(struct rte_ipv4_hdr) + offset);
        get_statistics()->port_stats[g_port_index].tcp_pkt++;
        ret = tcp_handle(m, ipv4_hdr, tcp_hdr);
    } else if (ipv4_hdr->next_proto_id == IPPROTO_ICMP) {
        get_statistics()->port_stats[g_port_index].icmp_pkt++;
        ret = icmp_handle(m);
    }
    return ret;
}

static __rte_always_inline void arp_handle(struct rte_mbuf *m)
{
    uint32_t offset = get_vlan_offset(m);
    struct rte_arp_hdr *arph = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr) + offset);

    get_statistics()->port_stats[g_port_index].arp_pkt++;

    /* arp pkt forward to every lwip stack */
    struct gazelle_instance_mgr *mgr = get_instance_mgr();
    for (uint32_t i = 0; i < GAZELLE_MAX_INSTANCE_NUM; i++) {
        struct gazelle_instance *instance = mgr->instances[i];
        if (instance == NULL || instance->ip_addr.s_addr != arph->arp_data.arp_tip) {
            continue;
        }

        struct gazelle_stack **stack_array = instance->stack_array;
        for (uint32_t j = 0; j < instance->stack_cnt; j++) {
            if (stack_array[j] != NULL && INSTANCE_IS_ON(stack_array[j])) {
                struct rte_mbuf *m_copy = rte_pktmbuf_alloc(m->pool);
                if (m_copy == NULL) {
                    LTRAN_ERR("copy mbuf failed in arp_handle. \n");
                    return;
                }
                copy_mbuf(m_copy, m);
                // send and free m_copy in enqueue_rx_packet
                enqueue_rx_packet(stack_array[j], m_copy);
            }
        }
    }
}

static __rte_always_inline void upstream_forward_one(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *iph = NULL;
    uint8_t ip_version;
    const int32_t ipv4_version_offset = 4;
    const int32_t ipv4_version = 4;
    uint32_t offset = get_vlan_offset(m);

    get_statistics()->port_stats[g_port_index].rx_bytes += m->data_len;

    iph = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr) + offset);
    ip_version = (iph->version_ihl & 0xf0) >> ipv4_version_offset;
    if (likely(ip_version == ipv4_version)) {
        int32_t ret = ipv4_handle(m, iph);
        if (ret == 0) {
            return;
        }
        // fail to process ipv4 packet
        goto forward_to_kni;
    }

    uint16_t type = 0;
    if (offset > 0) {
        struct rte_vlan_hdr *vlan_hdr = rte_pktmbuf_mtod_offset(m, struct rte_vlan_hdr *, sizeof(struct rte_ether_hdr));
        type = vlan_hdr->eth_proto;
    } else {
        struct rte_ether_hdr *ethh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        type = ethh->ether_type;
    }
    if (unlikely(RTE_BE16(RTE_ETHER_TYPE_ARP) == type)) {
        arp_handle(m);
        // arp packets are sent to kni by default
        goto forward_to_kni;
    }

forward_to_kni:
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
    if (get_ltran_config()->dpdk.kni_switch == GAZELLE_ON) {
        enqueue_rx_packet(get_kni_stack(), m);
    } else
#endif
    {
        rte_pktmbuf_free(m);
    }
    return;
}

static __rte_always_inline void msg_to_quintuple(struct gazelle_quintuple *transfer_qtuple,
                                                 const struct reg_ring_msg *msg)
{
    const struct gazelle_quintuple *qtuple = &msg->qtuple;

    transfer_qtuple->protocol = qtuple->protocol;
    transfer_qtuple->src_port = qtuple->dst_port;
    transfer_qtuple->src_ip   = qtuple->dst_ip;
    transfer_qtuple->dst_port = qtuple->src_port;
    transfer_qtuple->dst_ip   = qtuple->src_ip;
}

static __rte_always_inline void tcp_hash_table_del_conn(struct gazelle_quintuple *transfer_qtuple)
{
    struct gazelle_tcp_conn *tcp_conn = NULL;

    tcp_conn = gazelle_conn_get_by_quintuple(gazelle_get_tcp_conn_htable(), transfer_qtuple);
    if (tcp_conn == NULL) {
        return;
    }

    if (tcp_conn->sock != NULL) {
        if (tcp_conn->sock->tcp_con_num > 0) {
            tcp_conn->sock->tcp_con_num--;
        }
    }

    gazelle_conn_del_by_quintuple(gazelle_get_tcp_conn_htable(), transfer_qtuple);
}

static __rte_always_inline void tcp_hash_table_add_conn(struct gazelle_stack *stack,
    struct gazelle_quintuple *transfer_qtuple, uint32_t tid)
{
    struct gazelle_tcp_conn *tcp_conn = NULL;
    struct gazelle_tcp_conn_htable *conn_htable = gazelle_get_tcp_conn_htable();

    tcp_conn = gazelle_conn_get_by_quintuple(conn_htable, transfer_qtuple);
    if (tcp_conn) {
        /* When lstack is the server, conn is created in tcp_handle func. lwip send the connect command after
	     * receiving syn, and delete conn timeout. */
	    if (tcp_conn->conn_timeout >= 0) {
            tcp_conn->conn_timeout = -1;
            return;
	    } else {
	        /* del old invalid conn */
            gazelle_conn_del_by_quintuple(conn_htable, transfer_qtuple);
	    }
    }

    /* When lstack is the client, lwip send the connect command while calling connect func. conn is created
       without a timeout */
    tcp_conn = gazelle_conn_add_by_quintuple(conn_htable, transfer_qtuple);
    if (tcp_conn == NULL) {
        LTRAN_ERR("add tcp conn htable failed\n");
        return;
    }
    tcp_conn->stack = stack;
    tcp_conn->tid = tid;
    tcp_conn->conn_timeout = -1;
    tcp_conn->instance_reg_tick = stack->instance_reg_tick;
    tcp_conn->instance_cur_tick = stack->instance_cur_tick;
}

static void tcp_hash_table_modify(struct gazelle_stack *stack, const struct reg_ring_msg *msg)
{
    struct gazelle_tcp_sock *tcp_sock = NULL;
    // quintuple for ltran transfer
    struct gazelle_quintuple transfer_qtuple;

    msg_to_quintuple(&transfer_qtuple, msg);

    switch (msg->type) {
        case REG_RING_TCP_LISTEN:
            /* add sock htable */
            tcp_sock = gazelle_sock_add_by_ipporttid(gazelle_get_tcp_sock_htable(),
                transfer_qtuple.dst_ip.u_addr.ip4.addr, transfer_qtuple.dst_port, msg->tid);
            if (tcp_sock == NULL) {
                LTRAN_ERR("add tcp sock htable failed\n");
                break;
            }
            tcp_sock->instance_reg_tick = stack->instance_reg_tick;
            tcp_sock->instance_cur_tick = stack->instance_cur_tick;
            tcp_sock->stack = stack;
            break;
        case REG_RING_TCP_LISTEN_CLOSE:
            /* del sock htable */
            gazelle_sock_del_by_ipporttid(gazelle_get_tcp_sock_htable(),
                transfer_qtuple.dst_ip.u_addr.ip4.addr, transfer_qtuple.dst_port, msg->tid);
            break;
        case REG_RING_TCP_CONNECT:
            /* add conn htable */
            tcp_hash_table_add_conn(stack, &transfer_qtuple, msg->tid);
            break;
        case REG_RING_TCP_CONNECT_CLOSE:
            tcp_hash_table_del_conn(&transfer_qtuple);
            break;
        default:
            LTRAN_ERR("unknown REG_RING type\n");
            break;
    }
}

static __rte_always_inline void tcp_hash_table_handle(struct gazelle_stack *stack)
{
    void *pkts[PACKET_READ_SIZE];
    struct gazelle_tcp_sock_htable *sock_htable = gazelle_get_tcp_sock_htable();

    if (gazelle_ring_readable_count(stack->reg_ring) == 0) {
        return;
    }

    if (pthread_mutex_trylock(&sock_htable->mlock) != 0) {
        return;
    }

    uint32_t num = gazelle_ring_read(stack->reg_ring, pkts, PACKET_READ_SIZE);

    for (uint32_t i = 0; i < num; i++) {
        tcp_hash_table_modify(stack, pkts[i]);
        pkts[i] = NULL;
    }

    gazelle_ring_read_over(stack->reg_ring);
    if (pthread_mutex_unlock(&sock_htable->mlock) != 0) {
        LTRAN_WARN("write tcp_htable: unlock failed, errno %d\n", errno);
    }
}


static __rte_always_inline void flush_all_stack(void)
{
    struct gazelle_instance *instance = NULL;
    struct gazelle_stack** stack_array = NULL;
    struct gazelle_instance_mgr * instance_mgr = get_instance_mgr();

    for (uint32_t i = 0; i < instance_mgr->max_instance_num; i++) {
        instance = instance_mgr->instances[i];
        if (instance == NULL) {
            continue;
        }

        stack_array = instance->stack_array;
        for (uint32_t j = 0; j < instance->stack_cnt; j++) {
            if (stack_array[j] != NULL && INSTANCE_IS_ON(stack_array[j])) {
                tcp_hash_table_handle(stack_array[j]);
                flush_rx_ring(stack_array[j]);
            }
        }
    }
}

#define FWD_PREFETCH_OFFSET_ALREADY (FWD_PREFETCH_OFFSET * 2)
#define FWD_PREFETCH_OFFSET    2
static __rte_always_inline void upstream_forward_loop(uint32_t port_id, uint32_t queue_id)
{
    uint16_t i;
    uint16_t rx_count;
    uint32_t loop_cnt;
    uint64_t time_stamp = 0;

    struct rte_mbuf *buf[GAZELLE_PACKET_READ_SIZE] __rte_cache_aligned;
    for (loop_cnt = 0; loop_cnt < UPSTREAM_LOOP_TIMES; loop_cnt++) {
        if (get_start_latency_flag() == GAZELLE_ON) {
            time_stamp = gazelle_now_us();
        }

        rx_count = rte_eth_rx_burst(port_id, queue_id, buf, GAZELLE_PACKET_READ_SIZE);

        if (get_start_latency_flag() == GAZELLE_ON) {
            time_stamp_into_mbuf(rx_count, buf, time_stamp);
        }

        get_statistics()->port_stats[g_port_index].rx_iter_arr[rx_count]++;
        get_statistics()->port_stats[g_port_index].rx += rx_count;

        if (unlikely(rx_count < FWD_PREFETCH_OFFSET_ALREADY)) {
            for (i = 0; i < rx_count; i++) {
                upstream_forward_one(buf[i]);
            }
            break;
        }

        /* Prefetch first packets */
        for (i = 0; i < FWD_PREFETCH_OFFSET; i++) {
            rte_prefetch0(buf[i]);
        }

        for (i = 0; i < FWD_PREFETCH_OFFSET; i++) {
            rte_prefetch0(rte_pktmbuf_mtod(buf[i], void *));
            rte_prefetch0(buf[i + FWD_PREFETCH_OFFSET]);
        }

        /* Prefetch and forward already prefetched packets */
        for (i = 0; i < (rx_count - FWD_PREFETCH_OFFSET_ALREADY); i++) {
            rte_prefetch0(rte_pktmbuf_mtod(buf[i + FWD_PREFETCH_OFFSET], void *));
            rte_prefetch0(buf[i + FWD_PREFETCH_OFFSET_ALREADY]);
            upstream_forward_one(buf[i]);
        }

        for (; i < (rx_count - FWD_PREFETCH_OFFSET); i++) {
            rte_prefetch0(rte_pktmbuf_mtod(buf[i + FWD_PREFETCH_OFFSET], void *));
            upstream_forward_one(buf[i]);
        }

        /* Forward remaining prefetched packets */
        for (; i < rx_count; i++) {
            upstream_forward_one(buf[i]);
        }

        if (rx_count < UP_ADJUST_THRESH) {
            break;
        }
    }

    // After receiving packets from the NIC for 64 times, we sends the packets in the TX queue to each thread.
    flush_all_stack();
}

void upstream_forward(const uint16_t *port)
{
    g_port_index = *port;
    uint32_t queue_id;
    uint32_t queue_num = get_ltran_config()->bond.rx_queue_num;
    uint32_t port_id = get_bond_port()[g_port_index];
    unsigned long now_time;
    unsigned long last_time = gazelle_now_us();
    unsigned long aging_conn_last_time = last_time;

    while (get_ltran_stop_flag() != GAZELLE_TRUE) {
        for (queue_id = 0; queue_id < queue_num; queue_id++) {
            upstream_forward_loop(port_id, queue_id);
        }

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
        if (get_ltran_config()->dpdk.kni_switch == GAZELLE_ON) {
            flush_rx_ring(get_kni_stack());
            rte_kni_handle_request(get_gazelle_kni());
        }
#endif

        now_time = gazelle_now_us();
        if (now_time - aging_conn_last_time > GAZELLE_CONN_INTERVAL) {
            gazelle_delete_aging_conn(gazelle_get_tcp_conn_htable());
            aging_conn_last_time = now_time;
        }

        if (now_time - last_time > get_ltran_config()->tcp_conn.tcp_conn_scan_interval) {
            gazelle_detect_conn_logout(gazelle_get_tcp_conn_htable());
            gazelle_detect_sock_logout(gazelle_get_tcp_sock_htable());
            last_time = now_time;
        }

        set_rx_loop_count();
    }

    LTRAN_DEBUG("ltran rx loop stop.\n");
}

static __rte_always_inline void downstream_forward_one(struct gazelle_stack *stack, uint32_t port_id, uint32_t queue_id)
{
    int32_t ret;
    uint32_t tx_pkts = 0;
    uint64_t tx_bytes = 0;
    struct rte_mempool** pktmbuf_txpool = get_pktmbuf_txpool();
    uint32_t used_cnt;

    struct rte_mbuf *used_pkts[GAZELLE_PACKET_READ_SIZE];
    used_cnt = gazelle_ring_read(stack->tx_ring, (void **)used_pkts, GAZELLE_PACKET_READ_SIZE);
    if (used_cnt == 0) {
        return;
    }
    stack->stack_stats.tx += used_cnt;

    struct rte_mbuf *dst_bufs[GAZELLE_PACKET_READ_SIZE];
    ret = rte_pktmbuf_alloc_bulk(pktmbuf_txpool[g_port_index], dst_bufs, used_cnt);
    if (ret != 0) {
        /* free pkts that not have be sent. */
        LTRAN_ERR("down alloc error, rx_pkts:%u ret=%d.\n", used_cnt, ret);
        gazelle_ring_read_over(stack->tx_ring);
        stack->stack_stats.tx_drop += used_cnt;
        rte_exit(EXIT_FAILURE, "down alloc error\n");
    }

    for (tx_pkts = 0; tx_pkts < used_cnt; tx_pkts++) {
        copy_mbuf(dst_bufs[tx_pkts], used_pkts[tx_pkts]);
        tx_bytes += used_pkts[tx_pkts]->data_len;
        stack->stack_stats.tx_bytes += used_pkts[tx_pkts]->data_len;
    }
    gazelle_ring_read_over(stack->tx_ring);

    /* send packets anyway. */
    tx_pkts = 0;

    while (tx_pkts < used_cnt) {
        tx_pkts += rte_eth_tx_burst(port_id, queue_id,
                                    (struct rte_mbuf **)(&dst_bufs[tx_pkts]),
                                    used_cnt - tx_pkts);
        if (unlikely(rte_errno == ENOTSUP)) {
            for (; tx_pkts < used_cnt; tx_pkts++) {
                rte_pktmbuf_free(dst_bufs[tx_pkts]);
                stack->stack_stats.tx_drop++;
            }
        }
    }

    get_statistics()->port_stats[g_port_index].tx_bytes += tx_bytes;
    get_statistics()->port_stats[g_port_index].tx += tx_pkts;
}

static __rte_always_inline void downstream_forward_loop(uint32_t port_id, uint32_t queue_id)
{
    struct gazelle_instance_mgr * instance_mgr = get_instance_mgr();
    struct gazelle_stack** stack_array = NULL;
    struct gazelle_instance *instance = NULL;

    for (uint32_t i = 0; i < instance_mgr->max_instance_num; i++) {
        instance = instance_mgr->instances[i];
        if (instance == NULL) {
            continue;
        }

        stack_array = instance->stack_array;
        for (uint32_t j = 0; j < instance->stack_cnt; j++) {
            if (stack_array[j] != NULL && INSTANCE_IS_ON(stack_array[j])) {
                downstream_forward_one(stack_array[j], port_id, queue_id);
            }
        }
    }
}

int32_t downstream_forward(uint16_t *port)
{
    g_port_index = *port;
    uint32_t port_id = get_bond_port()[g_port_index];
    uint32_t queue_num = get_ltran_config()->bond.tx_queue_num;

    while (get_ltran_stop_flag() != GAZELLE_TRUE) {
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 0)
        /* kni rx means read from kni and send to nic */
        if (get_ltran_config()->dpdk.kni_switch == GAZELLE_ON &&
            get_kni_started()) {
            kni_process_rx(g_port_index);
        }
#endif

        for (uint32_t queue_id = 0; queue_id < queue_num; queue_id++) {
            downstream_forward_loop(port_id, queue_id);
        }
        /* avoid control_thread free memory when we visit tx_ring */
        set_tx_loop_count();
    }
    return 0;
}

