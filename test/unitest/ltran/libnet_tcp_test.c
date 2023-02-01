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

#include <stdlib.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <securec.h>
#include "ltran_tcp_sock.h"
#include "ltran_tcp_conn.h"

#define MAX_CONN 10
#define MAX_SOCK 10
void test_tcp_conn(void)
{
    struct gazelle_tcp_conn_htable *tcp_conn_htable = NULL;
    struct gazelle_tcp_conn *tcp_conn = NULL;
    struct gazelle_tcp_conn *exist_tcp_conn = NULL;
    struct gazelle_quintuple quintuple;
    /* 1: set instance on */
    int32_t instance_cur_tick = 1;

    tcp_conn_htable = gazelle_tcp_conn_htable_create(MAX_CONN);
    CU_ASSERT(tcp_conn_htable != NULL);
    gazelle_set_tcp_conn_htable(tcp_conn_htable);

    quintuple.src_ip = inet_addr("192.168.1.1");
    quintuple.dst_ip = inet_addr("192.168.1.2");
    quintuple.src_port = 22; /* 22:src port id */
    quintuple.dst_port = 23; /* 23:dst port id */
    quintuple.protocol = 0;
    tcp_conn = gazelle_conn_add_by_quintuple(gazelle_get_tcp_conn_htable(), &quintuple);
    CU_ASSERT(tcp_conn != NULL);
    tcp_conn->instance_cur_tick = &instance_cur_tick;
    /* 1: set instacn_cur_tick = instance_reg_tick indicate instance is on */
    tcp_conn->instance_reg_tick = 1;

    exist_tcp_conn = gazelle_conn_get_by_quintuple(gazelle_get_tcp_conn_htable(), &quintuple);
    CU_ASSERT(exist_tcp_conn != NULL);

    gazelle_conn_del_by_quintuple(gazelle_get_tcp_conn_htable(),  &quintuple);
    exist_tcp_conn = gazelle_conn_get_by_quintuple(gazelle_get_tcp_conn_htable(), &quintuple);
    CU_ASSERT(exist_tcp_conn == NULL);

    gazelle_conn_del_by_quintuple(gazelle_get_tcp_conn_htable(),  &quintuple);

    for (int i = 0; i <= MAX_CONN; i++) {
        quintuple.src_port++;
        tcp_conn = gazelle_conn_add_by_quintuple(gazelle_get_tcp_conn_htable(), &quintuple);
        if (i < MAX_CONN) {
            CU_ASSERT(tcp_conn != NULL);
            tcp_conn->instance_cur_tick = &instance_cur_tick;
            /* 1: set instacn_cur_tick = instance_reg_tick indicate instance is on */
            tcp_conn->instance_reg_tick = 1;
        } else {
            CU_ASSERT(tcp_conn == NULL);
        }

        tcp_conn = gazelle_conn_get_by_quintuple(gazelle_get_tcp_conn_htable(), &quintuple);
        if (i < MAX_CONN) {
            CU_ASSERT(tcp_conn != NULL);
        } else {
            CU_ASSERT(tcp_conn == NULL);
        }
    }

    gazelle_tcp_conn_htable_destroy();
}

void test_tcp_sock(void)
{
    char ip_str[16] = {0};
    struct in_addr tmp_subnet;
    struct gazelle_tcp_sock *tcp_sock = NULL;
    struct gazelle_tcp_sock *exist_tcp_sock = NULL;
    /* 1: set instance on */
    int32_t instance_cur_tick = 1;

    gazelle_set_tcp_sock_htable(gazelle_tcp_sock_htable_create(MAX_SOCK));
    gazelle_set_tcp_conn_htable(gazelle_tcp_conn_htable_create(GAZELLE_MAX_CONN_NUM));

    /* 22:dst port id  1111:dst tid number */
    tcp_sock = gazelle_sock_add_by_ipporttid(gazelle_get_tcp_sock_htable(), inet_addr("192.168.1.1"), 22, 1111);
    CU_ASSERT(tcp_sock != NULL);
    CU_ASSERT(tcp_sock->tid == 1111); /* 1111:tid number */
    CU_ASSERT(tcp_sock->port == 22); /* 22:port id */

    tmp_subnet.s_addr = tcp_sock->ip;
    CU_ASSERT(strcmp(inet_ntoa(tmp_subnet), "192.168.1.1") == 0);
    tcp_sock->instance_cur_tick = &instance_cur_tick;
    /* 1: set instacn_cur_tick = instance_reg_tick indicate instance is on */
    tcp_sock->instance_reg_tick = 1;

    /* 22:port id */
    exist_tcp_sock = gazelle_sock_get_by_min_conn(gazelle_get_tcp_sock_htable(), inet_addr("192.168.1.1"), 22);
    CU_ASSERT(exist_tcp_sock != NULL);
    CU_ASSERT(exist_tcp_sock->tid == 1111); /* 1111:tid number */

    /* 22:dst port id  1111:dst tid number */
    gazelle_sock_del_by_ipporttid(gazelle_get_tcp_sock_htable(), inet_addr("192.168.1.1"), 22, 1111);
    /* 22:dst port id */
    exist_tcp_sock = gazelle_sock_get_by_min_conn(gazelle_get_tcp_sock_htable(), inet_addr("192.168.1.1"), 22);
    CU_ASSERT(exist_tcp_sock == NULL);

    /* 22:port id 1111:dst tid number */
    gazelle_sock_del_by_ipporttid(gazelle_get_tcp_sock_htable(), inet_addr("192.168.1.1"), 22, 1111);

    for (int i = 0; i <= MAX_CONN; i++) {
        /* 22:dst port id  1111:dst tid number */
        tcp_sock = gazelle_sock_add_by_ipporttid(gazelle_get_tcp_sock_htable(), inet_addr("192.168.1.1"), 22, i);
        if (i < MAX_CONN) {
            CU_ASSERT(tcp_sock != NULL);
        } else {
            CU_ASSERT(tcp_sock == NULL);
        }
    }

    gazelle_tcp_sock_htable_destroy();
}
