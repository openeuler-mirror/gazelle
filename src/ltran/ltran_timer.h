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

#ifndef __GAZELLE_TIMER_H__
#define __GAZELLE_TIMER_H__

struct gazelle_tcp_conn_htable;
struct gazelle_tcp_sock_htable;

void gazelle_detect_conn_logout(struct gazelle_tcp_conn_htable *conn_htable);
void gazelle_detect_sock_logout(struct gazelle_tcp_sock_htable *tcp_sock_htable);
void gazelle_delete_aging_conn(struct gazelle_tcp_conn_htable *conn_htable);

#endif