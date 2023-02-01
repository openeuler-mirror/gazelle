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

#ifndef __LTRAN_TEST_CASE_H__
#define __LTRAN_TEST_CASE_H__

void test_ltran_stack(void);
void test_ltran_instance(void);
void test_ltran_normal_param(void);
void test_ltran_bad_params_clients(void);
void test_ltran_bad_params_port(void);
void test_ltran_bad_params_subnet(void);
void test_ltran_bad_params_bond_mode(void);
void test_ltran_bad_params_bond_miimon(void);
void test_ltran_bad_params_bond_mtu(void);
void test_ltran_bad_params_macs(void);
void test_tcp_conn(void);
void test_tcp_sock(void);

#endif
