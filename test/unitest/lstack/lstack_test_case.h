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

#ifndef __LSTACK_TEST_CASE_H__
#define __LSTACK_TEST_CASE_H__

void test_lstack_normal_param(void);
void test_lstack_bad_params_devices(void);
void test_lstack_bad_params_gateway_addr(void);
void test_lstack_bad_params_mask_addr(void);
void test_lstack_bad_params_host_addr(void);
void test_lstack_bad_params_num_cpus(void);
void test_lstack_bad_params_lowpower(void);

#endif
