# Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
# gazelle is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.12.1)
project(gazelle_test)

set(SDK_PATH /usr/include/dpdk)
set(LWIP_PATH /usr/include/lwip)
set(LIB_PATH ${PROJECT_SOURCE_DIR}/../../../src/lstack/include)
set(SRC_PATH ${PROJECT_SOURCE_DIR}/../../../src/lstack/core)
add_executable(lstack_config_fuzz lstack_config_fuzz.c ${SRC_PATH}/lstack_cfg.c)

target_compile_options(lstack_config_fuzz PRIVATE -DUSE_LIBOS_MEM)

SET(EXECUTABLE_OUTPUT_PATH ../)

target_include_directories(lstack_config_fuzz PRIVATE ${LIB_PATH} ${SDK_PATH} ${LWIP_PATH} ${COMMON_PATH})
target_link_libraries(lstack_config_fuzz PRIVATE  pthread config securec liblwip.a common_obj)
