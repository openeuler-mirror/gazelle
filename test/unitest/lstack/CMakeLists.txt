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
project(gazelle_unittest)

set(SRC_PATH ../../../src/lstack/core)
set(COMMON_PATH ../../../src/common)
set(LIB_PATH ../../../src/lstack /usr/include/dpdk /usr/include/lwip ${COMMON_PATH} ../../../src/lstack/include /usr/lib64)
set(EXECUTABLE_OUTPUT_PATH ../)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -g -fprofile-arcs -ftest-coverage -lgcov")

set(LIBRTE_LIB rte_pci rte_bus_pci rte_cmdline rte_hash rte_mempool rte_mempool_ring rte_timer rte_eal rte_ring rte_mbuf rte_kni rte_net_ixgbe rte_ethdev rte_net rte_kvargs)

add_executable(lstack_test lstack_param_test.c stub.c main.c ${SRC_PATH}/lstack_cfg.c ${COMMON_PATH}/gazelle_parse_config.c)
target_include_directories(lstack_test PRIVATE ${LIB_PATH})
target_link_libraries(lstack_test PRIVATE config boundscheck cunit lwip pthread ${LIBRTE_LIB})
#target_link_libraries(lstack_param_test PRIVATE config cunit)

target_compile_options(lstack_test PRIVATE -DUSE_LIBOS_MEM)
