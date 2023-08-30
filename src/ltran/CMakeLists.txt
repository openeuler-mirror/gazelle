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
project(ltran)

set(COMMON_DIR ${PROJECT_SOURCE_DIR}/../common)
set(LWIP_DIR /usr/include/lwip)

set(CMAKE_VERBOSE_MAKEFILE ON)
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
	set(CMAKE_C_FLAGS "-g -fstack-protector-strong -Wall -Werror -fPIE -pie -pthread -D_FORTIFY_SOURCE=2 -O2 -fPIC")
elseif (CMAKE_C_COMPILER_ID STREQUAL "Clang")
	set(CMAKE_C_FLAGS "-O2 -g -fstack-protector-strong -Wall -Werror -fPIE -pthread")
endif()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D LTRAN_COMPILE")

if($ENV{GAZELLE_COVERAGE_ENABLE})
	message("Enable Coverage compile option")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ftest-coverage -fprofile-arcs")
endif($ENV{GAZELLE_COVERAGE_ENABLE})

if($ENV{DPDK_VERSION_1911})
    set(DPDK_DIR /usr/include/dpdk)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDPDK_VERSION_1911=1")
    set(DPDK_LINK_FLAGS "-Wl,-lrte_pmd_bond -Wl,-lrte_pmd_hinic -Wl,-lrte_pmd_ixgbe \
    -Wl,-lrte_pmd_pcap -Wl,-lrte_pmd_virtio")
    if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "loongarch64")
        set(DPDK_LINK_FLAGS "${DPDK_LINK_FLAGS} -Wl,-lrte_pmd_i40e")
    endif()
else()
    set(DPDK_DIR /usr/local/include/)
    set(DPDK_LINK_FLAGS "-Wl,-lrte_net_bond -Wl,-lrte_net_hinic -Wl,-lrte_net_ixgbe \
    -Wl,-lpcap -Wl,-lrte_net_pcap -Wl,-lrte_net_virtio -Wl,-lrte_pcapng -Wl,-lrte_telemetry")
    if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "loongarch64")
        set(DPDK_LINK_FLAGS "${DPDK_LINK_FLAGS} -Wl,-lrte_net_i40e")
    endif()
endif($ENV{DPDK_VERSION_1911})

add_executable(ltran main.c ltran_param.c ltran_config.c ltran_ethdev.c ltran_stat.c ltran_errno.c
				ltran_monitor.c ltran_instance.c ltran_stack.c ltran_tcp_conn.c ltran_tcp_sock.c
				ltran_forward.c ltran_timer.c ${COMMON_DIR}/gazelle_dfx_msg.c ${COMMON_DIR}/dpdk_common.c
                ${COMMON_DIR}/gazelle_parse_config.c)

target_include_directories(ltran PRIVATE ${COMMON_DIR} ${PROJECT_SOURCE_DIR} ${LWIP_DIR} ${DPDK_DIR})
target_compile_options(ltran PRIVATE -fno-strict-aliasing -D__ARM_FEATURE_CRC32=1 -DRTE_MACHINE_CPUFLAG_NEON
               -DRTE_MACHINE_CPUFLAG_CRC32 -DRTE_MACHINE_CPUFLAG_PMULL -DRTE_MACHINE_CPUFLAG_AES
               -DRTE_MACHINE_CPUFLAG_SHA1 -DRTE_MACHINE_CPUFLAG_SHA2 -include rte_config.h
               -D_GNU_SOURCE -W -Wall -Wstrict-prototypes -Wmissing-declarations -Wmissing-prototypes -Wold-style-definition
               -Wpointer-arith -Wcast-qual -Wnested-externs -Wformat-nonliteral -Wformat-security -Wundef
               -Wdeprecated -Wwrite-strings -Wno-implicit-fallthrough -D_FORTIFY_SOURCE=2)
if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "sw_64")
    target_compile_options(ltran PRIVATE -march=native -Wcast-align)
endif()

target_link_libraries(ltran PRIVATE config boundscheck rte_pdump -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wtrampolines)
set_target_properties(ltran PROPERTIES LINK_FLAGS "-L$ENV{DPDK_LIB_PATH} -Wl,--no-whole-archive \
    -Wl,-lrte_meter -Wl,--whole-archive -Wl,-lrte_gro -Wl,-lrte_hash -Wl,-lrte_kvargs -Wl,-lrte_mbuf -Wl,-lrte_ethdev \
    -Wl,-lrte_net -Wl,-lrte_timer -Wl,-lrte_mempool -Wl,-lrte_mempool_ring -Wl,-lrte_ring -Wl,-lrte_pci \
    -Wl,-Bstatic -lrte_eal -Wl,-Bdynamic -Wl,-lrte_cmdline -Wl,-lrte_kni -Wl,-lrte_bus_pci \
    -Wl,-lrte_bus_vdev ${DPDK_LINK_FLAGS} \
    -Wl,--no-whole-archive -Wl,-lm -Wl,-lrt -Wl,-lnuma -Wl,-ldl -Wl,-export-dynamic -Wl,-export-dynamic \
    -Wl,--as-needed -Wl,-export-dynamic -Wl,-Map=ltran.map -Wl,--cref")

add_executable(gazellectl ltran_dfx.c ${COMMON_DIR}/gazelle_dfx_msg.c)
target_include_directories(gazellectl PRIVATE $ENV{DPDK_INCLUDE_FILE} ${COMMON_DIR} ${DPDK_DIR})
target_link_libraries(gazellectl PRIVATE boundscheck -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
