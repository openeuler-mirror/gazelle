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
set(LWIP_INCLUDE_DIR /usr/include/lwip)

execute_process(
    COMMAND rpm -qa dpdk
    OUTPUT_VARIABLE DPDK_VERSION_FULL
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX MATCH "[0-9]+\\.[0-9]+" DPDK_VERSION ${DPDK_VERSION_FULL})

if (DPDK_VERSION STREQUAL "21.11")
    set(DPDK_INCLUDE_DIR /usr/local/include/)
else()
    set(DPDK_INCLUDE_DIR /usr/include/dpdk)
endif()


set(CMAKE_C_FLAGS "-O2 -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLTRAN_COMPILE -D_GNU_SOURCE -fno-strict-aliasing")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -fstack-protector-strong -fPIE")
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pie -D_FORTIFY_SOURCE=2 -fPIC")
endif()

# gcc coredump in openEuler-20.03-LTS-XX aarch64 when add -march=native 
if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "sw_64|aarch64|ppc64le|riscv64" )
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native -Wcast-align")
endif()

if($ENV{GAZELLE_COVERAGE_ENABLE})
    message("Enable Coverage compile option")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ftest-coverage -fprofile-arcs")
endif($ENV{GAZELLE_COVERAGE_ENABLE})

if($ENV{GAZELLE_FAULT_INJECT_ENABLE})
    message("Enable Fault inject option")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DGAZELLE_FAULT_INJECT_ENABLE")
endif($ENV{GAZELLE_FAULT_INJECT_ENABLE})

set(LTRAN_C_FLAGS -D__ARM_FEATURE_CRC32=1 
    -Wstrict-prototypes -Wmissing-declarations -Wmissing-prototypes -Wold-style-definition 
    -Wpointer-arith -Wcast-qual -Wnested-externs -Wformat-nonliteral -Wformat-security -Wundef 
    -Wdeprecated -Wwrite-strings -Wno-implicit-fallthrough -Wno-error=deprecated-declarations)

set(DPDK_C_FLAGS -DRTE_MACHINE_CPUFLAG_NEON -DRTE_MACHINE_CPUFLAG_CRC32 
    -DRTE_MACHINE_CPUFLAG_PMULL -DRTE_MACHINE_CPUFLAG_AES 
    -DRTE_MACHINE_CPUFLAG_SHA1 -DRTE_MACHINE_CPUFLAG_SHA2 
    -include rte_config.h)

set(DPDK_LINK_FLAGS -Wl,-lrte_meter -Wl,-lrte_gro -Wl,-lrte_hash -Wl,-lrte_kvargs 
    -Wl,-lrte_mbuf -Wl,-lrte_ethdev -Wl,-lrte_net -Wl,-lrte_timer -Wl,-lrte_mempool 
    -Wl,-lrte_mempool_ring -Wl,-lrte_ring -Wl,-lrte_pci -Wl,-lrte_cmdline 
    -Wl,-lrte_bus_pci -Wl,-lrte_bus_vdev -Wl,-lrte_pdump)

if (DPDK_VERSION STREQUAL "19.11")
    set(DPDK_LINK_FLAGS ${DPDK_LINK_FLAGS} -Wl,-lrte_pmd_bond -Wl,-lrte_pmd_hinic -Wl,-lrte_pmd_ixgbe 
        -Wl,-lrte_pmd_pcap -Wl,-lrte_pmd_virtio)
    if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "loongarch64")
        set(DPDK_LINK_FLAGS ${DPDK_LINK_FLAGS} -Wl,-lrte_pmd_i40e)
    endif()
else()
    set(DPDK_LINK_FLAGS ${DPDK_LINK_FLAGS} -Wl,-lrte_net_bond -Wl,-lrte_net_hinic -Wl,-lrte_net_ixgbe 
        -Wl,-lpcap -Wl,-lrte_net_pcap -Wl,-lrte_net_virtio -Wl,-lrte_pcapng -Wl,-lrte_telemetry)
    if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "loongarch64|riscv64")
        set(DPDK_LINK_FLAGS ${DPDK_LINK_FLAGS} -Wl,-lrte_net_i40e)
    endif()
endif()

if (DPDK_VERSION  GREATER_EQUAL 23.11)
    set(DPDK_LINK_FLAGS ${DPDK_LINK_FLAGS} -lrte_log -Wl,-lrte_eal)
else()
    set(DPDK_LINK_FLAGS ${DPDK_LINK_FLAGS} -lrte_kni -Wl,-Bstatic -Wl,-lrte_eal -Wl,-Bdynamic)
endif()
if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "ppc64le")
    set(DPDK_LINK_FLAGS ${DPDK_LINK_FLAGS} -Wl,-larchive)
endif()

# compile info
# set(CMAKE_VERBOSE_MAKEFILE ON)
message("[CMAKE_C_FLAGS] ${CMAKE_C_FLAGS}")
message("[LTRAN_C_FLAGS] ${LTRAN_C_FLAGS}")
message("[DPDK_C_FLAGS ] ${DPDK_C_FLAGS}")
message("[DPDK_LINK_FLAGS] ${DPDK_LINK_FLAGS}")

add_executable(ltran main.c ltran_param.c ltran_config.c ltran_ethdev.c ltran_stat.c ltran_errno.c
    ltran_monitor.c ltran_instance.c ltran_stack.c ltran_tcp_conn.c ltran_tcp_sock.c
    ltran_forward.c ltran_timer.c 
    ${COMMON_DIR}/gazelle_dfx_msg.c 
    ${COMMON_DIR}/dpdk_common.c 
    ${COMMON_DIR}/gazelle_parse_config.c)

target_include_directories(ltran PRIVATE ${COMMON_DIR}/../ ${PROJECT_SOURCE_DIR} ${LWIP_INCLUDE_DIR} ${DPDK_INCLUDE_DIR})

# COMPILE_FLAGS and LINK_FLAGS are deprecated.
target_compile_options(ltran PRIVATE ${LTRAN_C_FLAGS} ${DPDK_C_FLAGS})
target_link_options(ltran PRIVATE 
    -Wl,--whole-archive ${DPDK_LINK_FLAGS} -Wl,--no-whole-archive 
    -Wl,--as-needed -Wl,-export-dynamic 
    -Wl,-Map=ltran.map -Wl,--cref)
target_link_libraries(ltran PRIVATE pthread config boundscheck 
    -Wl,-lm -Wl,-lrt -Wl,-lnuma -Wl,-ldl 
    -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wtrampolines)


add_executable(gazellectl ltran_dfx.c ${COMMON_DIR}/gazelle_dfx_msg.c)
target_include_directories(gazellectl PRIVATE ${COMMON_DIR}/../ ${DPDK_INCLUDE_DIR})
target_link_libraries(gazellectl PRIVATE boundscheck -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
