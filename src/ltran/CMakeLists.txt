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

set(CMAKE_C_FLAGS "-O2 -g -fstack-protector-strong -Wall -Werror -fPIE -pie -pthread")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D LTRAN_COMPILE")

if($ENV{GAZELLE_COVERAGE_ENABLE})
	message("Enable Coverage compile option")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ftest-coverage -fprofile-arcs")
endif($ENV{GAZELLE_COVERAGE_ENABLE})

add_executable(ltran main.c ltran_param.c ltran_config.c ltran_ethdev.c ltran_stat.c ltran_errno.c
				ltran_monitor.c ltran_instance.c ltran_stack.c ltran_tcp_conn.c ltran_tcp_sock.c
				ltran_forward.c ltran_timer.c ${COMMON_DIR}/gazelle_dfx_msg.c ${COMMON_DIR}/dpdk_common.c)

target_include_directories(ltran PRIVATE ${COMMON_DIR} ${PROJECT_SOURCE_DIR})
target_compile_options(ltran PRIVATE -march=native -fno-strict-aliasing -D__ARM_FEATURE_CRC32=1 -DRTE_MACHINE_CPUFLAG_NEON
               -DRTE_MACHINE_CPUFLAG_CRC32 -DRTE_MACHINE_CPUFLAG_PMULL -DRTE_MACHINE_CPUFLAG_AES
               -DRTE_MACHINE_CPUFLAG_SHA1 -DRTE_MACHINE_CPUFLAG_SHA2 -include rte_config.h
               -D_GNU_SOURCE -W -Wall -Wstrict-prototypes -Wmissing-declarations -Wmissing-prototypes -Wold-style-definition
               -Wpointer-arith -Wcast-align -Wcast-qual -Wnested-externs -Wformat-nonliteral -Wformat-security -Wundef
               -Wdeprecated -Wwrite-strings -Wno-implicit-fallthrough -D_FORTIFY_SOURCE=2)

target_link_libraries(ltran PRIVATE config boundscheck rte_pdump -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wtrampolines)
set_target_properties(ltran PROPERTIES LINK_FLAGS "-L$ENV{DPDK_LIB_PATH} -Wl,--whole-archive -Wl,-lrte_pipeline \
    -Wl,--no-whole-archive -Wl,-lrte_table -Wl,--whole-archive -Wl,--no-whole-archive -Wl,--whole-archive -Wl,-lrte_port -Wl,--no-whole-archive \
    -Wl,-lrte_distributor -Wl,-lrte_meter -Wl,-lrte_ip_frag -Wl,-lrte_lpm -Wl,--whole-archive -Wl,-lrte_acl -Wl,--no-whole-archive \
    -Wl,-lrte_jobstats -Wl,-lrte_bitratestats -Wl,-lrte_metrics -Wl,-lrte_latencystats -Wl,-lrte_power -Wl,-lrte_efd -Wl,-lrte_bpf \
    -Wl,--whole-archive -Wl,-lrte_gro -Wl,-lrte_cfgfile -Wl,-lrte_gso -Wl,-lrte_hash -Wl,-lrte_member -Wl,-lrte_vhost -Wl,-lrte_kvargs \
    -Wl,-lrte_mbuf -Wl,-lrte_ethdev -Wl,-lrte_net -Wl,-lrte_bbdev -Wl,-lrte_cryptodev -Wl,-lrte_security -Wl,-lrte_compressdev -Wl,-lrte_eventdev \
    -Wl,-lrte_rawdev -Wl,-lrte_timer -Wl,-lrte_mempool -Wl,-lrte_mempool_ring -Wl,-lrte_ring -Wl,-lrte_pci \
    -Wl,-Bstatic -lrte_eal -Wl,-Bdynamic -Wl,-lrte_cmdline \
    -Wl,-lrte_sched -Wl,-lrte_reorder -Wl,-lrte_kni -Wl,-lrte_common_cpt -Wl,-lrte_common_octeontx -Wl,-lrte_common_dpaax -Wl,-lrte_bus_pci \
    -Wl,-lrte_bus_dpaa -Wl,-lrte_bus_vdev -Wl,-lrte_bus_fslmc -Wl,-lrte_mempool_bucket -Wl,-lrte_mempool_stack -Wl,-lrte_mempool_dpaa \
    -Wl,-lrte_mempool_dpaa2 -Wl,-lrte_net_af_packet -Wl,-lrte_net_ark -Wl,-lrte_net_atlantic -Wl,-lrte_net_axgbe \
    -Wl,-lrte_net_bnxt -Wl,-lrte_net_bond -Wl,-lrte_net_cxgbe -Wl,-lrte_net_dpaa -Wl,-lrte_net_dpaa2 -Wl,-lrte_net_e1000 -Wl,-lrte_net_ena \
    -Wl,-lrte_net_enetc -Wl,-lrte_net_enic -Wl,-lrte_net_failsafe -Wl,-lrte_net_i40e -Wl,-lrte_net_hinic -Wl,-lrte_net_ixgbe -Wl,-lrte_net_kni \
    -Wl,-lrte_net_nfp -Wl,-lrte_net_null -Wl,-lpcap -Wl,-lrte_net_qede -Wl,-lrte_net_ring -Wl,-lrte_net_softnic \
    -Wl,-lrte_net_tap -Wl,-lrte_net_vdev_netvsc -Wl,-lrte_net_virtio -Wl,-lrte_net_vhost \
    -Wl,-lrte_bus_vmbus -Wl,-lrte_net_netvsc -Wl,-lrte_mempool_octeontx -Wl,-lrte_net_octeontx \
    -Wl,-lrte_bus_ifpga -Wl,-lrte_stack -Wl,-lrte_telemetry\
    -Wl,--no-whole-archive -Wl,-lm -Wl,-lrt -Wl,-lnuma -Wl,-ldl -Wl,-export-dynamic -Wl,-export-dynamic \
    -Wl,--as-needed -Wl,-export-dynamic -Wl,-Map=ltran.map -Wl,--cref")

add_executable(gazellectl ltran_dfx.c ${COMMON_DIR}/gazelle_dfx_msg.c)
target_include_directories(gazellectl PRIVATE $ENV{DPDK_INCLUDE_FILE} ${COMMON_DIR})
target_link_libraries(gazellectl PRIVATE boundscheck)
