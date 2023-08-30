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

set(LIB_PATH ../../../src/ltran /usr/include/dpdk ../../../src/common ../../../src/lstack/include)
set(SRC_PATH_LTRAN ../../../src/ltran)
set(EXECUTABLE_OUTPUT_PATH ../)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -g -fprofile-arcs -ftest-coverage -lgcov")

add_executable(ltran_test
    ltran_instance_test.c
    ltran_param_test.c
    ltran_stack_test.c
    libnet_tcp_test.c
    main.c
    ../stub.c
    ${SRC_PATH_LTRAN}/ltran_param.c
    ${SRC_PATH_LTRAN}/ltran_errno.c
    ${SRC_PATH_LTRAN}/ltran_instance.c
    ${SRC_PATH_LTRAN}/ltran_stack.c
    ${SRC_PATH_LTRAN}/ltran_tcp_sock.c
    ${SRC_PATH_LTRAN}/ltran_tcp_conn.c
    ${SRC_PATH_LTRAN}/../common/gazelle_dfx_msg.c
    ${SRC_PATH_LTRAN}/../common/gazelle_parse_config.c
)

set_target_properties(ltran_test PROPERTIES LINK_FLAGS "-L$ENV{DPDK_LIB_PATH} -Wl,--whole-archive -Wl,-lrte_pipeline -Wl,--wrap=rte_free -Wl,--wrap=rte_malloc \
    -Wl,--no-whole-archive -Wl,--whole-archive -Wl,-lrte_table -Wl,--no-whole-archive -Wl,--whole-archive -Wl,-lrte_port -Wl,--no-whole-archive \
    -Wl,-lrte_distributor -Wl,-lrte_ip_frag -Wl,-lrte_meter -Wl,-lrte_lpm -Wl,--whole-archive -Wl,-lrte_acl -Wl,--no-whole-archive \
    -Wl,-lrte_jobstats -Wl,-lrte_bitratestats -Wl,-lrte_metrics -Wl,-lrte_latencystats -Wl,-lrte_power -Wl,-lrte_efd -Wl,-lrte_bpf \
    -Wl,--whole-archive -Wl,-lrte_gro -Wl,-lrte_cfgfile -Wl,-lrte_gso -Wl,-lrte_hash -Wl,-lrte_member -Wl,-lrte_vhost -Wl,-lrte_kvargs \
    -Wl,-lrte_mbuf -Wl,-lrte_ethdev -Wl,-lrte_net -Wl,-lrte_bbdev -Wl,-lrte_cryptodev -Wl,-lrte_security -Wl,-lrte_compressdev -Wl,-lrte_eventdev \
    -Wl,-lrte_rawdev -Wl,-lrte_timer -Wl,-lrte_mempool -Wl,-lrte_mempool_ring -Wl,-lrte_ring -Wl,-lrte_pci \
    -Wl,-Bstatic -lrte_eal -Wl,-Bdynamic -Wl,-lrte_cmdline \
    -Wl,-lrte_sched -Wl,-lrte_reorder -Wl,-lrte_kni -Wl,-lrte_common_cpt -Wl,-lrte_common_octeontx -Wl,-lrte_common_dpaax -Wl,-lrte_bus_pci \
    -Wl,-lrte_bus_dpaa -Wl,-lrte_bus_vdev -Wl,-lrte_bus_fslmc -Wl,-lrte_mempool_bucket -Wl,-lrte_mempool_stack -Wl,-lrte_mempool_dpaa \
    -Wl,-lrte_mempool_dpaa2 -Wl,-lrte_net_af_packet -Wl,-lrte_net_ark -Wl,-lrte_net_atlantic -Wl,-lrte_net_axgbe \
    -Wl,-lrte_net_bnxt -Wl,-lrte_net_bond -Wl,-lrte_net_cxgbe -Wl,-lrte_net_dpaa -Wl,-lrte_net_dpaa2 -Wl,-lrte_net_e1000 -Wl,-lrte_net_ena \
    -Wl,-lrte_net_enetc -Wl,-lrte_net_enic -Wl,-lrte_net_failsafe -Wl,-lrte_net_hinic -Wl,-lrte_net_ixgbe -Wl,-lrte_net_kni \
    -Wl,-lrte_net_nfp -Wl,-lrte_net_null -Wl,-lpcap -Wl,-lrte_net_qede -Wl,-lrte_net_ring -Wl,-lrte_net_softnic \
    -Wl,-lrte_net_tap -Wl,-lrte_net_vdev_netvsc -Wl,-lrte_net_virtio -Wl,-lrte_net_vhost \
    -Wl,-lrte_bus_vmbus -Wl,-lrte_net_netvsc -Wl,-lrte_mempool_octeontx -Wl,-lrte_net_octeontx \
    -Wl,-lrte_bus_ifpga -Wl,-lrte_stack -Wl,-lrte_telemetry\
    -Wl,--no-whole-archive -Wl,-lm -Wl,-lrt -Wl,-lnuma -Wl,-ldl -Wl,-export-dynamic -Wl,-export-dynamic \
    -Wl,--as-needed -Wl,-export-dynamic -Wl,-Map=ltran.map -Wl,--cref")
if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "loongarch64")
    set_target_properties(ltran_test PROPERTIES LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-lrte_net_i40e")
endif()
target_include_directories(ltran_test PRIVATE ${LIB_PATH})
target_link_libraries(ltran_test PRIVATE config boundscheck cunit pthread)
