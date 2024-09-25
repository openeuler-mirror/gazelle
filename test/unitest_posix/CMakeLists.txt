# Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
# gazelle is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.10)
project(RtwSocketTest VERSION 1.0)
set(CMAKE_C_STANDARD 99)

# Add an option to enable code coverage
option(CODE_COVERAGE "Enable coverage reporting" OFF)

if(CODE_COVERAGE)
    message(STATUS "Building with coverage flags")
    set(COVERAGE_COMPILE_FLAGS "-fprofile-arcs -ftest-coverage")
    set(COVERAGE_LINK_FLAGS "-lgcov")

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COVERAGE_COMPILE_FLAGS}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COVERAGE_COMPILE_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${COVERAGE_LINK_FLAGS}")
endif()

add_definitions(-D_GNU_SOURCE=1)

add_compile_options(-mssse3)
include_directories(
    ${CMAKE_SOURCE_DIR}/../../src/lstack/include
    ${CMAKE_SOURCE_DIR}/../../src/lstack/include/posix
    ${CMAKE_SOURCE_DIR}/../../src /usr/include/lwip /usr/include include/)

file(GLOB LIBRTE_LIB /usr/lib64/librte_*.so)
file(
    GLOB_RECURSE
    LIBRARY_SHARED_OBJ
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/lstack/core/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/lstack/netif/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/lstack/api/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/common/*.c")

add_library(stack SHARED ${LIBRARY_SHARED_OBJ})

target_link_libraries(
    stack
    PUBLIC cunit
    boundscheck
    config
    numa
    rt
    pthread
    m
    dl
    lwip
    ${LIBRTE_LIB})
target_compile_options(stack PRIVATE -Wno-deprecated-declarations)

# Iterate over the list and add each subdirectory
file(GLOB POSIX_API ${CMAKE_SOURCE_DIR}/posix_api/*)
foreach(subdir ${POSIX_API})
    add_subdirectory(${subdir})
endforeach()

add_executable(main main.c)
target_link_libraries(
    main
    PRIVATE stack
    rtw_rtc_socket_test_lib
    rtw_bind_test_lib
    rtw_getsockname_test_lib
    rtw_listen_test_lib
    rtw_set_getsockopt_test_lib
    rtw_getpeername_test_lib
    rtw_connect_test_lib
    rtw_accept_test_lib
    rtw_read_recv_test_lib
    rtw_write_send_test_lib
    rtw_select_test_lib
    rtw_poll_test_lib
    rtw_epoll_test_lib
    rtc_epoll_test_lib)
