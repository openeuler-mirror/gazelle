# Copyright (c) 2022-2023. yyangoO.
# gazelle is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.


cmake_minimum_required(VERSION 3.12.1)

set(PROJECT_NAME example)

project(${PROJECT_NAME})

message(STATUS "PROJECT_SOURCE_DIR: " ${PROJECT_SOURCE_DIR})
message(STATUS "PROJECT_BINARY_DIR: " ${PROJECT_BINARY_DIR})

set(CMAKE_C_FLAGS "-O2 -g -fstack-protector-strong -Wall -Werror -pthread -lboundscheck")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D EXAMPLE_COMPILE")

include_directories(${PROJECT_SOURCE_DIR}/inc)

aux_source_directory(${PROJECT_SOURCE_DIR}/src SOURCES)

add_executable(${PROJECT_NAME} main.c ${SOURCES})
