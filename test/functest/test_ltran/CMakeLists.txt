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
project(gazelle_func_test)

INCLUDE_DIRECTORIES(../common)
set(LIB_PATH ${PROJECT_SOURCE_DIR}/../common)
set(EXECUTABLE_OTPUT_PATH ../)

add_executable(ltran_func_test ltran_func_test.c ${LIB_PATH}/common.c ${LIB_PATH}/utils.c)
target_include_directories(ltran_func_test PRIVATE ${LIB_PATH})
target_link_libraries(ltran_func_test PRIVATE cunit securec)
