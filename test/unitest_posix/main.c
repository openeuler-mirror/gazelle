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

#include <sys/stat.h>
#include "include/test_frame.h"
static FILE* log_file = NULL;

void open_log_file()
{
    struct stat st;
    memset(&st, 0, sizeof(st));
    const char* path = "../log";
    if (stat(path, &st) == -1) {
        if (mkdir(path, DIRECTORY_PERMISSIONS) != 0) {
            perror("mkdir log");
            return;
        }
    }
    if (log_file != NULL) {
        fclose(log_file);
    }
    log_file = fopen(LOG_FILE, "w");
}

void close_log_file()
{
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}

void log_message(const char* format, ...)
{
    if (log_file != NULL) {
        va_list args;
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
    }
}

void add_test(CU_pSuite pSuite, const char* test_name, CU_TestFunc test_func)
{
    if (NULL == CU_add_test(pSuite, test_name, test_func)) {
        CU_cleanup_registry();
        exit(CU_get_error());
    }
}

int main()
{
    CU_pSuite posix_Suite = NULL;

    /* Initialize CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    /* Add test suite */
    posix_Suite = CU_add_suite("Testing for POSIX_API", 0, 0);
    if (NULL == posix_Suite) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    open_log_file();
    // clang-format off
    {
    add_test(posix_Suite, "Testing rtw_single_bind success ", test_single_bind_success);
    add_test(posix_Suite, "Testing rtw_broadcast bind success ", test_broadcast_bind_success);
    add_test(posix_Suite, "Testing rtw_single_bind failure ", test_bind_failure);
    add_test(posix_Suite, "Testing rtw_getsockname success ", test_getsockname_success);
    add_test(posix_Suite, "Testing rtw_getsockname failure ", test_getsockname_failure);
    add_test(posix_Suite, "Testing rtw_single_isten_success ", test_single_listen_success);
    add_test(posix_Suite, "Testing rtw_broadcast_listen_success ", test_broadcast_listen_success);
    add_test(posix_Suite, "Testing rtw_listen_failure ", test_listen_failure);
    add_test(posix_Suite, "Testing rtw_set_getsockopt_success ", test_set_getsockopt_success);
    add_test(posix_Suite, "Testing rtw_set_getsockopt_failure ", test_set_getsockopt_failure);
    add_test(posix_Suite, "Testing rtw_getpeername_success ", test_getpeername_success);
    add_test(posix_Suite, "Testing rtw_getpeername_failure ", test_getpeername_failure);
    add_test(posix_Suite, "Testing rtw_connect_success ", test_connect_success);
    add_test(posix_Suite, "Testing rtw_connect_failure ", test_connect_failure);
    add_test(posix_Suite, "Testing test_accept_success ", test_accept_success);
    add_test(posix_Suite, "Testing test_accept_failure ", test_accept_failure);
    add_test(posix_Suite, "Testing rtw_read_success ", test_read_success);
    add_test(posix_Suite, "Testing rtw_rec_success ", test_rec_success);
    add_test(posix_Suite, "Testing rtw_read_recv_failure ", test_read_recv_failure);
    add_test(posix_Suite, "Testing rtw_write_success ", test_write_success);
    add_test(posix_Suite, "Testing rtw_send_success ", test_send_success);
    add_test(posix_Suite, "Testing rtw_write_send_failure ", test_write_send_failure);
    add_test(posix_Suite, "Testing rtw_select success ", test_select_success);
    add_test(posix_Suite, "Testing rtw_select_failure ", test_select_failure);
    add_test(posix_Suite, "Testing rtw_poll_success ", test_poll_success);
    add_test(posix_Suite, "Testing rtw_poll_failure ", test_poll_failure);
    add_test(posix_Suite, "Testing rtw_epoll_success ", test_epoll_success);
    add_test(posix_Suite, "Testing rtw_epoll_failure ", test_epoll_failure);
    add_test(posix_Suite, "Testing rtw_rtc_socket success ", test_socket_success);
    add_test(posix_Suite, "Testing rtw_rtc_socket failure ", test_socket_failure);
    add_test(posix_Suite, "Testing rtw_rtc_close_success_failure ", test_close_success_failure);
    add_test(posix_Suite, "Testing rtw_rtc_shutdown_success_failure ", test_shutdown_success_failure);
    add_test(posix_Suite, "Testing rtc_asynchronous ", test_asynchronous_rtc);
    }
    // clang-format on

    // run all tests
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();

    close_log_file();
    return CU_get_error();
}
