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

#include <securec.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "gazelle_opt.h"
#include "gazelle_base_func.h"

#ifdef LTRAN_COMPILE
#include "ltran_log.h"
#define  COMMON_ERR(fmt, ...)    LTRAN_ERR(fmt, ##__VA_ARGS__)
#define  COMMON_INFO(fmt, ...)   LTRAN_INFO(fmt, ##__VA_ARGS__)
#else
#include "lstack_log.h"
#define  COMMON_ERR(fmt, ...)    LSTACK_LOG(ERR, LSTACK, fmt, ##__VA_ARGS__)
#define  COMMON_INFO(fmt, ...)   LSTACK_LOG(INFO, LSTACK, fmt, ##__VA_ARGS__)
#endif

int32_t separate_str_to_array(char *args, uint32_t *array, int32_t array_size, int32_t max_value)
{
    uint32_t count = 0;
    char *end = NULL;
    int32_t min, max;
    int32_t idx;

    for (idx = 0; idx < array_size; idx++) {
        array[idx] = 0;
    }

    while (isblank(*args)) {
        args++;
    }

    min = array_size;
    do {
        while (isblank(*args)) {
            args++;
        }
        if (*args == '\0') {
            return -1;
        }
        errno = 0;
        /* prefix 0x,0X indicate hexdecimal */
        if (strncmp(args, "0x", 2) == 0 || strncmp(args, "0X", 2) == 0) {
            idx = strtol(args, &end, 16); /* 16: hexdecimal */
        } else {
            idx = strtol(args, &end, 10); /* 10: decimal */
        }
        if (errno || end == NULL) {
            return -1;
        }
        if (idx < 0 || idx >= max_value) {
            return -1;
        }
        while (isblank(*end)) {
            end++;
        }
        if (*end == '-') {
            min = idx;
        } else if ((*end == ',') || (*end == '\0') || (*end == '\n')) {
            max = idx;
            if (min == array_size) {
                min = idx;
            }
            for (idx = min; idx <= max; idx++) {
                array[count] = idx;
                count++;
            }
            min = array_size;
        } else {
            return -1;
        }
        args = end + 1;
    } while (*end != '\0' && *end != '\n');

    if (count == 0) {
        return -1;
    }

    return count;
}

int32_t check_and_set_run_dir(void)
{
    int32_t ret;

    if (access(GAZELLE_RUN_DIR, 0) != 0) {
        ret = mkdir(GAZELLE_RUN_DIR, GAZELLE_FILE_PERMISSION);
        if (ret != 0) {
            return -1;
        }
    }
    return 0;
}

/* return 1 for check error */
int32_t filename_check(const char* args)
{
    if (args == NULL) {
        return 1;
    }

    if (strlen(args) <= 0 || strlen(args) > GAZELLE_SOCK_FILENAME_MAXLEN - 1) {
        COMMON_ERR("socket_filename_check: invalid unix sock name %s, filename exceeds the limit %d.\n", args, GAZELLE_SOCK_FILENAME_MAXLEN);
        return 1;
    }

    char* sensitive_chars = strpbrk(args, "|;&$><`\\!\n");
    if (sensitive_chars != NULL) {
        COMMON_ERR("socket_filename_check: invalid unix sock name %s, filename contains sensitive characters.\n", args);
        return 1;
    }

    return 0;
}
