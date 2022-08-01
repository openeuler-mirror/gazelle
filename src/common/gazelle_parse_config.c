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

static int32_t parse_str_data(char *args, uint32_t *array, int32_t array_size)
{
    const char *delim = "-";
    char *elem = NULL;
    char *next_token = NULL;
    char *endptr = NULL;
    int32_t cnt = 0;
    int64_t start, end;

    elem = strtok_s(args, delim, &next_token);
    start = strtol(elem, &endptr, 0);
    if (endptr == elem) {
        return cnt;
    }

    elem = strtok_s(NULL, delim, &next_token);
    if (elem == NULL) {
        /* just a single data */
        array[cnt++] = (uint32_t)start;
        return cnt;
    }
    end = strtol(elem, &endptr, 0);
    if (endptr == elem) {
        array[cnt++] = start;
        return cnt;
    }

    for (int64_t i = start; i <= end && cnt < array_size; i++) {
        if (i < 0 || i > UINT_MAX) {
            break;
        }
        array[cnt++] = (uint32_t)i;
    }

    return cnt;
}

/* support '-' and ',' */
int32_t separate_str_to_array(char *args, uint32_t *array, int32_t array_size)
{
    const char *delim = ",";
    char *elem = NULL;
    char *next_token = NULL;
    int32_t cnt = 0;

    elem = strtok_s(args, delim, &next_token);
    while (elem != NULL && cnt < array_size) {
        cnt += parse_str_data(elem, &array[cnt], array_size - cnt);
        elem = strtok_s(NULL, delim, &next_token);
    }

    return cnt;
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
