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

#ifndef __GAZELLE_BASE_FUNC_H__
#define __GAZELLE_BASE_FUNC_H__

#include <math.h>

#define US_PER_MS 1000

#define GAZELLE_FREE(p)  do { \
    if (p) { \
        free(p); \
        p = NULL; \
    } \
} while (0)

#define GAZELLE_RETURN(err) do { \
    errno = err; \
    return -1; \
} while (0)

#define NODE_ENTRY(node, type, member) \
    ((type*)((char*)(node) - (size_t)&((type*)0)->member))

#define MB_IN_BYTES    (1024 * 1024)
static inline int bytes_to_mb(uint32_t bytes)
{
    return ceil((double)bytes / MB_IN_BYTES);
}

int32_t separate_str_to_array(char *args, uint32_t *array, int32_t array_size, int32_t max_value);

int32_t check_and_set_run_dir(void);

int32_t filename_check(const char* args);

void gazelle_exit(void);

/* Do not check if the type of ptr and type->member are the same */
#define container_of_uncheck_ptr(ptr, type, member) \
    ((type *)(void*)(((char *)(ptr)) - offsetof(type, member)))

#endif /* ifndef __GAZELLE_BASE_FUNC_H__ */
