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

#endif /* ifndef __GAZELLE_BASE_FUNC_H__ */
