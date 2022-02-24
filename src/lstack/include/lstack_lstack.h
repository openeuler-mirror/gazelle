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

#ifndef _LSTACK_H
#define _LSTACK_H

#if defined __GNUC__
#define LSTACK_EXPORT_SYMBOL __attribute__((visibility("default")))

#elif defined(_MSC_VER)
#define LSTACK_EXPORT_SYMBOL extern __declspec(dllexport)

#elif defined(__SUNPRO_C) && (__SUNPRO_C >= 0x550)
#define LSTACK_EXPORT_SYMBOL __global

#else
#define LSTACK_EXPORT_SYMBOL /* unknown compiler */
#endif

/* Return string describing version of currently running lstack.  */
LSTACK_EXPORT_SYMBOL const char *get_lstack_version(void);

#endif /* lstack.h */
