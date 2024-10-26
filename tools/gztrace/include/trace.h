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

/*
 * trace.h
 *
 * Features included:
 * - Prints the POSIX interfaces supported by Gazelle.
*/

#ifndef GZTRACE_TRACE_H
#define GZTRACE_TRACE_H

#include <time.h>
#include <stdio.h>
#include <string.h>
#define API_LIST_MD_PATH "../../../doc/support_en.md"
#define MAX_LINE_LENGTH 1024

/* Lists the supported APIs by reading from a markdown file under a specific title */
void list_api();

#endif /* GZTRACE_TRACE_H */
