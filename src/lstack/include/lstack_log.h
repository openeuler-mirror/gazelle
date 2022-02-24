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

#ifndef __LSTACK_LOG_H__
#define __LSTACK_LOG_H__

#include <stdio.h>
#include <syslog.h>

#include <rte_log.h>

#include "lwipopts.h"

#define RTE_LOGTYPE_LSTACK   RTE_LOGTYPE_USER1
#define LSTACK_EXIT(a, fmt, ...)        rte_exit(a, "%s:%d "fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LSTACK_LOG(a, b, fmt, ...)      (void)RTE_LOG(a, b, "%s:%d "fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define LSTACK_INFO  LOG_INFO
#define LSTACK_ERR   LOG_ERR

/* before rte_eal_init */
#define LSTACK_PRE_LOG(level, fmt, ...) \
do { \
    syslog(level, ""fmt"", ##__VA_ARGS__);  \
} while (0)

static inline void lstack_prelog_init(const char *name)
{
    openlog(name, LOG_CONS | LOG_PID, LOG_USER);
}
static inline void lstack_prelog_uninit(void)
{
    closelog();
}

#endif /* __LSTACK_LOG_H__ */
