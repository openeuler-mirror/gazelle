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

#ifndef __GAZELLE_LOG_H__
#define __GAZELLE_LOG_H__

#include <rte_log.h>

#define RTE_LOGTYPE_LTRAN   RTE_LOGTYPE_USER1

#define LTRAN_DEBUG(fmt, ...) \
    do { \
        (void)RTE_LOG(DEBUG, LTRAN, "%s:%d "fmt, __func__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define LTRAN_WARN(fmt, ...) \
    do { \
        (void)RTE_LOG(WARNING, LTRAN, "%s:%d "fmt, __func__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define LTRAN_INFO(fmt, ...) \
    do { \
        (void)RTE_LOG(INFO, LTRAN, "%s:%d "fmt, __func__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define LTRAN_RTE_ERR(fmt, ...) \
    do { \
        (void)RTE_LOG(ERR, LTRAN, "%s:%d "fmt" rte_errno %d: %s\n", __func__, __LINE__, ##__VA_ARGS__, \
            rte_errno, rte_strerror(rte_errno)); \
    } while (0)

#define LTRAN_ERR(fmt, ...) \
    do { \
        (void)RTE_LOG(ERR, LTRAN, "%s:%d "fmt, __func__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#endif /* ifndef __GAZELLE_LOG_H__ */