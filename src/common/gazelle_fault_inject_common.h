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

#ifndef __GAZELLE_INJECT_COMMON_H__
#define __GAZELLE_INJECT_COMMON_H__

#include <stdint.h>

enum GAZELLE_FAULT_INJECT_TYPE {
    GAZELLE_FAULT_INJECT_TYPE_ERR = 0,
    GAZELLE_FAULT_INJECT_PACKET_DELAY,
    GAZELLE_FAULT_INJECT_PACKET_LOSS,
    GAZELLE_FAULT_INJECT_PACKAET_DUPLICATE,
    GAZELLE_FAULT_INJECT_PACKET_REORDER,
    GAZELLE_FAULT_INJECT_TYPE_MAX,
};

enum GAZELLE_FAULT_INJECT_RULE {
    INJECT_RULE_ERR = 0,
    /* packet delay rule */
    INJECT_DELAY_RANDOM,
    /* packet loss rule */
    INJECT_LOSS_RANDOM,
    /* packet duplicate */
    INJECT_DUPLICATE_RANDOM,
    /* packet reorder */
    INJECT_REORDER_RANDOM,
};

/* fault inject delay: packet delay's time and range, time unit is "ms" */
struct delay_data {
    uint32_t delay_time;
    uint32_t delay_range;
};

/* fault inject loss: packet loss rate */
struct loss_data {
    double loss_rate;
    uint32_t loss_sigle_count;
};

/* fault inject duplicate: packet duplicate rate and duplicate count */
struct duplicate_data {
    double duplicate_rate;
    uint32_t duplicate_sigle_count;
};

/* fault inject reorder: packet reorder rate and reorder count */
struct reorder_data {
    double reorder_rate;
    uint32_t reorder_sigle_count;
};

struct gazelle_fault_inject_data {
    int32_t fault_inject_on;
    enum GAZELLE_FAULT_INJECT_TYPE inject_type;
    enum GAZELLE_FAULT_INJECT_RULE inject_rule;
    union {
        struct delay_data delay;
        struct loss_data loss;
        struct duplicate_data duplicate;
        struct reorder_data reorder;
    } inject_data;
};

#endif /* __GAZELLE_INJECT_COMMON_H__ */
