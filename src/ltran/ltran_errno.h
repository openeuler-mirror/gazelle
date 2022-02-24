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

#ifndef __GAZELLE_ERRNO_H__
#define __GAZELLE_ERRNO_H__

#include <sys/types.h>
#include <stdint.h>

#define GAZELLE_SUCCESS      9000
#define GAZELLE_ENOMEM       9001
#define GAZELLE_EPARAM       9002
#define GAZELLE_ERANGE       9003
#define GAZELLE_EINETATON    9004
#define GAZELLE_EMAC         9005
#define GAZELLE_EMEMCP       9006
#define GAZELLE_ECONSIST     9007
#define GAZELLE_ESTRTOUL     9008
#define GAZELLE_ESTRCP       9009
#define GAZELLE_EPATH        9010

#define GAZELLE_EEALINIT     9011
#define GAZELLE_ENETADDR     9012
#define GAZELLE_EHOSTADDR    9013

void gazelle_set_errno(const int32_t value);
int32_t gazelle_get_errno(void);


#endif /* ifndef __GAZELLE_ERRNO_H__ */
