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

#ifndef _LSTACK_RTC_API_H_
#define _LSTACK_RTC_API_H_

#include <lwip/lwipgz_posix_api.h>

/* don't include lwip/sockets.h, conflict with sys/socket.h */
extern int lwip_fcntl(int s, int cmd, int val);
extern int lwip_ioctl(int s, long cmd, void *argp);

void dummy_api_init(posix_api_t *api);
void rtc_api_init(posix_api_t *api);

#endif /* __LSTACK_RTC_API_H_  */
