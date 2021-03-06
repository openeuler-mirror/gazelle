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

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "gazelle_dfx_msg.h"

int read_specied_len(int fd, char *buf, size_t target_size)
{
    ssize_t tmp_size;
    char *tmp_pbuf = buf;
    while (target_size > 0) {
        tmp_size = read(fd, tmp_pbuf, target_size);
        if ((tmp_size == -1) && (errno != EINTR)) {
            printf("read msg from fd %d failed, errno %d\n", fd, errno);
            return -1;
        } else if (tmp_size == 0) {
            printf("read zero bytes from fd %d, maybe peer is down\n", fd);
            return -1;
        }

        tmp_size = (tmp_size < 0) ? 0 : tmp_size;
        target_size -= (size_t)tmp_size;
        tmp_pbuf += tmp_size;
    }

    return 0;
}

int write_specied_len(int fd, const char *buf, size_t target_size)
{
    ssize_t tmp_size;
    const char *tmp_pbuf = buf;
    while (target_size > 0) {
        tmp_size = write(fd, tmp_pbuf, target_size);
        if ((tmp_size == -1) && (errno != EINTR) && (errno != EAGAIN)) {
            printf("write msg from fd %d failed, errno %d\n", fd, errno);
            return -1;
        } else if (tmp_size == 0) {
            printf("write zero bytes from fd %d, maybe peer is down\n", fd);
            return -1;
        }

        tmp_size = (tmp_size < 0) ? 0 : tmp_size;
        target_size -= (size_t)tmp_size;
        tmp_pbuf += tmp_size;
    }

    return 0;
}
