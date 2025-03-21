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

#include <lwip/lwipgz_sock.h>
#include <lwip/sockets.h>

#include "lstack_log.h"
#include "lstack_rtc_api.h"


void rtc_api_init(posix_api_t *api)
{
    api->close_fn         = lwip_close;
    api->shutdown_fn      = lwip_shutdown;
    api->socket_fn        = lwip_socket;
    api->accept_fn        = lwip_accept;
    api->accept4_fn       = lwip_accept4;
    api->bind_fn          = lwip_bind;
    api->listen_fn        = lwip_listen;
    api->connect_fn       = lwip_connect;

    api->setsockopt_fn    = lwip_setsockopt;
    api->getsockopt_fn    = lwip_getsockopt;
    api->getpeername_fn   = lwip_getpeername;
    api->getsockname_fn   = lwip_getsockname;

    api->read_fn          = lwip_read;
    api->readv_fn         = lwip_readv;
    api->write_fn         = lwip_write;
    api->writev_fn        = lwip_writev;
    api->recv_fn          = lwip_recv;
    api->send_fn          = lwip_send;
    api->recvmsg_fn       = lwip_recvmsg;
    api->sendmsg_fn       = lwip_sendmsg;
    api->recvfrom_fn      = lwip_recvfrom;
    api->sendto_fn        = lwip_sendto;
}
