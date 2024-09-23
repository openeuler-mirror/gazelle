/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Huawei Technologies
 *
 */

// #include <netinet/in.h>
// #include <sys/ioctl.h>
// #include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>

#include "lwipgz_posix_api.h"
#include "lwipgz_sock.h"

posix_api_t *posix_api = NULL;
static posix_api_t posix_api_val;

int posix_api_init(void)
{
/* the symbol we use here won't be NULL, so we don't need dlerror() to test error */
#define CHECK_DLSYM_RET_RETURN(ret) do {  \
        if ((ret) == NULL)                   \
            goto err_out;                 \
    } while (0)

    posix_api = &posix_api_val;

    void *__restrict handle = RTLD_NEXT;

    /* glibc standard api */
    CHECK_DLSYM_RET_RETURN(posix_api->shutdown_fn   = dlsym(handle, "shutdown"));
    CHECK_DLSYM_RET_RETURN(posix_api->close_fn      = dlsym(handle, "close"));
    CHECK_DLSYM_RET_RETURN(posix_api->socket_fn     = dlsym(handle, "socket"));
    CHECK_DLSYM_RET_RETURN(posix_api->connect_fn    = dlsym(handle, "connect"));
    CHECK_DLSYM_RET_RETURN(posix_api->bind_fn       = dlsym(handle, "bind"));
    CHECK_DLSYM_RET_RETURN(posix_api->listen_fn     = dlsym(handle, "listen"));
    CHECK_DLSYM_RET_RETURN(posix_api->accept_fn     = dlsym(handle, "accept"));
    CHECK_DLSYM_RET_RETURN(posix_api->accept4_fn    = dlsym(handle, "accept4"));

    CHECK_DLSYM_RET_RETURN(posix_api->getpeername_fn    = dlsym(handle, "getpeername"));
    CHECK_DLSYM_RET_RETURN(posix_api->getsockname_fn    = dlsym(handle, "getsockname"));
    CHECK_DLSYM_RET_RETURN(posix_api->getsockopt_fn     = dlsym(handle, "getsockopt"));
    CHECK_DLSYM_RET_RETURN(posix_api->setsockopt_fn     = dlsym(handle, "setsockopt"));

    CHECK_DLSYM_RET_RETURN(posix_api->read_fn       = dlsym(handle, "read"));
    CHECK_DLSYM_RET_RETURN(posix_api->write_fn      = dlsym(handle, "write"));
    CHECK_DLSYM_RET_RETURN(posix_api->readv_fn      = dlsym(handle, "readv"));
    CHECK_DLSYM_RET_RETURN(posix_api->writev_fn     = dlsym(handle, "writev"));
    CHECK_DLSYM_RET_RETURN(posix_api->recv_fn       = dlsym(handle, "recv"));
    CHECK_DLSYM_RET_RETURN(posix_api->send_fn       = dlsym(handle, "send"));
    CHECK_DLSYM_RET_RETURN(posix_api->recvmsg_fn    = dlsym(handle, "recvmsg"));
    CHECK_DLSYM_RET_RETURN(posix_api->sendmsg_fn    = dlsym(handle, "sendmsg"));
    CHECK_DLSYM_RET_RETURN(posix_api->recvfrom_fn   = dlsym(handle, "recvfrom"));
    CHECK_DLSYM_RET_RETURN(posix_api->sendto_fn     = dlsym(handle, "sendto"));

    CHECK_DLSYM_RET_RETURN(posix_api->select_fn         = dlsym(handle, "select"));
    CHECK_DLSYM_RET_RETURN(posix_api->poll_fn           = dlsym(handle, "poll"));
    CHECK_DLSYM_RET_RETURN(posix_api->epoll_create_fn   = dlsym(handle, "epoll_create"));
    CHECK_DLSYM_RET_RETURN(posix_api->epoll_create1_fn  = dlsym(handle, "epoll_create1"));
    CHECK_DLSYM_RET_RETURN(posix_api->epoll_ctl_fn      = dlsym(handle, "epoll_ctl"));
    CHECK_DLSYM_RET_RETURN(posix_api->epoll_wait_fn     = dlsym(handle, "epoll_wait"));
    CHECK_DLSYM_RET_RETURN(posix_api->eventfd_fn        = dlsym(handle, "eventfd"));

    CHECK_DLSYM_RET_RETURN(posix_api->ioctl_fn          = dlsym(handle, "ioctl"));
    CHECK_DLSYM_RET_RETURN(posix_api->fcntl_fn          = dlsym(handle, "fcntl"));
    CHECK_DLSYM_RET_RETURN(posix_api->fcntl64_fn        = dlsym(handle, "fcntl64"));

    CHECK_DLSYM_RET_RETURN(posix_api->sigaction_fn      = dlsym(handle, "sigaction"));
    CHECK_DLSYM_RET_RETURN(posix_api->fork_fn           = dlsym(handle, "fork"));

    /* support fork */
    posix_api->use_kernel = 1;
    lwip_sock_init();
    return 0;

err_out:
    return -1;
#undef CHECK_DLSYM_RET_RETURN
}
