# Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
# gazelle is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

LSTACK_LIBS=

ifdef USE_GAZELLE
ifeq ($(LSTACK_LIB_FILE),)
	LSTACK_LIB_FILE=/lib64/
endif

WRAP_PREFIX := -Wl,--wrap=
WRAP_API := epoll_ctl \
            epoll_wait \
            epoll_create \
            fcntl \
            fcntl64 \
            accept \
            accept4 \
            bind \
            connect \
            listen \
            getpeername \
            getsockname \
            getsockopt \
            setsockopt \
            socket \
            read \
            write \
            recv \
            send \
            recvmsg \
            sendmsg \
            close \
            ioctl \
            sigaction \
            fork

WRAP_LDFLAGS = $(patsubst %, $(WRAP_PREFIX)%, $(WRAP_API))


# USE_SHARED_LSTACK
$(info ***enable shared lstack***)
LSTACK_LIBS= -L$(LSTACK_LIB_FILE) -llstack $(WRAP_LDFLAGS)

endif
