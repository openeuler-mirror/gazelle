# Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
# gazelle is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

LIB_PATH ?= /usr/lib64
LWIP_INCLUDE_FILE ?= /usr/include/lwip

include $(ROOT_DIR)/Printlog.mk

AR = ar
ARFLAGS = crDP
CC ?= gcc
RM = rm -f
OPTIMIZATION = -O2 -g
LDFLAGS = -shared -ldl -lm -lpthread -lrt -lnuma -lconfig -lboundscheck
CFLAGS = $(OPTIMIZATION) -fno-strict-aliasing
CFLAGS += -D__USE_GNU=1 -D_GNU_SOURCE=1

ifeq ($(GAZELLE_COVERAGE_ENABLE), 1)
	LDFLAGS += -fprofile-arcs -ftest-coverage
	CFLAGS += -fprofile-arcs -ftest-coverage
endif

ifeq ($(shell $(CC) -dumpmachine | cut -d"-" -f1), x86_64)
	CFLAGS += -mssse3
endif

ifneq ($(CC),clang)
	SEC_FLAGS = -fstack-protector-strong -Werror -Wall -Wl,-z,relro, -Wl,-z,now -Wl,-z,noexecstack -Wtrampolines -fPIC -D_FORTIFY_SOURCE=2
else
	SEC_FLAGS = -fstack-protector-strong -Werror -Wall -fPIC
endif
CFLAGS += $(SEC_FLAGS)

INC = -I$(ROOT_DIR)/include \
      -I$(ROOT_DIR)/../     \
      -I$(LWIP_INCLUDE_FILE)

$(info $(CC):$(CFLAGS))
CFLAGS += $(INC)

SRCS = $(wildcard  ./api/*.c  ./core/*.c  ./netif/*.c  ../common/*.c)
# Linking object and library
OBJS = $(subst .c,.o,$(SRCS))

LWIP_LIB = $(LIB_PATH)/liblwip.a
LIBRTE_LIB = $(LIB_PATH)/librte_bus_pci.so \
             $(LIB_PATH)/librte_pci.so \
             $(LIB_PATH)/librte_cmdline.so \
             $(LIB_PATH)/librte_hash.so \
             $(LIB_PATH)/librte_mempool.so \
             $(LIB_PATH)/librte_mempool_ring.so \
             $(LIB_PATH)/librte_timer.so \
             $(LIB_PATH)/librte_eal.so \
             $(LIB_PATH)/librte_gro.so \
             $(LIB_PATH)/librte_ring.so \
             $(LIB_PATH)/librte_mbuf.so \
             $(LIB_PATH)/librte_telemetry.so \
             $(LIB_PATH)/librte_kni.so \
             $(LIB_PATH)/librte_net_ixgbe.so \
             $(LIB_PATH)/librte_kvargs.so \
             $(LIB_PATH)/librte_net_hinic.so \
             $(LIB_PATH)/librte_net_i40e.so \
             $(LIB_PATH)/librte_net_virtio.so \
             $(LIB_PATH)/librte_bus_vdev.so \
             $(LIB_PATH)/librte_net.so \
             $(LIB_PATH)/librte_rcu.so \
             $(LIB_PATH)/librte_ethdev.so \
             $(LIB_PATH)/librte_pdump.so \
             $(LIB_PATH)/librte_bpf.so \
             $(LIB_PATH)/librte_pcapng.so \
             $(LIB_PATH)/librte_security.so \
             $(LIB_PATH)/librte_cryptodev.so \
	     $(LIB_PATH)/librte_net_pcap.so \
	     $(LIB_PATH)/librte_net_bond.so


DEP_LIBS = $(LWIP_LIB) $(LIBRTE_LIB)
LDFLAGS += -Wl,--whole-archive $(DEP_LIBS) $(OBJS) -Wl,--no-whole-archive

# Target
LSTACK_SHARED_LIB = liblstack.so
LSTACK_STATIC_LIB = liblstack.a

.PHONY: all clean
all: $(LSTACK_SHARED_LIB)

$(LSTACK_SHARED_LIB): $(OBJS)
	$(call printlog, BUILD, $@)
	$(QUIET) $(CC) $(LDFLAGS) -Wl,--whole-archive -Wl,--no-whole-archive -o $@

%.o: %.c
	$(call printlog, BUILD, $@)
	$(QUIET) $(CC) $(CFLAGS) -c $(filter %.c,$^) -o $@

clean:
	$(call printlog, CLEAN, $(LSTACK_SHARED_LIB))
	$(QUIET) $(RM) $(LSTACK_SHARED_LIB) $(OBJS)
