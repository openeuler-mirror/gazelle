# Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
# gazelle is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
LSTACK_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT_DIR := $(dir $(abspath $(LSTACK_DIR)))

LWIP_INCLUDE_FILE ?= /usr/include/lwip
LIB_PATH ?= /usr/lib64

DPDK_VERSION := $(shell rpm -q --queryformat '%{VERSION}' dpdk)
ifeq ($(DPDK_VERSION),21.11)
    DPDK_INCLUDE_FILE := /usr/local/include
else
    DPDK_INCLUDE_FILE := /usr/include/dpdk
endif

AR = ar
ARFLAGS = crDP
CC ?= gcc
OPTIMIZATION = -O2 -g
RM = rm -f
LDFLAGS = -shared -ldl -lm -lpthread -lrt -lnuma -lconfig -lboundscheck
ARCH := $(shell uname -m)

ifneq ($(CC),clang)
	SEC_FLAGS = -fstack-protector-strong -Werror -Wall -Wno-deprecated-declarations -Wl,-z,relro, -Wl,-z,now -Wl,-z,noexecstack -Wtrampolines -fPIC -D_FORTIFY_SOURCE=2
else
	SEC_FLAGS = -fstack-protector-strong -Werror -Wall -Wno-deprecated-declarations -fPIC
endif
$(info $(CC):$(SEC_FLAGS))

INC = -I$(LSTACK_DIR)/include   \
      -I$(LSTACK_DIR)/../common \
      -I$(LWIP_INCLUDE_FILE)    \
      -I$(DPDK_INCLUDE_FILE)

CFLAGS += $(OPTIMIZATION) -fno-strict-aliasing $(INC) -Wno-error=unused-function

ifeq ($(GAZELLE_COVERAGE_ENABLE), 1)
	LDFLAGS += -fprofile-arcs -ftest-coverage
	CFLAGS += -fprofile-arcs -ftest-coverage
endif

ifeq ($(GAZELLE_FAULT_INJECT_ENABLE), 1)
	LDFLAGS += -DGAZELLE_FAULT_INJECT_ENABLE
	CFLAGS += -DGAZELLE_FAULT_INJECT_ENABLE
endif

ifeq ($(shell $(CC) -dumpmachine | cut -d"-" -f1), x86_64)
	CFLAGS += -mssse3
endif

CFLAGS += $(SEC_FLAGS)

SRCS =
DIRS = core netif api ../common

define register_dir
SRCS += $(patsubst %, $(1)/%, $(2))
endef

include $(patsubst %, %/dir.mk, $(DIRS))

# Linking object and library
OBJS = $(subst .c,.o,$(SRCS))

LWIP_LIB = $(LIB_PATH)/liblwip.a
LIBRTE_LIB = $(LIB_PATH)/librte_pci.so \
             $(LIB_PATH)/librte_bus_pci.so \
             $(LIB_PATH)/librte_cmdline.so \
             $(LIB_PATH)/librte_hash.so \
             $(LIB_PATH)/librte_mempool.so \
             $(LIB_PATH)/librte_mempool_ring.so \
             $(LIB_PATH)/librte_timer.so \
             $(LIB_PATH)/librte_eal.so \
             $(LIB_PATH)/librte_gro.so \
             $(LIB_PATH)/librte_ring.so \
             $(LIB_PATH)/librte_mbuf.so \
             $(LIB_PATH)/librte_kvargs.so \
             $(LIB_PATH)/librte_bus_vdev.so \
             $(LIB_PATH)/librte_net.so \
             $(LIB_PATH)/librte_ethdev.so \
             $(LIB_PATH)/librte_pdump.so

ifeq ($(shell expr $(DPDK_VERSION) \< 23.11), 1)
	LIBRTE_LIB += $(LIB_PATH)/librte_kni.so
endif

ifeq ($(DPDK_VERSION), 19.11)
	LIBRTE_LIB += $(LIB_PATH)/librte_pmd_pcap.so \
                  $(LIB_PATH)/librte_pmd_bond.so \
                  $(LIB_PATH)/librte_pmd_hinic.so \
                  $(LIB_PATH)/librte_pmd_ixgbe.so \
                  $(LIB_PATH)/librte_pmd_virtio.so
    ifneq ($(ARCH), loongarch64)
	LIBRTE_LIB += $(LIB_PATH)/librte_pmd_i40e.so
    endif
else
	LIBRTE_LIB += $(LIB_PATH)/librte_net_pcap.so \
                      $(LIB_PATH)/librte_net_bond.so \
                      $(LIB_PATH)/librte_net_hinic.so \
                      $(LIB_PATH)/librte_net_ixgbe.so \
                      $(LIB_PATH)/librte_net_virtio.so \
                      $(LIB_PATH)/librte_telemetry.so \
                      $(LIB_PATH)/librte_pcapng.so
    ifneq ($(ARCH), loongarch64)
	LIBRTE_LIB += $(LIB_PATH)/librte_net_i40e.so
    endif
endif

DEP_LIBS = $(LWIP_LIB) $(LIBRTE_LIB)
LDFLAGS += -Wl,--whole-archive $(DEP_LIBS) $(OBJS) -Wl,--no-whole-archive

# Target
LSTACK_SHARED_LIB = liblstack.so
LSTACK_STATIC_LIB = liblstack.a

.PHONY: all
all: $(LSTACK_SHARED_LIB)

depend: .depend

.depend: $(SRCS)
	rm -f ./.depend
	$(foreach SRC,$(SRCS),$(CC) $(CFLAGS) -MM -MT $(SRC:.c=.o) $(SRC)  >> .depend;)

-include .depend

$(LSTACK_SHARED_LIB): $(OBJS)
	$(CC) $(LDFLAGS) -Wl,--whole-archive -Wl,--no-whole-archive -o $@

clean:
	$(RM) $(LSTACK_SHARED_LIB) $(OBJS) .depend
