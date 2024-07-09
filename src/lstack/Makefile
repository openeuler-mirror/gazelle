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

include $(ROOT_DIR)/Printlog.mk

LIB_PATH ?= /usr/lib64
LWIP_INCLUDE_DIR ?= /usr/include/lwip

DPDK_VERSION := $(shell rpm -q --queryformat '%{VERSION}' dpdk)
ifeq ($(DPDK_VERSION),21.11)
    DPDK_INCLUDE_DIR := /usr/local/include
else
    DPDK_INCLUDE_DIR := /usr/include/dpdk
endif

AR = ar
ARFLAGS = crDP
CC ?= gcc
RM = rm -f
ARCH := $(shell uname -m)

CFLAGS = -O2 -g
LDFLAGS = -shared -ldl -lm -lpthread -lrt -lnuma -lconfig -lboundscheck

ifeq ($(GAZELLE_COVERAGE_ENABLE), 1)
	LDFLAGS += -fprofile-arcs -ftest-coverage
	CFLAGS += -fprofile-arcs -ftest-coverage
endif

ifeq ($(GAZELLE_FAULT_INJECT_ENABLE), 1)
	CFLAGS += -DGAZELLE_FAULT_INJECT_ENABLE
endif

ifeq ($(shell $(CC) -dumpmachine | cut -d"-" -f1), x86_64)
	CFLAGS += -mssse3
endif

SEC_FLAGS = -Wall -Werror -fstack-protector-strong -Wno-deprecated-declarations -fPIC
ifneq ($(CC),clang)
	SEC_FLAGS += -Wl,-z,relro, -Wl,-z,now -Wl,-z,noexecstack -Wtrampolines -D_FORTIFY_SOURCE=2
endif

INC = -I$(ROOT_DIR)/include \
      -I$(ROOT_DIR)/../     \
      -I$(LWIP_INCLUDE_DIR) \
      -I$(DPDK_INCLUDE_DIR)

CFLAGS += -fno-strict-aliasing -Wno-error=unused-function
CFLAGS += -D__USE_GNU=1 -D_GNU_SOURCE=1
CFLAGS += $(SEC_FLAGS)
CFLAGS += $(INC)


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
	ifeq ($(filter loongarch64 riscv64, $(ARCH)),)
		LIBRTE_LIB += $(LIB_PATH)/librte_net_i40e.so
	endif
endif

DEP_LIBS = $(LWIP_LIB) $(LIBRTE_LIB)

SRCS = $(wildcard  ./api/*.c  ./core/*.c  ./netif/*.c  ../common/*.c)
# Linking object and library
OBJS = $(subst .c,.o,$(SRCS))

LDFLAGS += -Wl,--whole-archive $(DEP_LIBS) $(OBJS) -Wl,--no-whole-archive

$(info [CFLAGS] $(CFLAGS))
$(info [LDFLAGS] $(LDFLAGS))

# Target
LSTACK_SHARED_LIB = liblstack.so
LSTACK_STATIC_LIB = liblstack.a

.PHONY: all clean
all: $(LSTACK_SHARED_LIB)

$(LSTACK_SHARED_LIB): $(OBJS)
	$(call printlog, BUILD, $@)
	$(QUIET) $(CC) $(LDFLAGS) -o $@

%.o: %.c
	$(call printlog, BUILD, $@)
	$(QUIET) $(CC) $(CFLAGS) -c $(filter %.c,$^) -o $@

clean:
	$(call printlog, CLEAN, $(LSTACK_SHARED_LIB))
	$(QUIET) $(RM) $(LSTACK_SHARED_LIB) $(OBJS)
