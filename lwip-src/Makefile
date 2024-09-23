LWIP_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT_DIR := $(dir $(abspath $(LWIP_DIR)))

include $(LWIP_DIR)/Printlog.mk

LWIP_INC = $(LWIP_DIR)/include
DPDK_VERSION := $(shell rpm -q --queryformat '%{VERSION}' dpdk)
ifeq ($(DPDK_VERSION),21.11)
    DPDK_INCLUDE_FILE := /usr/local/include
else
    DPDK_INCLUDE_FILE := /usr/include/dpdk
endif

CC = gcc
AR = ar
ARFLAGS = crDP

SEC_FLAGS = -fstack-protector-strong -Werror -Wall -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wtrampolines -fPIC -D_FORTIRY_SOURCE=2 
CFLAGS = $(SEC_FLAGS)
CFLAGS += -D__USE_GNU=1 -D_GNU_SOURCE=1
CFLAGS += -O2 -g 

ifeq ($(shell $(CC) -dumpmachine | cut -d"-" -f1), x86_64)
    CFLAGS += -mssse3
endif

INC = -I$(LWIP_DIR) \
      -I$(LWIP_INC) \
      -I$(DPDK_INCLUDE_FILE)

CFLAGS += $(INC)
$(info [CFLAGS] $(CFLAGS))


SRCS =
DIRS = api core netif

define register_dir
    SRCS += $(patsubst %, $(1)/%, $(2))
endef
include $(patsubst %, %/lwipgz_dir.mk, $(DIRS))

OBJS = $(subst .c,.o,$(SRCS))

LWIP_LIB = liblwip.a

INSTALL_LIB = $(DESTDIR)/usr/lib64
INSTALL_INC = $(DESTDIR)/usr/include/lwip

.PHONY: all install clean
all: $(LWIP_LIB)

$(LWIP_LIB): $(OBJS)
	$(call printlog, BUILD, $@)
	$(QUIET) $(AR) $(ARFLAGS) $@ $(OBJS)

%.o: %.c
	$(call printlog, BUILD, $@)
	$(QUIET) $(CC) $(CFLAGS) -c $(filter %.c,$^) -o $@

install:
	$(QUIET) install -dp $(INSTALL_LIB) $(INSTALL_INC)
	$(call printlog, INSTALL, $(INSTALL_LIB)/$(LWIP_LIB))
	$(QUIET) install -Dp $(LWIP_DIR)/$(LWIP_LIB) $(INSTALL_LIB)
	$(call printlog, INSTALL, $(INSTALL_INC))
	$(QUIET) cp -pr $(LWIP_INC)/* $(INSTALL_INC)/
	$(QUIET) cp -p Printlog.mk $(INSTALL_INC)/

clean:
	$(call printlog, CLEAN, $(LWIP_LIB))
	$(QUIET) $(RM) $(LWIP_LIB) $(OBJS)
