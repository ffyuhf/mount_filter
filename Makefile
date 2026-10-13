# mount_filter KPM build (pattern: kpms/selinux_hook/Makefile, aligned with
# the in-tree demo Makefiles: KP_DIR points at the repository root).
#
# Usage:
#   export TARGET_COMPILE=aarch64-none-elf-     # or rely on NDK detection
#   make                                        # silent release build
#   make DEBUG=1                                # full-log debug build
#
# 版本规则: vX.Y.Z; 日志默认零输出，DEBUG=1 恢复。
# 修改历史: 2026-10-13 23:30 — initial version (v1.0.0)

MOUNT_FILTER_VERSION := 1.0.1

ifndef KP_DIR
    KP_DIR = ../..
endif

OS_NAME = $(shell uname | tr A-Z a-z)
MACHINE = $(shell uname -m)
NDK_BIN_DIR := toolchains/llvm/prebuilt/$(OS_NAME)-$(MACHINE)/bin
ifdef ANDROID_NDK_LATEST_HOME
    NDK_PATH ?= $(ANDROID_NDK_LATEST_HOME)/$(NDK_BIN_DIR)
else ifdef ANDROID_NDK
    NDK_PATH ?= $(ANDROID_NDK)/$(NDK_BIN_DIR)
else ifdef ANDROID_NDK_HOME
    NDK_PATH ?= $(ANDROID_NDK_HOME)/$(NDK_BIN_DIR)
endif

ifdef TARGET_COMPILE
    CC := $(TARGET_COMPILE)gcc
    LD := $(TARGET_COMPILE)ld
    OBJCOPY := $(TARGET_COMPILE)objcopy
else ifdef NDK_PATH
    CC := $(NDK_PATH)/aarch64-linux-android31-clang
    LD := $(NDK_PATH)/ld.lld
    OBJCOPY := $(NDK_PATH)/llvm-objcopy
endif

# Flags aligned with selinux_hook plus -Wextra -Werror: this module's own code
# must stay warning-clean (framework-header warnings, if any, are handled by
# targeted -Wno-* additions documented in the code-change record).
CFLAGS = -Wall -Wextra -Werror -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-unwind-tables
CFLAGS += -fno-stack-protector -fno-common
CFLAGS += -mgeneral-regs-only -ffixed-x18
CFLAGS += -fno-builtin-strlen -fno-builtin-memcpy -fno-exceptions
CFLAGS += -DMOUNT_FILTER_VERSION=\"$(MOUNT_FILTER_VERSION)\"
CFLAGS += -std=gnu99

ifdef DEBUG
    CFLAGS += -DMOUNT_FILTER_DEBUG=1
endif

INCLUDE_DIRS := . include patch/include linux linux/include linux/security/selinux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := mount_filter.o

all: mount_filter_$(MOUNT_FILTER_VERSION).kpm

mount_filter_$(MOUNT_FILTER_VERSION).kpm: ${objs}
	${CC} -r -nostdlib -Wl,--no-eh-frame-hdr -o $@ $^
ifneq ($(strip $(OBJCOPY)),)
	${OBJCOPY} --remove-section=.eh_frame --remove-section=.eh_frame_hdr --remove-section=.rela.eh_frame $@
endif

%.o: %.c mount_filter.h
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
