# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 AntiFormat contributors
#
# AntiFormat kernel module Makefile
#
# KDIR 指向 GKI 6.6 内核源码树（含完整 Kbuild 基础设施）
# 示例: make KDIR=/path/to/gki-kernel

KDIR ?= /data/user/0/com.ai.assistance.operit/files/workspace/8beaccbf-4297-46a2-b1ea-dfaa70322fcc/antiformat/build/gki-kernel
ARCH ?= arm64
CROSS_COMPILE ?= aarch64-linux-gnu-

obj-m := antiformat.o
antiformat-objs := af_main.o ksym.o mmuhack.o

# 使用与内核相同的编译标志，避免 CFI/签名问题
ccflags-y := -fno-pic -fno-pie -O2

# 模块符号通过运行时 kprobe/kallsyms 动态解析，静态 modpost 无需全部符号；
# 且 GKI 符号无命名空间，放宽 modpost 检查避免 namespace 误报
KBUILD_MODPOST_WARN := 1

all:
	make -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	make -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean

install:
	@echo "Module built: antiformat.ko"
	@echo "Place it into KernelSU module: /data/adb/modules/antiformat/system/lib/modules/"

.PHONY: all clean install