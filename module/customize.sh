#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 AntiFormat contributors
#
# AntiFormat customize.sh - KernelSU 安装脚本 (安装 zip 时由管理器执行)
# v0.3.0: 极端模式 + afd 守护

ui_print "*******************************"
ui_print " AntiFormat 防格机保护模块 v0.3.0"
ui_print "*******************************"

# 1) 架构检查 (KernelSU 提供 $ARCH; 兜底用 uname -m)
ARCH_CHK="${ARCH:-$(uname -m 2>/dev/null)}"
case "$ARCH_CHK" in
  arm64|aarch64|arm64-v8a)
    ui_print "- 架构 OK: $ARCH_CHK"
    ;;
  *)
    abort "错误: 仅支持 arm64 (aarch64) 设备, 当前: $ARCH_CHK"
    ;;
esac

# 2) 内核版本展示 (仅供确认兼容性)
ui_print "- 当前内核: $(uname -r 2>/dev/null)"

# 3) 检查 /proc/antiformat 是否已存在 (旧模块残留会提示)
if [ -d /proc/antiformat ]; then
  ui_print "- 警告: 检测到 antiformat 已在内核中 (旧版残留)"
  ui_print "  将使用最新版覆盖, 重启后生效"
fi

# 4) afd 二进制权限
chmod 755 "$MODDIR/afd" 2>/dev/null
ui_print "- afd 守护二进制就绪"

# 5) 安装完成提示
ui_print "- 安装完成!"
ui_print "- 本版特性:"
ui_print "  1. 极端模式: 任何进程(含 root)不能打开 /dev/block"
ui_print "  2. 白名单系统进程编译期内定, 不可修改"
ui_print "  3. afd 守护进程: 卸载需修正错别字(人机验证)"
ui_print "  4. /data/adb 等路径受保护"

exit 0