#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 AntiFormat contributors
#
# AntiFormat uninstall - 卸载前做逻辑卸载（防护停用）
# v0.3.0: 卸载必须通过 afd 守护进程的"错别字人机验证"（60 段题随机出题）
#         恶意程序无法通过验证（无人操作永远过不了），只能由用户手动确认
MODDIR=${0%/*}
AFD_BIN="/data/adb/modules/antiformat/afd"
LOGF="/data/adb/modules/antiformat/antiformat.log"

echo "**********************************************"
echo " AntiFormat 卸载验证"
echo "**********************************************"
echo " 卸载需要人机验证（修正错别字）。"
echo " 如果 afd 守护进程未运行，请先重启设备。"
echo ""

if [ ! -f "$AFD_BIN" ]; then
  echo "[!] afd 二进制不存在: $AFD_BIN"
  echo "    无法验证卸载，防护保持激活。"
  echo "    如确实需要卸载，请先移除模块再重启。"
  exit 1
fi

if [ ! -d /proc/antiformat ]; then
  echo "[!] 内核模块未加载（/proc/antiformat 不存在）"
  echo "    直接移除模块即可（防护不在内核中）。"
  exit 0
fi

# 调用 afd 验证卸载（交互式: 显示错别字题, 用户输入修正后的句子）
"$AFD_BIN" verify
rc=$?

if [ $rc -eq 0 ]; then
  echo ""
  echo "[antiformat] 逻辑卸载完成，防护已停用。"
  echo "[antiformat] 模块文件将被移除。"
  echo ""

  # 清理日志
  rm -f "$LOGF" 2>/dev/null
  # 清理 socket
  rm -f /data/local/tmp/afd.sock 2>/dev/null

  # 继续卸载流程（删除模块目录由 KernelSU 完成）
  exit 0
fi

echo ""
echo "[!] 验证失败，卸载中止。防护保持激活。"
exit 1