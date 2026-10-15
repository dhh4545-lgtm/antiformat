#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 AntiFormat contributors
#
# AntiFormat service - 开机自动加载 antiformat 内核模块 + 启动 afd 守护
# v0.3.0: 极端模式(拦 /dev/block) + 白名单 + afd 守护进程(人机验证卸载)
# 注意: 必须等系统完全启动后再加载, 否则 persist/基带初始化写会被拦截导致分区坏死
MODDIR=${0%/*}

KOMOD="/data/adb/modules/antiformat/lib/modules/antiformat.ko"
AFD_BIN="/data/adb/modules/antiformat/afd"
LOGF="/data/adb/modules/antiformat/antiformat.log"

log() {
  echo "[antiformat] $*" >> "$LOGF" 2>&1
  echo "[antiformat] $*" > /dev/kmsg 2>/dev/null || true
}

# 0) 等待系统完全启动 (persist/基带/传感器初始化完成后再加载, 防分区坏死)
n=0
while [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ]; do
  n=$((n + 1))
  if [ $n -ge 60 ]; then
    log "WARN: sys.boot_completed not set after 120s, continuing anyway"
    break
  fi
  sleep 2
done
log "boot_completed=$(getprop sys.boot_completed 2>/dev/null) (waited $((n * 2))s)"

# 1) 加载内核模块（重复加载返回 EEXIST，属正常——说明已加载）
if [ -f "$KOMOD" ]; then
  /system/bin/insmod "$KOMOD" 2>/dev/null
  rc=$?
  if [ $rc -eq 0 ]; then
    log "insmod OK"
  else
    log "insmod rc=$rc (EEXIST=已加载, 正常)"
  fi
else
  log "module not found: $KOMOD"
fi

# 2) 启动 afd 守护进程（注册 pid 受内核保护 + 一次性读 key 入内存）
if [ -f "$AFD_BIN" ] && [ -d /proc/antiformat ]; then
  # 防止重复启动
  if ! pgrep -f 'antiformat/afd$' >/dev/null 2>&1; then
    chmod 755 "$AFD_BIN"
    # 以后台方式启动守护 (setsid 脱离终端, 防被杀)
    setsid "$AFD_BIN" >/dev/null 2>&1 &
    sleep 1
    if pgrep -f 'antiformat/afd$' >/dev/null 2>&1; then
      log "afd daemon started"
    else
      log "afd daemon start FAILED"
    fi
  else
    log "afd daemon already running"
  fi

  # 看门狗: 每 30 秒检查 afd 是否存活, 死亡则重启 (最多重启 5 次)
  (
    tries=0
    while [ $tries -lt 5 ]; do
      sleep 30
      if ! pgrep -f 'antiformat/afd$' >/dev/null 2>&1; then
        # afd 死亡: 重新拉起 (注意: key 已被读走, 重启后 key 无法再读,
        # 卸载将不可用——但防护仍在, 符合设计)
        setsid "$AFD_BIN" >/dev/null 2>&1 &
        tries=$((tries + 1))
        log "afd daemon restarted (tries=$tries)"
      fi
    done
  ) &
else
  log "afd not started (module not loaded or binary missing)"
fi

# 3) 状态
log "status: $(cat /proc/antiformat/status 2>/dev/null | tr '\n' ' ')"

exit 0