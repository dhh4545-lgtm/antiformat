#!/system/bin/sh
# run_destroy.sh - 极限破坏测试 (备份 -> 攻击 -> sha256校验 -> 自动恢复)
BK=/sdcard/aftest/init_boot_b.bak2
DEV=/dev/block/by-name/init_boot_b
LOG=/sdcard/aftest/destroy_test.log
BIN=/data/local/tmp/destroy_initboot

echo "=== destroy_initboot 极限测试 ===" > "$LOG"

# 1. 确认备份存在
if [ ! -f "$BK" ]; then
  echo "!!! 备份不存在: $BK (先运行 backup_initboot.sh)" >> "$LOG"
  echo "!!! 备份不存在" 
  exit 2
fi

# 2. 攻击前 sha256
echo "--- before ---" >> "$LOG"
BEFORE=$(sha256sum "$DEV" | awk '{print $1}')
echo "$BEFORE" >> "$LOG"

# 3. 执行攻击 (从 sdcard 复制到 /data/local/tmp 再运行)
cp /sdcard/aftest/destroy_initboot "$BIN" 2>>"$LOG"
chmod 755 "$BIN" 2>>"$LOG"
"$BIN" /dev/block/by-name/init_boot_b >> "$LOG" 2>&1
RC=$?
echo "attack rc=$RC" >> "$LOG"

# 4. 攻击后 sha256
echo "--- after ---" >> "$LOG"
AFTER=$(sha256sum "$DEV" | awk '{print $1}')
echo "$AFTER" >> "$LOG"

# 5. 对比: 不一致 = 有洞且被破坏, 立即恢复
if [ "$BEFORE" != "$AFTER" ]; then
  echo "!!! 分区被破坏! 立即恢复..." >> "$LOG"
  dd if="$BK" of="$DEV" bs=1M conv=fsync 2>>"$LOG"
  echo "restored" >> "$LOG"
  echo "!!! 防护有洞: 分区内容被改写, 已从备份恢复" >> "$LOG"
else
  echo "OK: 分区内容未变, 攻击全部被拦" >> "$LOG"
fi

echo "=== done ===" >> "$LOG"
cat "$LOG"