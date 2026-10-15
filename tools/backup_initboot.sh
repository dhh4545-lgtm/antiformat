#!/system/bin/sh
# backup_initboot.sh - 备份当前 init_boot_b (测试恢复点) + sha256
BK=/sdcard/aftest/init_boot_b.bak2
SRC=/dev/block/by-name/init_boot_b
LOG=/sdcard/aftest/initboot_backup.log

echo "=== backup init_boot_b ===" > "$LOG"
echo "src: $SRC" >> "$LOG"
echo "dst: $BK" >> "$LOG"

dd if="$SRC" of="$BK" bs=1M 2>>"$LOG"
echo "--- sha256 before ---" >> "$LOG"
sha256sum "$SRC" >> "$LOG" 2>&1
echo "--- sha256 backup ---" >> "$LOG"
sha256sum "$BK" >> "$LOG" 2>&1
echo "--- size ---" >> "$LOG"
stat -c '%s bytes' "$BK" >> "$LOG" 2>&1
echo "=== done ===" >> "$LOG"
cat "$LOG"