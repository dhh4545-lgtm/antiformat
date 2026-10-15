#!/system/bin/sh
# backup_partitions.sh - 备份关键分区 (persist/基带/efs 等) 到 /sdcard/aftest/backup
# 用法: sh backup_partitions.sh
# 注意: 需要 root (Shizuku/Root shell)
BK=/sdcard/aftest/backup
mkdir -p "$BK"
LOG=/sdcard/aftest/backup_partitions.log
: > "$LOG"

echo "=== backup partitions ===" | tee -a "$LOG"

backup() {
  local name="$1"; local dev="$2"
  if [ -e "$dev" ]; then
    local sz=$(blockdev --getsize64 "$dev" 2>/dev/null)
    echo "[*] $name ($dev) size=$sz" | tee -a "$LOG"
    dd if="$dev" of="$BK/$name.img" bs=1M 2>>"$LOG"
    echo "    -> $BK/$name.img ($(stat -c%s "$BK/$name.img" 2>/dev/null) bytes)" | tee -a "$LOG"
  else
    echo "[!] $name: $dev not found" | tee -a "$LOG"
  fi
}

# 关键分区
backup persist /dev/block/by-name/persist
backup fsg /dev/block/by-name/fsg
backup fsc /dev/block/by-name/fsc
backup modemst1 /dev/block/by-name/modemst1
backup modemst2 /dev/block/by-name/modemst2
backup mdm1oemnvbktmp /dev/block/by-name/mdm1oemnvbktmp
backup oplusdycnvbk /dev/block/by-name/oplusdycnvbk
backup vm-persist /dev/block/by-name/vm-persist
backup keystore /dev/block/by-name/keystore
backup frp /dev/block/by-name/frp
backup misc /dev/block/by-name/misc
backup connsec /dev/block/by-name/connsec
backup tzsc /dev/block/by-name/tzsc
backup storsec /dev/block/by-name/storsec
backup devinfo /dev/block/by-name/devinfo
backup logfs /dev/block/by-name/logfs
backup dpm /dev/block/by-name/dpm
backup last_parti /dev/block/by-name/last_parti

echo "=== sha256 ===" | tee -a "$LOG"
for f in "$BK"/*.img; do
  [ -f "$f" ] || continue
  sha256sum "$f" >> "$LOG"
done

echo "=== done ===" | tee -a "$LOG"