#!/system/bin/sh
# gen_real_blocklist.sh - 生成所有分区的真实块设备路径列表 (/dev/block/sdXX)
# 用法: sh gen_real_blocklist.sh > /sdcard/aftest/real_blocks.list
OUT=/sdcard/aftest/real_blocks.list
: > "$OUT"

for f in /dev/block/by-name/*; do
  n=$(basename "$f")
  case "$n" in
    sda*|sdb*|sdc*|sdd*|sde*|sdf*|mmcblk*) continue ;;
  esac
  tgt=$(readlink -f "$f" 2>/dev/null)
  [ -b "$tgt" ] || continue
  dev=$(stat -c '%t:%T' "$tgt" 2>/dev/null)
  echo "$tgt  # $n ($dev)" >> "$OUT"
done
cat "$OUT"