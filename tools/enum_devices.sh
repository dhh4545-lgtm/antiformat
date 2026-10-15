#!/system/bin/sh
# enum_devices.sh - 枚举 by-name 分区 dev_t (major:minor)
echo "=== by-name partitions with dev_t ==="
for f in /dev/block/by-name/*; do
  n=$(basename "$f")
  # 跳过纯数字设备名(sda/sdb...)
  case "$n" in
    sda*|sdb*|sdc*|sdd*|sde*|sdf*|mmcblk*) continue ;;
  esac
  tgt=$(readlink -f "$f" 2>/dev/null)
  [ -b "$tgt" ] || continue
  dev=$(stat -c '%t:%T' "$tgt" 2>/dev/null)
  sz=$(blockdev --getsize64 "$f" 2>/dev/null)
  echo "$n  $dev  ${sz}B"
done
echo "=== done ==="