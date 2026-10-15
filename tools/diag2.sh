#!/system/bin/sh
# diag2.sh - 查 dmesg 中 protect 解析的 dev_t + 检查 bootdevice 别名
echo "=== 1. dmesg protect lines ==="
dmesg 2>&1 | grep -i "protect +" | tail -20
echo "=== 2. dmesg init_boot ==="
dmesg 2>&1 | grep -i "init_boot" | tail -10
echo "=== 3. bootdevice 目录 ==="
ls -la /dev/block/bootdevice/by-name/ 2>&1 | grep -iE "init_boot|persist" | head
echo "=== 4. by-name 目录 ==="
ls -la /dev/block/by-name/ 2>&1 | grep -iE "init_boot|persist" | head
echo "=== 5. readlink 比较 ==="
readlink -f /dev/block/bootdevice/by-name/init_boot_b 2>&1
readlink -f /dev/block/by-name/init_boot_b 2>&1
echo "=== 6. stat via readlink target ==="
stat -c '%t:%T %n' "$(readlink -f /dev/block/bootdevice/by-name/init_boot_b)" 2>&1
stat -c '%t:%T %n' "$(readlink -f /dev/block/by-name/init_boot_b)" 2>&1
echo "=== done ==="