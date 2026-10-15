#!/system/bin/sh
# reload_test.sh - 重新加载新版模块, 验证 dev_t 解析修复
# 步骤: 逻辑卸载旧模块 -> 加载新版 -> 检查 dev_t 解析
echo "=== 0. old module ==="
cat /proc/modules 2>&1 | grep -i anti
echo "=== 1. logical unload old ==="
KEY=$(dmesg 2>&1 | grep -o 'unload key: [0-9A-Za-z_-]*' | tail -1 | awk '{print $NF}')
echo "old key: $KEY"
if [ -n "$KEY" ] && [ -d /proc/antiformat ]; then
  echo "$KEY" > /proc/antiformat/unload 2>&1
  echo "unload rc=$?"
fi
sleep 1
echo "=== 2. load new ==="
cp /sdcard/aftest/antiformat.ko /data/local/tmp/antiformat.ko 2>&1
/system/bin/insmod /data/local/tmp/antiformat.ko 2>&1
echo "insmod rc=$?"
sleep 1
echo "=== 3. dmesg dev_t ==="
dmesg 2>&1 | grep -i "protect +/dev/block/sd" | tail -15
echo "=== 4. status ==="
cat /proc/antiformat/status 2>&1 | head -8
echo "=== 5. new key ==="
dmesg 2>&1 | grep -o 'unload key: [0-9A-Za-z_-]*' | tail -1
echo "=== done ==="