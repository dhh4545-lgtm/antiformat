#!/system/bin/sh
# unload_af.sh - 用 key 逻辑停用 antiformat 防护 (disabled=1)
echo "=== status before ==="
cat /proc/antiformat/status 2>&1
echo "=== find key ==="
dmesg 2>/dev/null | grep -a 'unload key' | tail -2
K=$(dmesg 2>/dev/null | grep -a 'unload key' | tail -1 | sed 's/.*unload key[: ]*//')
echo "key=[$K]"
if [ -n "$K" ]; then
  echo "$K" > /proc/antiformat/unload 2>&1
  echo "unload cmd exit=$?"
fi
sleep 1
echo "=== status after ==="
cat /proc/antiformat/status 2>&1
echo "=== done ==="
