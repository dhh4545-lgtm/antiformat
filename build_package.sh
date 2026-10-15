#!/bin/bash
# build_package.sh - 打包 AntiFormat KernelSU 模块 (v0.3.0)
# 用法: bash build_package.sh        (在 antiformat/ 根目录下执行)
#
# 前置: 内核模块已编译 (kernel/antiformat.ko) + afd 已编译 (daemon/afd)
# 产物: dist/antiformat-kernelsu.zip
#
# zip 根目录结构（标准 KernelSU 模块）:
#   antiformat-kernelsu.zip
#   ├── module.prop
#   ├── customize.sh
#   ├── service.sh
#   ├── uninstall.sh
#   ├── afd                  (守护二进制)
#   └── lib/modules/antiformat.ko

set -e

# 项目根 = 脚本所在目录（antiformat/）
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="$ROOT_DIR/kernel"
MODULE_DIR="$ROOT_DIR/module"
DAEMON_DIR="$ROOT_DIR/daemon"
DIST_DIR="$ROOT_DIR/dist"
STAGE_DIR="$ROOT_DIR/build/module_stage"

echo "[*] AntiFormat v0.3.0 打包开始"

# 1) 检查内核模块
KO="$KERNEL_DIR/antiformat.ko"
if [ ! -f "$KO" ]; then
  echo "[!] 未找到 $KO，请先编译内核模块"
  exit 1
fi
echo "[*] 内核模块: $KO ($(stat -c%s "$KO") bytes)"

# 2) 检查 afd 守护二进制
AFD="$DAEMON_DIR/afd"
if [ ! -f "$AFD" ]; then
  echo "[!] 未找到 $AFD，请先编译 afd"
  exit 1
fi
echo "[*] 守护二进制: $AFD ($(stat -c%s "$AFD") bytes)"

# 3) 准备 KernelSU 模块暂存目录
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/lib/modules"

cp -a "$KO" "$STAGE_DIR/lib/modules/antiformat.ko"
cp -a "$AFD" "$STAGE_DIR/afd"
cp -a "$MODULE_DIR/module.prop" "$STAGE_DIR/"
cp -a "$MODULE_DIR/customize.sh" "$STAGE_DIR/"
cp -a "$MODULE_DIR/service.sh" "$STAGE_DIR/"
cp -a "$MODULE_DIR/uninstall.sh" "$STAGE_DIR/"

# 设置可执行权限
chmod 755 "$STAGE_DIR/service.sh" "$STAGE_DIR/uninstall.sh" "$STAGE_DIR/customize.sh"
chmod 755 "$STAGE_DIR/afd"
chmod 644 "$STAGE_DIR/module.prop"

# 4) 打包 zip (python3 zipfile)
mkdir -p "$DIST_DIR"
ZIP="$DIST_DIR/antiformat-kernelsu.zip"
rm -f "$ZIP"

python3 - "$STAGE_DIR" "$ZIP" <<'PYEOF'
import sys, os, zipfile, stat
stage, outzip = sys.argv[1], sys.argv[2]
# 需要可执行位的文件 (unix 权限 0755)
EXEC_FILES = {
    'service.sh', 'uninstall.sh', 'customize.sh', 'afd',
}
with zipfile.ZipFile(outzip, 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk(stage):
        for f in files:
            full = os.path.join(root, f)
            arc = os.path.relpath(full, stage)
            info = zipfile.ZipInfo(arc)
            info.compress_type = zipfile.ZIP_DEFLATED
            # 保留 unix 权限位 (默认 0644, 可执行文件 0755)
            if arc in EXEC_FILES:
                info.external_attr = (0o100755 << 16)
            else:
                info.external_attr = (0o100644 << 16)
            with open(full, 'rb') as fh:
                zf.writestr(info, fh.read())
print(f"[*] zip entries:")
with zipfile.ZipFile(outzip) as zf:
    for i in zf.infolist():
        mode = (i.external_attr >> 16) & 0o777
        print(f"    {i.filename}  ({i.file_size}B -> {i.compress_size}B, mode={oct(mode)})")
PYEOF

echo "[*] 打包完成: $ZIP"
echo ""
echo "=============================================="
echo "  安装方式:"
echo "  1. 把 antiformat-kernelsu.zip 传到设备"
echo "  2. 在 KernelSU 管理器中 模块->本地安装"
echo "  3. 重启后模块自动加载 + afd 守护启动"
echo "  4. 卸载: 在 KernelSU 卸载, 需修正错别字验证"
echo "=============================================="