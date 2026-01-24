#!/bin/bash
# 测试临时文件清理功能

echo "=== 测试临时文件清理功能 ==="
echo

# 测试 1: 正常退出
echo "测试 1: 模拟正常退出（应该只清理 /reinstall-tmp）"
echo "预期: /reinstall-tmp 被删除，/reinstall-* 文件保留"
echo

# 测试 2: 异常退出
echo "测试 2: 模拟异常退出（应该清理所有临时文件）"
echo "预期: /reinstall-tmp 和 /reinstall-* 文件都被删除"
echo

# 测试 3: Ctrl+C 中断
echo "测试 3: 模拟 Ctrl+C 中断（应该清理所有临时文件）"
echo "预期: /reinstall-tmp 和 /reinstall-* 文件都被删除"
echo

echo "注意事项："
echo "1. cleanup_tmp 函数会在脚本退出时自动调用"
echo "2. 通过 trap 'cleanup_tmp' EXIT INT TERM 实现"
echo "3. 正常退出时 \$? = 0，只清理 /reinstall-tmp"
echo "4. 异常退出时 \$? != 0，清理所有临时文件"
echo "5. 使用 2>/dev/null || true 确保清理失败不会中断脚本"
