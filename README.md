## 📖 项目简介

本项目是 [@bin456789/reinstall](https://github.com/bin456789/reinstall) 的精简重构版本。剔除了多余的发行版支持，专注于打磨 **Debian** 的安装体验。

**核心目标**：将任意 Linux 系统（VPS/云主机/物理机）一键重装为纯净的 Debian 系统，使用 Btrfs 文件系统，自动开启 Zstd 压缩，实现 **30%-50% 的磁盘空间节省** 和显著的 I/O 性能提升。

## ✨ 核心特性

| 特性 | 描述 |
| :--- | :--- |
| 🐧 **纯净构建** | 仅安装最核心组件，无任何多余预装软件。 |
| 💾 **Btrfs + Zstd** | 自动开启 `compress=zstd`，大幅节省空间并延长闪存寿命。 |
| 🔒 **安全强化** | 默认生成高强度随机密码（`/dev/urandom`），拒绝弱口令风险。 |
| ☁️ **云端适配** | 自动修复 Azure 加速网络问题；针对部分云厂商的 DHCP/RA 行为做兼容处理。 |
| 🔧 **灵活配置** | 支持自定义 SSH 端口、主机名、导入 SSH 公钥。 |


## 下载

```bash
curl -O https://raw.githubusercontent.com/imengying/reinstall/main/reinstall.sh || wget -O ${_##*/} $_
```

## 🚀 快速开始

### 1. 标准安装 (推荐)

最简单的使用方式，自动下载并安装最新版 Debian：

```bash
bash reinstall.sh debian
```

安装指定版本（支持 9, 10, 11, 12, 13）：

```bash
bash reinstall.sh debian 12
```

### 2. 高级配置

如果您有特定需求，可以使用以下参数：

```bash
# 指定 SSH 端口 (默认 22)
bash reinstall.sh debian --ssh-port 2222

# 指定主机名
bash reinstall.sh debian --hostname my-debian

# 指定固定密码 (不推荐，建议使用默认随机密码)
bash reinstall.sh debian --password "MySecurePassword123!"

# 导入 SSH 公钥 (直接提供)
bash reinstall.sh debian --ssh-key "ssh-ed25519 AAAA..."
```

## 📊 系统详情

| 项目 | 配置 |
| :--- | :--- |
| **默认用户** | `root` |
| **默认密码** | 安装结束时在终端**随机生成并显示**，请务必截图或记录！ |
| **文件系统** | **Btrfs** (Zstd 压缩) |
| **分区方案** | 自动扩容根分区以利用所有空间，**无 Swap 分区**。 |

## ⚙️ 前置依赖

脚本会自动检查环境，但在极简系统上可能需要手动安装基础工具：

```bash
# Debian/Ubuntu
apt update && apt install -y curl grep openssl

# CentOS/RHEL
yum install -y curl grep openssl

# Alpine
apk add curl grep openssl bash
```

## 🧹 临时文件管理

脚本运行时会创建以下临时文件：

- `/reinstall-tmp/` - 临时工作目录（脚本结束时自动清理）
- `/reinstall-vmlinuz` - 安装内核（重启后使用，正常完成时保留）
- `/reinstall-initrd` - 初始化内存盘（重启后使用，正常完成时保留）
- `/reinstall-firmware` - 固件文件（如需要，重启后使用）

**自动清理机制：**
- ✅ 脚本正常完成：清理 `/reinstall-tmp/`，保留安装文件
- ✅ 脚本异常退出：清理所有临时文件
- ✅ 用户中断（Ctrl+C）：清理所有临时文件

## 📜 许可证

本项目遵循 [GNU GPL v3.0](LICENSE) 开源协议。
