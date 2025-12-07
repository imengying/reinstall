# reinstall

一键重装 Debian 系统脚本

> 精简版本，专注于提供 Debian 系统的 Btrfs + Zstd 压缩安装

## 介绍

- 一键重装 Debian 系统（支持 Debian 9-13）
- 使用 Btrfs 文件系统 + Zstd 透明压缩（可节省 20-50% 磁盘空间）
- 自动设置 IP，智能设置动静态，支持 `/32`、`/128`、`网关不在子网范围内`、`纯 IPv6`、`IPv4/IPv6 在不同的网卡`
- 专门适配低配机器，比官方 netboot 需要更少的内存
- 全程用分区表 ID 识别硬盘，确保不会写错硬盘
- 支持 BIOS、EFI 引导，支持 ARM 服务器
- 不含自制包，所有资源均实时从镜像源获得

## 系统要求

| 系统   | 版本              | 内存   | 硬盘           | 文件系统          |
| ------ | ----------------- | ------ | -------------- | ----------------- |
| Debian | 9, 10, 11, 12, 13 | 256 MB | 1 ~ 1.5 GB ^ | Btrfs + Zstd 压缩 |

^ 表示需要 256 MB 内存 + 1.5 GB 硬盘，或 512 MB 内存 + 1 GB 硬盘

> [!WARNING]
>
> ❌ 本脚本不支持 OpenVZ、LXC 虚拟机

## 下载

```bash
curl -O https://raw.githubusercontent.com/imengying/reinstall/main/reinstall.sh || wget -O ${_##*/} $_
```

## ⚠️ 重要安全提示

> **警告：默认密码安全问题**
> 
> 本脚本使用默认密码 `123@@@`，**强烈建议**：
> 1. 首次登录后立即修改密码：`passwd`
> 2. 或使用 `--ssh-key` 参数设置 SSH 密钥登录（更安全）
> 3. **切勿在生产环境中长期使用默认密码**
> 
> 示例：使用 SSH 密钥安装
> ```bash
> bash reinstall.sh debian --ssh-key github:your_username
> ```

## 使用

### 安装 Debian

> [!CAUTION]
>
> 此功能会清除当前系统**整个硬盘**的全部数据（包含其它分区）！
>
> 数据无价，请三思而后行！

```bash
bash reinstall.sh debian [9|10|11|12|13]
```

安装最新版可不指定版本号：

```bash
bash reinstall.sh debian
```

### DD 安装

安装 Debian 官方/第三方镜像（可享受 Btrfs + Zstd 压缩）：

```bash
bash reinstall.sh dd "IMG_URL"
```

> [!NOTE]
>
> 即使是 DD 安装，如果目标镜像是 Debian 系统，脚本也会尝试自动挂载并启用 Btrfs + Zstd 透明压缩，从而节省磁盘空间。
> 
> **注意**：仅当您 DD 的原始镜像本身也使用 Btrfs 文件系统时，压缩才会生效（取决于镜像制作方式），或者本脚本能成功识别并修正挂载选项。对于非 Debian 镜像，将原样写入（不保证支持其他系统）。

### 系统特性

- **用户名**: `root`
- **默认密码**: `123@@@`
- **文件系统**: Btrfs + Zstd 透明压缩 + noatime
- **分区**: 最大化利用磁盘空间，不含 boot 分区，不含 swap 分区
- **SSH**: 重装后如需修改 SSH 端口或改成密钥登录，注意还要修改 `/etc/ssh/sshd_config.d/` 里面的文件

### Btrfs 透明压缩说明

使用 Btrfs + Zstd 压缩的系统将自动获得以下优势：

- ✅ **节省磁盘空间**：通常可节省 20-50% 的磁盘空间
- ✅ **性能优秀**：Zstd 压缩/解压速度快，对性能影响很小
- ✅ **透明操作**：对应用程序完全透明，无需任何修改
- ✅ **实时压缩**：所有写入的数据自动压缩
- ℹ️ **适用场景**：特别适合文本文件、日志、配置文件等可压缩内容
- ℹ️ **已压缩文件**：对 jpg、mp4、gz 等已压缩文件无明显效果

### Btrfs 注意事项

**✅ 推荐使用场景**：
- Web 服务器、应用服务器
- 文件服务器、开发测试环境
- 日志服务器、缓存服务器

**⚠️ 不推荐场景**：
- 高性能数据库服务器（MySQL、PostgreSQL 等）
- 超低内存环境（< 256MB）
- 需要极致随机写入性能的场景

**维护建议**：
```bash
# 查看文件系统状态
btrfs filesystem df /
btrfs device stats /

# 定期平衡（可选，用于回收空间）
btrfs balance start -dusage=50 /
```

### 可选参数

- `--password PASSWORD` 设置密码
- `--ssh-key KEY` 设置 SSH 登录公钥，[格式如下](#--ssh-key)。当使用公钥时，密码为空
- `--ssh-port PORT` 修改 SSH 端口（安装期间观察日志用，也作用于新系统）
- `--web-port PORT` 修改 Web 端口（安装期间观察日志用）
- `--frpc-toml /path/to/frpc.toml` 添加 frpc 内网穿透
- `--hold 2` 安装结束后不重启，此时可以 SSH 登录修改系统内容，系统挂载在 `/os`

### 参数格式

#### --ssh-key

- `--ssh-key "ssh-rsa ..."`
- `--ssh-key "ssh-ed25519 ..."`
- `--ssh-key "ecdsa-sha2-nistp256/384/521 ..."`
- `--ssh-key http://path/to/public_key`
- `--ssh-key github:your_username`
- `--ssh-key gitlab:your_username`
- `--ssh-key /path/to/public_key`

## 验证压缩效果

安装完成后，可以通过以下命令验证压缩效果：

```bash
# 查看挂载选项
mount | grep ' / '

# 查看文件系统空间使用（需要 btrfs-progs）
btrfs filesystem df /
btrfs filesystem usage /

# 查看压缩率（需要安装 compsize）
apt install compsize
compsize /
```

## 如何修改脚本自用

1. Fork 本仓库
2. 修改 `reinstall.sh` 开头的 `confhome`
3. 修改其它代码

## 致谢

本项目修改自 [@bin456789/reinstall](https://github.com/bin456789/reinstall)

感谢原作者提供的优秀脚本！

### 与原项目的区别

本项目是原项目的精简版本，主要变化：

- ✅ **只保留 Debian 支持**：移除了其他 Linux 发行版和 Windows 支持
- ✅ **强制使用 Btrfs**：所有安装自动使用 Btrfs 文件系统
- ✅ **启用 Zstd 压缩**：自动开启透明压缩，节省 20-50% 磁盘空间
- ✅ **DD 支持**：支持 `dd` 命令安装任意镜像，并针对 Linux 镜像尝试开启 Zstd 压缩
- ✅ **代码精简**：从 40+ 个文件精简到 17 个核心文件
- ✅ **配置优化**：使用 `compress=zstd,noatime` 挂载选项

如果您需要：
- 安装 Windows 系统
- 更多高级功能

请使用原项目：[https://github.com/bin456789/reinstall](https://github.com/bin456789/reinstall)
