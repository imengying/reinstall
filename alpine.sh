#!/bin/bash
#
# LXC -> Alpine Linux 一键重装脚本
# 仅支持 LXC 容器（不支持 OpenVZ / KVM）
#
# 特性：
#   - 重装为 Alpine Linux，运行时可选择 3.21 / 3.22 / 3.23 / 3.24
#   - 自动识别 x86_64 / arm64 / armhf / i386 / riscv64 / ppc64le / s390x
#   - 自动识别所有 IPv4/IPv6 网卡（不同网卡可分别配置 v4/v6）
#   - 可设置新的 root 密码，直接回车则沿用当前系统的密码
#   - 保留 /root/.ssh、主机名、DNS
#   - 自动生成 Alpine ifupdown-ng 网络配置
#   - 启动时问一次版本和密码，之后全程无交互；关键步骤会在终端
#     打印进度，不会让人误以为脚本卡住了
#
# 完整过程日志：/root/alpine-reinstall.log
# （出错时终端会打印一行原因；想看细节可以 nano /root/alpine-reinstall.log）
#
# 警告：当前系统的用户空间会被完全替换，所有现有文件都会被删除。
#

set -Eeuo pipefail

SERVER="https://images.linuxcontainers.org"
ROOTFS="/x"
LOG="/root/alpine-reinstall.log"

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# ------------------------------------------------------------
# 输出处理：fd3 = 真正的终端；fd1/fd2 默认重定向进日志文件，
# 关键步骤用 msg() 显式打印到终端，避免看起来像卡住了。
# ------------------------------------------------------------
: > "$LOG"
exec 3>&1
exec >>"$LOG" 2>&1

msg() {   # 终端 + 日志
    printf '%s\n' "$*" >&3
    printf '%s\n' "$*"
}

fail() {  # 终端 + 日志，然后退出
    printf '\n错误：%s\n' "$*" >&3
    printf '\n错误：%s\n' "$*"
    exit 1
}

# 任何未被显式 `|| fail ...` 捕获的失败命令，都会在这里报出具体的
# 行号和命令，避免再出现"脚本莫名其妙退出、什么提示都没有"的情况。
trap 'fail "第 $LINENO 行执行失败: $BASH_COMMAND"' ERR

cleanup() {
    rm -f "${INDEX_FILE:-}" 2>/dev/null || true
    rm -f "${NET_FILE:-}" 2>/dev/null || true

    if mountpoint -q "$ROOTFS/oldroot" 2>/dev/null; then
        umount "$ROOTFS/oldroot" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ============================================================
# 基础检查
# ============================================================

[ "$(id -u)" -eq 0 ] || fail "请用 root 权限运行此脚本。"
[ -e "$ROOTFS" ] && fail "$ROOTFS 已存在，请先删除后再运行。"

# ============================================================
# 选择 Alpine 版本
# ============================================================

choose_version() {
    local choice=""

    msg ""
    msg "请选择要安装的 Alpine 版本："
    msg "  1) 3.21"
    msg "  2) 3.22"
    msg "  3) 3.23"
    msg "  4) 3.24 (默认)"

    if [ -r /dev/tty ]; then
        while :; do
            printf '请输入数字 [1-4，直接回车默认 4]: ' >&3
            read -r choice < /dev/tty || choice=""
            case "$choice" in
                1) ALPINE_VERSION="3.21"; break ;;
                2) ALPINE_VERSION="3.22"; break ;;
                3) ALPINE_VERSION="3.23"; break ;;
                4|"") ALPINE_VERSION="3.24"; break ;;
                *) printf '无效选项，请输入 1-4。\n' >&3 ;;
            esac
        done
    else
        # 没有可交互的终端（比如完全自动化运行），直接用默认版本，
        # 不要卡在这里等一个永远不会来的输入。
        ALPINE_VERSION="3.24"
    fi

    msg "已选择 Alpine $ALPINE_VERSION"
}

choose_version

# ============================================================
# 设置 root 密码
# ============================================================

NEW_ROOT_PASSWORD=""

choose_password() {
    local pass1="" pass2=""

    msg ""
    msg "设置 root 密码（直接回车则沿用当前系统的 root 密码）"

    if [ -r /dev/tty ]; then
        while :; do
            printf '新密码（不显示，直接回车跳过）: ' >&3
            read -r -s pass1 < /dev/tty || pass1=""
            printf '\n' >&3

            if [ -z "$pass1" ]; then
                msg "将沿用当前的 root 密码。"
                return 0
            fi

            printf '再输入一遍确认: ' >&3
            read -r -s pass2 < /dev/tty || pass2=""
            printf '\n' >&3

            if [ "$pass1" = "$pass2" ]; then
                NEW_ROOT_PASSWORD="$pass1"
                msg "已设置新的 root 密码。"
                return 0
            fi

            printf '两次输入不一致，请重新输入。\n' >&3
        done
    fi
    # 没有可交互终端时保持沿用原密码，不在这里卡住。
}

choose_password

# ============================================================
# 安装依赖
# ============================================================

install_requirements() {
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache \
            curl wget tar xz ca-certificates iproute2 gawk sed grep virt-what
    elif command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y \
            curl wget tar xz-utils ca-certificates iproute2 gawk sed grep virt-what
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y \
            curl wget tar xz ca-certificates iproute gawk sed grep virt-what
    elif command -v yum >/dev/null 2>&1; then
        yum install -y \
            curl wget tar xz ca-certificates iproute gawk sed grep virt-what
    else
        fail "不支持的包管理器。"
    fi
}

msg "[1/8] 安装依赖..."
install_requirements

for cmd in curl tar xz ip awk sed grep mount chroot; do
    command -v "$cmd" >/dev/null 2>&1 || fail "缺少命令: $cmd"
done

# ============================================================
# 检测 LXC
# ============================================================

is_lxc() {
    if command -v virt-what >/dev/null 2>&1; then
        virt-what 2>/dev/null | grep -qx "lxc" && return 0
    fi

    if [ -f /run/systemd/container ] &&
       [ "$(cat /run/systemd/container 2>/dev/null || true)" = "lxc" ]; then
        return 0
    fi

    if [ -r /proc/1/environ ] &&
       tr '\0' '\n' < /proc/1/environ 2>/dev/null | grep -qx "container=lxc"; then
        return 0
    fi

    if [ -r /proc/1/cgroup ] &&
       grep -qaE '(^|/)(lxc|lxc\.payload)(/|$)' /proc/1/cgroup 2>/dev/null; then
        return 0
    fi

    return 1
}

msg "[2/8] 检测虚拟化环境..."
is_lxc || fail "此脚本仅支持 LXC 容器。"

# ============================================================
# 架构
# ============================================================

case "$(uname -m)" in
    x86_64|amd64)   ARCH="amd64" ;;
    aarch64|arm64)  ARCH="arm64" ;;
    armv7l|armv7*)  ARCH="armhf" ;;
    i386|i686)      ARCH="i386" ;;
    riscv64)        ARCH="riscv64" ;;
    ppc64le)        ARCH="ppc64le" ;;
    s390x)          ARCH="s390x" ;;
    *) fail "不支持的架构: $(uname -m)" ;;
esac

# ============================================================
# 定位 Alpine rootfs
# ============================================================

msg "[3/8] 定位 Alpine $ALPINE_VERSION rootfs ($ARCH)..."

INDEX_FILE="$(mktemp)"

curl -fsSL "$SERVER/meta/1.0/index-system" -o "$INDEX_FILE" ||
    fail "无法下载 linuxcontainers.org 镜像索引。"

IMAGE_PATH="$(
    awk -F';' -v arch="$ARCH" -v ver="$ALPINE_VERSION" '
        $1 == "alpine" && $2 == ver && $3 == arch && $4 == "default" { print $NF }
    ' "$INDEX_FILE" | tail -n 1
)"

rm -f "$INDEX_FILE"
INDEX_FILE=""

[ -n "$IMAGE_PATH" ] || fail "没有找到架构 $ARCH 对应的 Alpine $ALPINE_VERSION 镜像。"

case "$IMAGE_PATH" in
    /*) ;;
    *) IMAGE_PATH="/$IMAGE_PATH" ;;
esac

DOWNLOAD_URL="${SERVER%/}${IMAGE_PATH%/}/rootfs.tar.xz"

curl -fsI "$DOWNLOAD_URL" >/dev/null 2>&1 ||
    fail "Alpine rootfs 不可用: $DOWNLOAD_URL"

# ============================================================
# 保存当前网络 / 主机名配置
#
# 注意：下面两个函数末尾都加了 `|| true`。很多 LXC 机器没有 IPv6
# 默认路由（或 IPv6 整个被禁用），这时 `ip -6 route show default`
# 会返回非零状态。配合 set -e + pipefail，未加保护的赋值语句会让
# 脚本直接静默退出——这是旧版本卡在这一步的真正原因。
# ============================================================

msg "[4/8] 保存当前网络/主机名配置..."

get_default_dev() {  # $1: -4 / -6
    ip "$1" route show default 2>/dev/null | awk '
        NR==1 { for (i=1;i<=NF;i++) if ($i=="dev") { print $(i+1); exit } }
    ' || true
}

get_default_gw() {   # $1: -4 / -6
    ip "$1" route show default 2>/dev/null | awk '
        NR==1 { for (i=1;i<=NF;i++) if ($i=="via") { print $(i+1); exit } }
    ' || true
}

DEFAULT4_DEV="$(get_default_dev -4)"
DEFAULT4_GW="$(get_default_gw -4)"
DEFAULT6_DEV="$(get_default_dev -6)"
DEFAULT6_GW="$(get_default_gw -6)"

CURRENT_HOSTNAME="$(hostname)"

if [ -z "$DEFAULT4_DEV" ] && [ -z "$DEFAULT6_DEV" ]; then
    fail "无法确定默认网络接口。"
fi

NET_FILE="$(mktemp)"

cat > "$NET_FILE" <<'EOF'
# Generated by alpine-lxc.sh

auto lo
iface lo inet loopback

EOF

IFACES="$(
    ip -o link show 2>/dev/null |
        awk -F': ' '{print $2}' |
        sed 's/@.*//' |
        grep -v '^lo$' |
        sort -u || true
)"

for DEV in $IFACES; do

    IPV4_ADDRS="$(ip -4 -o addr show dev "$DEV" scope global 2>/dev/null | awk '{print $4}' || true)"
    IPV6_ADDRS="$(ip -6 -o addr show dev "$DEV" scope global 2>/dev/null | awk '{print $4}' || true)"

    if [ -z "$IPV4_ADDRS" ] && [ -z "$IPV6_ADDRS" ]; then
        continue
    fi

    echo "auto $DEV" >> "$NET_FILE"

    if [ -n "$IPV4_ADDRS" ]; then
        echo "iface $DEV inet static" >> "$NET_FILE"
        while IFS= read -r ADDR; do
            [ -n "$ADDR" ] || continue
            printf '    address %s\n' "$ADDR" >> "$NET_FILE"
        done <<< "$IPV4_ADDRS"

        if [ "$DEV" = "$DEFAULT4_DEV" ] && [ -n "$DEFAULT4_GW" ]; then
            printf '    gateway %s\n' "$DEFAULT4_GW" >> "$NET_FILE"
        fi
    fi

    if [ -n "$IPV6_ADDRS" ]; then
        echo "iface $DEV inet6 static" >> "$NET_FILE"
        while IFS= read -r ADDR; do
            [ -n "$ADDR" ] || continue
            printf '    address %s\n' "$ADDR" >> "$NET_FILE"
        done <<< "$IPV6_ADDRS"

        if [ "$DEV" = "$DEFAULT6_DEV" ] && [ -n "$DEFAULT6_GW" ]; then
            printf '    gateway %s\n' "$DEFAULT6_GW" >> "$NET_FILE"
        fi
    fi

    echo >> "$NET_FILE"
done

DNS_LIST="$(
    awk '$1=="nameserver" && $2!="" { print $2 }' /etc/resolv.conf 2>/dev/null |
    head -n 4 || true
)"

if [ -z "$DNS_LIST" ]; then
    DNS_LIST=$'1.1.1.1\n8.8.8.8\n2606:4700:4700::1111\n2001:4860:4860::8888'
fi

# ============================================================
# 下载 Alpine
# ============================================================

msg "[5/8] 下载 Alpine $ALPINE_VERSION rootfs..."

mkdir -p "$ROOTFS"

# 这一步耗时最长，用 --progress-bar 把下载进度直接打到终端，
# 免得看起来像卡住了；具体字节数等细节仍然写进日志。
curl -fL --progress-bar "$DOWNLOAD_URL" 2>&3 | tar -xJ -C "$ROOTFS" ||
    fail "下载或解压 Alpine rootfs 失败。"

[ -f "$ROOTFS/etc/alpine-release" ] || fail "下载的 rootfs 无效。"

# ============================================================
# 迁移配置
# ============================================================

msg "[6/8] 迁移配置（密码 / SSH / 主机名 / 网络 / DNS）..."

ROOT_SHADOW="$(awk -F: '$1=="root" { print; exit }' /etc/shadow)"
[ -n "$ROOT_SHADOW" ] || fail "无法读取 root 密码。"

sed -i '/^root:/d' "$ROOTFS/etc/shadow"
printf '%s\n' "$ROOT_SHADOW" >> "$ROOTFS/etc/shadow"

if [ -d /root/.ssh ]; then
    mkdir -p "$ROOTFS/root"
    cp -a /root/.ssh "$ROOTFS/root/"
fi

printf '%s\n' "$CURRENT_HOSTNAME" > "$ROOTFS/etc/hostname"

mkdir -p "$ROOTFS/etc/network"
cp "$NET_FILE" "$ROOTFS/etc/network/interfaces"

rm -f "$ROOTFS/etc/resolv.conf"
printf '%s\n' "$DNS_LIST" | while IFS= read -r DNS; do
    [ -n "$DNS" ] || continue
    printf 'nameserver %s\n' "$DNS"
done > "$ROOTFS/etc/resolv.conf"

msg "[7/8] 在新系统中安装基础软件包..."

chroot "$ROOTFS" /bin/sh -c '
    apk update &&
    apk add --no-cache bash openssh ifupdown-ng ca-certificates shadow
' || fail "在新系统中安装软件包失败。"

# shadow 包装好之后才有 chpasswd 可用；只有输入了新密码才会走到这里，
# 直接回车（NEW_ROOT_PASSWORD 为空）就保留前面从旧系统拷贝的密码。
if [ -n "$NEW_ROOT_PASSWORD" ]; then
    printf 'root:%s\n' "$NEW_ROOT_PASSWORD" | chroot "$ROOTFS" chpasswd ||
        fail "设置新密码失败。"
fi

# ============================================================
# 配置 SSH
# ============================================================

if [ -f "$ROOTFS/etc/ssh/sshd_config" ]; then
    sed -i -E '/^[[:space:]]*#?[[:space:]]*PermitRootLogin[[:space:]]+/d' "$ROOTFS/etc/ssh/sshd_config"
    sed -i -E '/^[[:space:]]*#?[[:space:]]*PasswordAuthentication[[:space:]]+/d' "$ROOTFS/etc/ssh/sshd_config"
    cat >> "$ROOTFS/etc/ssh/sshd_config" <<'EOF'

PermitRootLogin yes
PasswordAuthentication yes
EOF
fi

if [ -d "$ROOTFS/root/.ssh" ]; then
    chmod 700 "$ROOTFS/root/.ssh" || true
    find "$ROOTFS/root/.ssh" -type f -exec chmod 600 {} + 2>/dev/null || true
fi

# ============================================================
# 替换旧系统
# ============================================================

msg "[8/8] 替换系统文件..."

mkdir -p "$ROOTFS/oldroot"

mount --bind / "$ROOTFS/oldroot" || fail "mount --bind 失败，此 LXC 不允许该操作。"

chroot "$ROOTFS" /bin/sh <<'CHROOT' || fail "替换系统文件失败。"
set -eu

cd /oldroot
find . -mindepth 1 -maxdepth 1 \
    ! -name dev ! -name proc ! -name sys ! -name run ! -name x \
    -exec rm -rf -- {} +

cd /
find . -mindepth 1 -maxdepth 1 \
    ! -name dev ! -name proc ! -name sys ! -name run ! -name oldroot \
    -exec mv -f -- {} /oldroot/ +
CHROOT

umount "$ROOTFS/oldroot" || fail "卸载临时根目录失败。"
rmdir "$ROOTFS/oldroot" 2>/dev/null || true
rm -rf "$ROOTFS"

rm -f "$NET_FILE"
NET_FILE=""

# ============================================================
# 收尾
# ============================================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

rc-update add devfs sysinit 2>/dev/null || true
rc-update add mdev sysinit 2>/dev/null || true
rc-update add networking default 2>/dev/null || true
rc-update add sshd default 2>/dev/null || true

if [ -f /etc/init.d/networking ]; then
    sed -i 's/--auto/-a/' /etc/init.d/networking 2>/dev/null || true
fi

sync

msg ""
msg "Alpine $ALPINE_VERSION 安装完成，请执行以下命令重启："
msg ""
msg "    reboot -f"
msg ""
