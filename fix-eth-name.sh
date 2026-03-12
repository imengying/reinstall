#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC3001

set -eE

# 首次启动时等待 udev 完成网卡重命名
sleep 10
if command -v udevadm >/dev/null; then
    udevadm settle
elif command -v mdev >/dev/null; then
    mdev -sf
fi

# 本脚本在首次进入新系统后运行
# 将 trans 阶段生成的网络配置中的网卡名(eth0) 改为正确的网卡名
# 也适用于安装时和安装后内核网卡命名不一致的情况
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=928923

to_lower() {
    tr '[:upper:]' '[:lower:]'
}

retry() {
    local max_try=$1
    shift

    for i in $(seq "$max_try"); do
        if "$@"; then
            return
        else
            ret=$?
            if [ "$i" -ge "$max_try" ]; then
                return $ret
            fi
            sleep 1
        fi
    done
}

get_ethx_by_mac() {
    retry 10 _get_ethx_by_mac "$@"
}

_get_ethx_by_mac() {
    mac=$(echo "$1" | to_lower)

    ip -o link | grep -i "$mac" | grep -v master | awk '{print $2}' | cut -d: -f1 | grep .
}

fix_ifupdown() {
    file=/etc/network/interfaces
    tmp_file=$file.tmp

    rm -f "$tmp_file"

    if [ -f "$file" ]; then
        while IFS= read -r line; do
            del_this_line=false
            if [[ "$line" = "# mac "* ]]; then
                ethx=
                if mac=$(echo "$line" | awk '{print $NF}'); then
                    ethx=$(get_ethx_by_mac "$mac") || true
                fi
                del_this_line=true
            elif [[ "$line" = "iface e"* ]] ||
                [[ "$line" = "auto e"* ]] ||
                [[ "$line" = "allow-hotplug e"* ]]; then
                if [ -n "$ethx" ]; then
                    line=$(echo "$line" | awk "{\$2=\"$ethx\"; print \$0}")
                fi
            elif [[ "$line" = *" dev e"* ]]; then
                if [ -n "$ethx" ]; then
                    line=$(echo "$line" | sed -E "s/[^ ]*$/$ethx/")
                fi
            fi
            if ! $del_this_line; then
                echo "$line" >>"$tmp_file"
            fi
        done <"$file"

        mv "$tmp_file" "$file"
    fi
}

fix_ifupdown
