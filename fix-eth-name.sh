#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC3001

set -eE

# 本脚本在首次进入新系统后运行
# 将 trans 阶段生成的网络配置中的网卡名(eth0) 改为正确的网卡名
# 也适用于安装时和安装后内核网卡命名不一致的情况
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=928923

# 首次启动时网卡名可能会被 udev/systemd 反复修改几次，需等待名称稳定。
has_eth=false
check_count=0
stable_count=0
old_state=
max_wait=60
stable_wait=10
while true; do
    check_count=$((check_count + 1))

    # 只比较接口名和链路层地址，忽略 UP/DOWN、qdisc 等运行状态变化。
    new_state=$(
        ip -o link |
            awk '$2 != "lo:" { for (i = 1; i < NF; i++) if ($i ~ /^link\//) { print $2, $(i + 1); break } }' |
            sort
    )
    if [ -n "$new_state" ]; then
        has_eth=true
    else
        has_eth=false
    fi

    if $has_eth && [ "$old_state" = "$new_state" ]; then
        stable_count=$((stable_count + 1))
    else
        stable_count=0
    fi

    old_state=$new_state

    if $has_eth && [ "$stable_count" -ge "$stable_wait" ]; then
        break
    fi

    if [ "$check_count" -ge "$max_wait" ]; then
        if ! $has_eth; then
            echo "No network interface found after ${max_wait}s." >&2
            exit 1
        fi
        echo "Network interface names did not stabilize after ${max_wait}s; continuing with the latest state." >&2
        break
    fi

    sleep 1
done

to_lower() {
    tr '[:upper:]' '[:lower:]'
}

get_ethx_by_mac() {
    local mac
    mac=$(echo "$1" | to_lower)

    ip -o link | awk -v target="$mac" '
        {
            name = $2
            sub(/:$/, "", name)
            has_master = 0
            for (i = 1; i <= NF; i++) {
                if ($i == "master") {
                    has_master = 1
                }
            }
            if (has_master) {
                next
            }
            for (i = 1; i < NF; i++) {
                if ($i == "link/ether" && tolower($(i + 1)) == target) {
                    print name
                    break
                }
            }
        }
    '
}

fix_ifupdown() {
    file=/etc/network/interfaces
    tmp_file=$file.tmp

    if ! [ -f "$file" ]; then
        echo "$file does not exist." >&2
        return 1
    fi

    rm -f "$tmp_file"
    cp -p "$file" "$tmp_file"
    true >"$tmp_file"

    ethx=
    while IFS= read -r line; do
        del_this_line=false
        if [[ "$line" = "# mac "* ]]; then
            mac=$(echo "$line" | awk '{print $NF}')
            matches=$(get_ethx_by_mac "$mac") || true
            match_count=$(printf '%s\n' "$matches" | awk 'NF { count++ } END { print count+0 }')
            if [ "$match_count" -ne 1 ]; then
                echo "Expected one interface for MAC $mac, found $match_count." >&2
                rm -f "$tmp_file"
                return 1
            fi
            ethx=$(printf '%s\n' "$matches" | awk 'NF { print; exit }')
            del_this_line=true
        elif [[ "$line" = "iface e"* ]] ||
            [[ "$line" = "auto e"* ]] ||
            [[ "$line" = "allow-hotplug e"* ]]; then
            if [ -n "$ethx" ]; then
                line=$(printf '%s\n' "$line" | awk -v ethx="$ethx" '{$2=ethx; print}')
            fi
        elif [[ "$line" = *" dev e"* ]]; then
            if [ -n "$ethx" ]; then
                line=$(printf '%s\n' "$line" | awk -v ethx="$ethx" '{$NF=ethx; print}')
            fi
        fi
        if ! $del_this_line; then
            printf '%s\n' "$line" >>"$tmp_file"
        fi
    done <"$file"

    mv "$tmp_file" "$file"
}

fix_ifupdown
