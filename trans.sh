#!/bin/ash
# shellcheck shell=dash
# shellcheck disable=SC2086,SC3047,SC3036,SC3010,SC3001,SC3060
# alpine 默认使用 busybox ash

# 出错后停止运行，将进入到登录界面，防止失联
set -eE

# 用于判断 reinstall.sh 和 trans.sh 是否兼容
# shellcheck disable=SC2034
SCRIPT_VERSION=4BACD833-A585-23BA-6CBB-9AA4E08E0003

TRUE=0
FALSE=1

get_ra_to() {
    if [ -z "$_ra" ]; then
        if command -v rdisc6 >/dev/null 2>&1; then
            _ra="$(rdisc6 -1 "$ethx" || true)"
        else
            _ra=""
            ra_unavailable=1
        fi
    fi
    eval "$1='$_ra'"
}

get_netconf_to() {
    case "$1" in
    slaac | dhcpv6 | rdnss | other) get_ra_to ra ;;
    esac

    # shellcheck disable=SC2154
    case "$1" in
    slaac) echo "$ra" | grep 'Autonomous address conf' | grep -q Yes && res=1 || res=0 ;;
    dhcpv6) echo "$ra" | grep 'Stateful address conf' | grep -q Yes && res=1 || res=0 ;;
    rdnss) res=$(echo "$ra" | grep 'Recursive DNS server' | cut -d: -f2-) ;;
    other) echo "$ra" | grep 'Stateful other conf' | grep -q Yes && res=1 || res=0 ;;
    *) res=$(cat /dev/netconf/$ethx/$1) ;;
    esac

    eval "$1='$res'"
}

# 有 dhcpv4 不等于有网关，例如 vultr 纯 ipv6
# 没有 dhcpv4 不等于是静态ip，可能是没有 ip
is_dhcpv4() {
    if ! is_ipv4_has_internet || should_disable_dhcpv4; then
        return 1
    fi

    get_netconf_to dhcpv4
    # shellcheck disable=SC2154
    [ "$dhcpv4" = 1 ]
}

is_staticv4() {
    if ! is_ipv4_has_internet; then
        return 1
    fi

    if ! is_dhcpv4; then
        get_netconf_to ipv4_addr
        get_netconf_to ipv4_gateway
        if [ -n "$ipv4_addr" ] && [ -n "$ipv4_gateway" ]; then
            return 0
        fi
    fi
    return 1
}

is_staticv6() {
    if ! is_ipv6_has_internet; then
        return 1
    fi

    if ! is_slaac && ! is_dhcpv6; then
        get_netconf_to ipv6_addr
        get_netconf_to ipv6_gateway
        if [ -n "$ipv6_addr" ] && [ -n "$ipv6_gateway" ]; then
            return 0
        fi
    fi
    return 1
}

is_dhcpv6_or_slaac() {
    get_netconf_to dhcpv6_or_slaac
    # shellcheck disable=SC2154
    [ "$dhcpv6_or_slaac" = 1 ]
}

is_ipv4_has_internet() {
    get_netconf_to ipv4_has_internet
    # shellcheck disable=SC2154
    [ "$ipv4_has_internet" = 1 ]
}

is_ipv6_has_internet() {
    get_netconf_to ipv6_has_internet
    # shellcheck disable=SC2154
    [ "$ipv6_has_internet" = 1 ]
}

should_disable_dhcpv4() {
    get_netconf_to should_disable_dhcpv4
    # shellcheck disable=SC2154
    [ "$should_disable_dhcpv4" = 1 ]
}

should_disable_accept_ra() {
    get_netconf_to should_disable_accept_ra
    # shellcheck disable=SC2154
    [ "$should_disable_accept_ra" = 1 ]
}

should_disable_autoconf() {
    get_netconf_to should_disable_autoconf
    # shellcheck disable=SC2154
    [ "$should_disable_autoconf" = 1 ]
}

is_slaac() {
    # 如果是静态（包括自动获取到 IP 但无法联网而切换成静态）直接返回 1，不考虑 ra
    # 防止部分机器slaac/dhcpv6获取的ip/网关无法上网

    # 有可能 ra 的 dhcpv6/slaac 是打开的，但实测无法获取到 ipv6 地址
    # is_dhcpv6_or_slaac 是实测结果，因此如果实测不通过，也返回 1

    # 不要判断 is_staticv6，因为这会导致死循环
    if ! is_ipv6_has_internet || ! is_dhcpv6_or_slaac || should_disable_accept_ra || should_disable_autoconf; then
        return 1
    fi
    get_netconf_to slaac
    # shellcheck disable=SC2154
    [ "$slaac" = 1 ]
}

is_dhcpv6() {
    # 如果是静态（包括自动获取到 IP 但无法联网而切换成静态）直接返回 1，不考虑 ra
    # 防止部分机器slaac/dhcpv6获取的ip/网关无法上网

    # 有可能 ra 的 dhcpv6/slaac 是打开的，但实测无法获取到 ipv6 地址
    # is_dhcpv6_or_slaac 是实测结果，因此如果实测不通过，也返回 1

    # 不要判断 is_staticv6，因为这会导致死循环
    if ! is_ipv6_has_internet || ! is_dhcpv6_or_slaac || should_disable_accept_ra || should_disable_autoconf; then
        return 1
    fi
    get_netconf_to dhcpv6

    # shellcheck disable=SC2154
    # 甲骨文即使没有添加 IPv6 地址，RA DHCPv6 标志也是开的
    # 部分系统开机需要等 DHCPv6 超时
    # 这种情况需要禁用 DHCPv6
    if [ "$dhcpv6" = 1 ] && ! ip -6 -o addr show scope global dev "$ethx" | grep -q .; then
        echo 'DHCPv6 flag is on, but DHCPv6 is not working.'
        return 1
    fi

    [ "$dhcpv6" = 1 ]
}

is_have_ipv6() {
    is_slaac || is_dhcpv6 || is_staticv6
}

is_enable_other_flag() {
    get_netconf_to other
    # shellcheck disable=SC2154
    [ "$other" = 1 ]
}

is_have_rdnss() {
    # rdnss 可能有几个
    get_netconf_to rdnss
    [ -n "$rdnss" ]
}

is_need_manual_set_dnsv6() {
    # 有没有可能是静态但是有 rdnss？
    [ -n "$ra_unavailable" ] && return $FALSE
    ! is_have_ipv6 && return $FALSE
    is_dhcpv6 && return $FALSE
    is_staticv6 && return $TRUE
    is_slaac && ! is_enable_other_flag && ! is_have_rdnss
}

get_current_dns() {
    mark=$(
        case "$1" in
        4) echo . ;;
        6) echo : ;;
        esac
    )
    # debian 11 initrd 没有 xargs awk
    # debian 12 initrd 没有 xargs
    if false; then
        grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | grep -F "$mark" | cut -d '%' -f1
    else
        grep '^nameserver' /etc/resolv.conf | cut -d' ' -f2 | grep -F "$mark" | cut -d '%' -f1
    fi
}

get_eths() {
    (
        cd /dev/netconf
        ls
    )
}

create_ifupdown_config() {
    conf_file=$1

    rm -f $conf_file

    cat <<EOF >>$conf_file
source /etc/network/interfaces.d/*

EOF

    # 生成 lo配置
    cat <<EOF >>$conf_file
auto lo
iface lo inet loopback
EOF

    # ethx
    for ethx in $(get_eths); do
        mode=auto

        # dmit debian 普通内核和云内核网卡名不一致，因此需要 rename
        # 安装系统时 ens18
        # 普通内核   ens18
        # 云内核     enp6s18
        # https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=928923

        # 头部
        get_netconf_to mac_addr
        {
            echo
            # 这是标记，fix-eth-name 要用，不要删除
            # shellcheck disable=SC2154
            echo "# mac $mac_addr"
            echo $mode $ethx
        } >>$conf_file

        # ipv4
        if is_dhcpv4; then
            echo "iface $ethx inet dhcp" >>$conf_file

        elif is_staticv4; then
            get_netconf_to ipv4_addr
            get_netconf_to ipv4_gateway
            cat <<EOF >>$conf_file
iface $ethx inet static
    address $ipv4_addr
    gateway $ipv4_gateway
EOF
            # dns
            if list=$(get_current_dns 4); then
                for dns in $list; do
                    cat <<EOF >>$conf_file
    dns-nameservers $dns
EOF
                done
            fi
        fi

        # ipv6
        if is_slaac; then
            echo "iface $ethx inet6 auto" >>$conf_file

        elif is_dhcpv6; then
            # debian 13 使用 ifupdown + dhcpcd-base
            # inet/inet6 都配置成 dhcp 时，重启后 dhcpv4 会丢失
            # 手动 systemctl restart networking 后正常
            # 删除 dhcpcd-base 安装 isc-dhcp-client（类似 debian 12 升级到 13），轮到 dhcpv6 丢失
            if [ -n "$releasever" ] && [ "$releasever" -ge 13 ]; then
                echo "iface $ethx inet6 auto" >>$conf_file
            else
                echo "iface $ethx inet6 dhcp" >>$conf_file
            fi

        elif is_staticv6; then
            if [ -n "$ra_unavailable" ]; then
                echo "iface $ethx inet6 auto" >>$conf_file
                continue
            fi
            get_netconf_to ipv6_addr
            get_netconf_to ipv6_gateway
            cat <<EOF >>$conf_file
iface $ethx inet6 static
    address $ipv6_addr
    gateway $ipv6_gateway
EOF
            # debian 9
            # ipv4 支持静态 onlink 网关
            # ipv6 不支持静态 onlink 网关，需使用 post-up 添加，未测试动态
            # ipv6 也不支持直接 ip route add default via xxx onlink
            if [ -n "$releasever" ] && [ "$releasever" -le 9 ]; then
                # debian 添加 gateway 失败时不会执行 post-up
                # 因此 gateway post-up 只能二选一

                # 注释最后一行，也就是 gateway
                sed -Ei '$s/^( *)/\1# /' "$conf_file"
                cat <<EOF >>$conf_file
    post-up ip route add $ipv6_gateway dev $ethx
    post-up ip route add default via $ipv6_gateway dev $ethx
EOF
            fi
        fi

        # dns
        # 有 ipv6 但需设置 dns 的情况
        if is_need_manual_set_dnsv6; then
            for dns in $(get_current_dns 6); do
                cat <<EOF >>$conf_file
    dns-nameserver $dns
EOF
            done
        fi

        # 禁用 ra
        if should_disable_accept_ra; then
            cat <<EOF >>$conf_file
    accept_ra 0
EOF
        fi

        # 禁用 autoconf
        if should_disable_autoconf; then
            cat <<EOF >>$conf_file
    autoconf 0
EOF
        fi
    done
}

# debian initrd 会寻找 main
# 并调用本文件的 create_ifupdown_config 方法
: main

if [ -d /dev/netconf ]; then
    create_ifupdown_config /etc/network/interfaces
fi
