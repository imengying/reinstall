#!/bin/ash
# shellcheck shell=dash
# shellcheck disable=SC2086,SC3047,SC3036,SC3010,SC3001,SC3060
# 安装期脚本使用 ash 语法兼容集

# 出错后停止运行，将进入到登录界面，防止失联
set -e

# 用于判断 reinstall.sh 和 trans.sh 是否兼容
# shellcheck disable=SC2034
SCRIPT_VERSION=4BACD833-A585-23BA-6CBB-9AA4E08E0004

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
    slaac)
        if echo "$ra" | grep 'Autonomous address conf' | grep -q Yes; then
            res=1
        else
            res=0
        fi
        ;;
    dhcpv6)
        if echo "$ra" | grep 'Stateful address conf' | grep -q Yes; then
            res=1
        else
            res=0
        fi
        ;;
    rdnss) res=$(echo "$ra" | grep 'Recursive DNS server' | cut -d: -f2-) ;;
    other)
        if echo "$ra" | grep 'Stateful other conf' | grep -q Yes; then
            res=1
        else
            res=0
        fi
        ;;
    should_add_ipv4_static_dns | should_add_ipv6_static_dns)
        res=$(cat /dev/netconf/$ethx/$1 2>/dev/null || echo 0)
        ;;
    *) res=$(cat /dev/netconf/$ethx/$1) ;;
    esac

    eval "$1='$res'"
}

# 有 dhcpv4 不等于一定有默认网关
# 没有 dhcpv4 也不等于一定是静态地址
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
    # 某些环境会宣告 DHCPv6，但实际拿不到可用 IPv6 地址
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

should_add_ipv4_static_dns() {
    if ! { is_dhcpv4 || is_staticv4; }; then
        return $FALSE
    fi
    get_netconf_to should_add_ipv4_static_dns
    [ "$should_add_ipv4_static_dns" = 1 ] || is_staticv4
}

should_add_ipv6_static_dns() {
    if ! is_have_ipv6; then
        return $FALSE
    fi
    get_netconf_to should_add_ipv6_static_dns
    [ "$should_add_ipv6_static_dns" = 1 ] && return $TRUE
    if is_staticv6; then
        return $TRUE
    fi
    if { is_slaac || is_dhcpv6; } && ! is_enable_other_flag && ! is_have_rdnss; then
        return $TRUE
    fi
    return $FALSE
}

get_current_dns() {
    # 后一张网卡的 DHCP 可能改写全局 resolv.conf，使用该网卡检测后的快照。
    if [ -f "/dev/netconf/$ethx/ipv${1}_dns" ]; then
        cat "/dev/netconf/$ethx/ipv${1}_dns"
        return
    fi
    [ -f /etc/resolv.conf ] || return 0

    mark=$(
        case "$1" in
        4) echo . ;;
        6) echo : ;;
        esac
    )
    # debian 11 initrd 没有 xargs awk
    # debian 12 initrd 没有 xargs
    grep '^nameserver' /etc/resolv.conf | cut -d' ' -f2 | grep -F "$mark" | cut -d '%' -f1 || true
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
        _ra=
        ra_unavailable=

        # 安装期内核和目标系统内核的网卡命名可能不一致，因此保留 MAC 标记
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
        fi
        # DHCP 下发的 DNS 不可用时也必须保存回退 DNS。
        if should_add_ipv4_static_dns; then
            for dns in $(get_current_dns 4); do
                cat <<EOF >>$conf_file
    dns-nameservers $dns
EOF
            done
        fi

        # ipv6
        has_ipv6_iface=false
        if is_slaac; then
            echo "iface $ethx inet6 auto" >>$conf_file
            has_ipv6_iface=true

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
            has_ipv6_iface=true

        elif is_staticv6; then
            get_netconf_to ipv6_addr
            get_netconf_to ipv6_gateway
            cat <<EOF >>$conf_file
iface $ethx inet6 static
    address $ipv6_addr
    gateway $ipv6_gateway
EOF
            has_ipv6_iface=true
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

            get_netconf_to ipv6_extra_addrs
            if [ -n "$ipv6_extra_addrs" ]; then
                printf '%s\n' "$ipv6_extra_addrs" | tr ',' '\n' | while IFS= read -r addr; do
                    if [ -n "$addr" ]; then
                        echo "    post-up ip -6 addr add $addr dev $ethx" >>$conf_file
                    fi
                done
            fi
        fi

        # accept_ra/autoconf 必须属于 IPv6 iface，不能挂到 IPv4 或 auto 行后。
        if ! $has_ipv6_iface && { should_disable_accept_ra || should_disable_autoconf; }; then
            echo "iface $ethx inet6 manual" >>$conf_file
        fi

        # dns
        # 有 ipv6 但需设置 dns 的情况
        if should_add_ipv6_static_dns; then
            for dns in $(get_current_dns 6); do
                cat <<EOF >>$conf_file
    dns-nameservers $dns
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

create_dns_config() {
    local config_dir=$1 resolver=${2:-/etc/resolv.conf}
    local family dns dns_list fallback option all_dns=
    mkdir -p "$config_dir"
    : >"$config_dir/dhclient-dns.conf"
    : >"$config_dir/dhcpcd-dns.conf"
    # 保留搜索域等非 nameserver 配置，并合并各网卡检测后的 DNS。
    sed '/^nameserver[[:space:]]/d' "$resolver" >"$config_dir/resolv.conf"
    for family in 4 6; do
        dns_list=
        fallback=false
        for ethx in $(get_eths); do
            if ! "is_ipv${family}_has_internet"; then continue; fi
            get_netconf_to "should_add_ipv${family}_static_dns"
            case "$family" in
            4) [ "$should_add_ipv4_static_dns" != 1 ] || fallback=true ;;
            6) [ "$should_add_ipv6_static_dns" != 1 ] || fallback=true ;;
            esac
            for dns in $(get_current_dns "$family"); do
                case " $dns_list " in *" $dns "*) continue ;; esac
                dns_list="${dns_list:+$dns_list }$dns"
                echo "nameserver $dns" >>"$config_dir/resolv.conf"
            done
        done
        if [ -n "$dns_list" ]; then
            all_dns="${all_dns:+$all_dns }$dns_list"
            if $fallback; then
                case "$family" in
                4) option=domain-name-servers ;;
                6) option=dhcp6.name-servers ;;
                esac
                echo "supersede $option $(echo "$dns_list" | sed 's/ /, /g');" >>"$config_dir/dhclient-dns.conf"
            fi
        fi
    done
    if [ -n "$all_dns" ]; then
        # 多网卡的最后一次 DHCP 不应覆盖前面已经选好的 DNS。
        cat "$config_dir/resolv.conf" >"$resolver"
        if [ -s "$config_dir/dhclient-dns.conf" ]; then
            echo "static domain_name_servers=$all_dns" >"$config_dir/dhcpcd-dns.conf"
        fi
    fi
}

# 安装期执行入口
: main

if [ -z "$releasever" ] && [ -f /configs/releasever ]; then
    releasever=$(cat /configs/releasever)
fi

if [ -d /dev/netconf ]; then
    create_ifupdown_config /etc/network/interfaces
    create_dns_config /configs
fi
