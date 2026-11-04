#!/bin/ash
# shellcheck shell=dash
# 安装期 initrd 网络探测与回填脚本

# accept_ra 接收 RA + 自动配置网关
# autoconf  自动配置地址，依赖 accept_ra

mac_addr=$1
ipv4_addr=$2
ipv4_gateway=$3
ipv6_addr=$4
ipv6_gateway=$5
is_in_china=$6
ipv6_extra_addrs=$7

DHCP_TIMEOUT=15
DNS_FILE_TIMEOUT=5
TEST_TIMEOUT=10

# 通过访问常见公共地址的开放端口来判断连通性
# 此时可能还没有稳定的 DNS 解析能力
# HTTP 80
# HTTPS/DOH 443
# DOT 853
if $is_in_china; then
    ipv4_dns1='223.5.5.5'
    ipv4_dns2='119.29.29.29' # 不开放 853
    ipv6_dns1='2400:3200::1'
    ipv6_dns2='2402:4e00::' # 不开放 853
else
    ipv4_dns1='1.1.1.1'
    ipv4_dns2='8.8.8.8' # 不开放 80
    ipv6_dns1='2606:4700:4700::1111'
    ipv6_dns2='2001:4860:4860::8888' # 不开放 80
fi

# 找到主网卡
# debian 11 initrd 没有 xargs awk
# debian 12 initrd 没有 xargs
get_ethx() {
    # 过滤 azure vf (带 master ethx)
    # 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP qlen 1000\    link/ether 60:45:bd:21:8a:51 brd ff:ff:ff:ff:ff:ff
    # 3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP800> mtu 1500 qdisc mq master eth0 state UP qlen 1000\    link/ether 60:45:bd:21:8a:51 brd ff:ff:ff
    ip -o link | grep -i "$mac_addr" | grep -v master | cut -d' ' -f2 | cut -d: -f1 | grep .
}

get_first_ipv4_addr() {
    # debian 11 initrd 没有 xargs awk
    # debian 12 initrd 没有 xargs
    ip -4 -o addr show scope global dev "$ethx" | head -1 | grep -o '[0-9\.]*/[0-9]*'
}

get_first_ipv4_gateway() {
    # debian 11 initrd 没有 xargs awk
    # debian 12 initrd 没有 xargs
    ip -4 route show default dev "$ethx" | head -1 | cut -d' ' -f3
}

remove_netmask() {
    cut -d/ -f1
}

get_first_ipv6_addr() {
    local addresses addr
    # 额外地址可能排在第一位（腾讯云 DHCPv6 尤其常见）。优先使用旧系统主地址，
    # 保留多 IPv6 功能，但不能让一个不可用的额外地址导致整组地址被删除。
    addresses=$(ip -6 -o addr show scope global dev "$ethx" |
        grep -Ev ' (tentative|dadfailed)( |$)' |
        sed -n 's/.* inet6 \([^ ]*\).*/\1/p')
    for addr in $addresses; do
        if [ "${addr%/*}" = "${ipv6_addr%/*}" ]; then
            echo "$addr"
            return
        fi
    done
    printf '%s\n' "$addresses" | head -1
}

get_first_ipv6_gateway() {
    # debian 11 initrd 没有 xargs awk
    # debian 12 initrd 没有 xargs
    ip -6 route show default dev "$ethx" | head -1 | cut -d' ' -f3
}

is_have_ipv4_addr() {
    ip -4 addr show scope global dev "$ethx" | grep -q inet
}

is_have_ipv6_addr() {
    ip -6 addr show scope global dev "$ethx" | grep -q inet6
}

is_have_ipv4_gateway() {
    ip -4 route show default dev "$ethx" | grep -q .
}

is_have_ipv6_gateway() {
    ip -6 route show default dev "$ethx" | grep -q .
}

is_have_ipv4() {
    if ! is_have_ipv4_addr; then
        return 1
    fi
    is_have_ipv4_gateway
}

is_have_ipv6() {
    if ! is_have_ipv6_addr; then
        return 1
    fi
    is_have_ipv6_gateway
}

is_have_ipv4_dns() {
    [ -f /etc/resolv.conf ] || return 1
    grep -q '^nameserver .*\.' /etc/resolv.conf
}

is_have_ipv6_dns() {
    [ -f /etc/resolv.conf ] || return 1
    grep -q '^nameserver .*:' /etc/resolv.conf
}

add_missing_ipv4_config() {
    if [ -n "$ipv4_addr" ] && [ -n "$ipv4_gateway" ]; then
        if ! is_have_ipv4_addr; then
            ip -4 addr add "$ipv4_addr" dev "$ethx"
        fi

        if ! is_have_ipv4_gateway; then
            # 如果 dhcp 无法设置onlink网关，那么在这里设置
            # debian 9 ipv6 不能识别 onlink，但 ipv4 能识别 onlink
            ip -4 route add "$ipv4_gateway" dev "$ethx"
            ip -4 route add default via "$ipv4_gateway" dev "$ethx"
        fi
    fi
}

add_missing_ipv6_config() {
    if [ -n "$ipv6_addr" ] && [ -n "$ipv6_gateway" ]; then
        if ! is_have_ipv6_addr; then
            ip -6 addr add "$ipv6_addr" dev "$ethx"
        fi

        if ! is_have_ipv6_gateway; then
            # 如果 dhcp 无法设置onlink网关，那么在这里设置
            # debian 9 ipv6 不能识别 onlink
            ip -6 route add "$ipv6_gateway" dev "$ethx"
            ip -6 route add default via "$ipv6_gateway" dev "$ethx"
        fi

        if [ -n "$ipv6_extra_addrs" ]; then
            printf '%s\n' "$ipv6_extra_addrs" | tr ',' '\n' | while IFS= read -r addr; do
                if [ -n "$addr" ]; then
                    ip -6 addr add "$addr" dev "$ethx" 2>/dev/null || true
                fi
            done
        fi
    fi
}

is_need_test_ipv4() {
    if ! is_have_ipv4; then
        return 1
    fi
    if [ "${1:-ip}" = full ]; then
        ! $ipv4_has_internet_with_dns
    else
        ! $ipv4_has_internet
    fi
}

is_need_test_ipv6() {
    if ! is_have_ipv6; then
        return 1
    fi
    if [ "${1:-ip}" = full ]; then
        ! $ipv6_has_internet_with_dns
    else
        ! $ipv6_has_internet
    fi
}

# 优先使用 initrd 内现成的 wget / nc 做连通性测试
# 只要目标端口可连通，就视为该协议可用

test_by_wget() {
    local src=$1 dst=$2 url

    case "$dst" in
    http://* | https://*) url=$dst ;;
    *:*) url="https://[$dst]" ;;
    *) url="https://$dst" ;;
    esac

    # tcp 443 通了就算成功，不管 http 是不是 404
    # grep -m1 快速返回
    wget -T "$TEST_TIMEOUT" \
        --bind-address="$src" \
        --no-check-certificate \
        --max-redirect 0 \
        --tries 1 \
        -O /dev/null \
        "$url" 2>&1 | grep -iq -m1 connected
}

test_by_nc() {
    local src=$1 dst=$2

    # 完整检测需解析域名并限定源地址；Debian initrd 使用 GNU wget。
    case "$dst" in
    http://* | https://*) test_by_wget "$src" "$dst"; return ;;
    esac

    # tcp 443 通了就算成功
    nc -z -v \
        -w "$TEST_TIMEOUT" \
        -s "$src" \
        "$dst" 443
}

is_debian_kali() {
    [ -f /etc/lsb-release ] || return 1
    grep -Eiq 'Debian|Kali' /etc/lsb-release
}

test_connect() {
    if is_debian_kali; then
        test_by_wget "$1" "$2"
    else
        test_by_nc "$1" "$2"
    fi
}

test_internet() {
    local mode=${1:-ip} i current_ipv4_addr current_ipv6_addr
    local ipv4_dst1 ipv4_dst2 ipv6_dst1 ipv6_dst2
    if [ "$mode" = full ]; then
        ipv4_dst1=https://www.qualcomm.cn/
        ipv4_dst2=https://www.autodesk.com.cn/
        ipv6_dst1=$ipv4_dst1
        ipv6_dst2=$ipv4_dst2
    else
        ipv4_dst1=$ipv4_dns1
        ipv4_dst2=$ipv4_dns2
        ipv6_dst1=$ipv6_dns1
        ipv6_dst2=$ipv6_dns2
    fi
    for i in $(seq 5); do
        echo "Testing Internet Connection ($mode). Test $i... "
        if is_need_test_ipv4 "$mode" && { current_ipv4_addr="$(get_first_ipv4_addr | remove_netmask)"; test_connect "$current_ipv4_addr" "$ipv4_dst1" >/dev/null 2>&1 || test_connect "$current_ipv4_addr" "$ipv4_dst2" >/dev/null 2>&1; }; then
            echo "IPv4 has internet."
            ipv4_has_internet=true
            if [ "$mode" = full ]; then ipv4_has_internet_with_dns=true; fi
        fi
        if is_need_test_ipv6 "$mode" && { current_ipv6_addr="$(get_first_ipv6_addr | remove_netmask)"; test_connect "$current_ipv6_addr" "$ipv6_dst1" >/dev/null 2>&1 || test_connect "$current_ipv6_addr" "$ipv6_dst2" >/dev/null 2>&1; }; then
            echo "IPv6 has internet."
            ipv6_has_internet=true
            if [ "$mode" = full ]; then ipv6_has_internet_with_dns=true; fi
        fi
        if ! is_need_test_ipv4 "$mode" && ! is_need_test_ipv6 "$mode"; then
            break
        fi
        sleep 1
    done
}

flush_ipv4_dns() {
    sed -i '/^nameserver[[:space:]].*\./d' /etc/resolv.conf
}

flush_ipv6_dns() {
    sed -i '/^nameserver[[:space:]].*:/d' /etc/resolv.conf
}

add_ipv4_static_dns() {
    printf 'nameserver %s\n' "$ipv4_dns1" "$ipv4_dns2" >>/etc/resolv.conf
}

add_ipv6_static_dns() {
    printf 'nameserver %s\n' "$ipv6_dns1" "$ipv6_dns2" >>/etc/resolv.conf
}

configure_dns() {
    # /etc/resolv.conf 在多网卡间共享；只为已验证能联网的协议添加回退 DNS。
    if $ipv4_has_internet && ! is_have_ipv4_dns; then
        should_add_ipv4_static_dns=true
        add_ipv4_static_dns
    fi
    if $ipv6_has_internet && ! is_have_ipv6_dns; then
        should_add_ipv6_static_dns=true
        add_ipv6_static_dns
    fi

    test_internet full
    if $ipv4_has_internet && ! $ipv4_has_internet_with_dns; then
        echo 'IPv4 works but DNS failed; using static DNS.'
        should_add_ipv4_static_dns=true
        flush_ipv4_dns
        add_ipv4_static_dns
        test_internet full
    fi
    if $ipv6_has_internet && ! $ipv6_has_internet_with_dns; then
        echo 'IPv6 works but DNS failed; using static DNS.'
        should_add_ipv6_static_dns=true
        flush_ipv6_dns
        add_ipv6_static_dns
        test_internet full
    fi
}

flush_ipv4_config() {
    ip -4 addr flush scope global dev "$ethx"
    ip -4 route flush dev "$ethx"
    # DNS 是全局配置，交给 configure_dns 验证，避免清掉其他网卡的有效 DNS。
}

should_disable_dhcpv4=false
should_disable_accept_ra=false
should_disable_autoconf=false
should_add_ipv4_static_dns=false
should_add_ipv6_static_dns=false

flush_ipv6_config() {
    if $should_disable_accept_ra; then
        echo 0 >"/proc/sys/net/ipv6/conf/$ethx/accept_ra"
    fi
    if $should_disable_autoconf; then
        echo 0 >"/proc/sys/net/ipv6/conf/$ethx/autoconf"
    fi
    ip -6 addr flush scope global dev "$ethx"
    ip -6 route flush dev "$ethx"
    # DNS 是全局配置，交给 configure_dns 验证。
}

for i in $(seq 20); do
    if ethx=$(get_ethx); then
        break
    fi
    sleep 1
done

if [ -z "$ethx" ]; then
    echo "Not found network card: $mac_addr"
    exit
fi

echo "Configuring $ethx ($mac_addr)..."

# 不开启 lo 则 frp 无法连接 127.0.0.1 22
ip link set dev lo up

# 开启 ethx
ip link set dev "$ethx" up
sleep 1

# 开启 dhcpv4/v6
# debian / kali
if [ -f /usr/share/debconf/confmodule ]; then
    # shellcheck source=/dev/null
    . /usr/share/debconf/confmodule

    db_progress STEP 1

    # dhcpv4
    # 无需等待写入 dns，在 dhcpv6 等待
    db_progress INFO netcfg/dhcp_progress
    udhcpc -i "$ethx" -f -q -n || true
    db_progress STEP 1

    # slaac + dhcpv6
    db_progress INFO netcfg/slaac_wait_title
    # https://salsa.debian.org/installer-team/netcfg/-/blob/master/autoconfig.c#L148
    cat <<EOF >/var/lib/netcfg/dhcp6c.conf
interface $ethx {
    send ia-na 0;
    request domain-name-servers;
    request domain-name;
    script "/lib/netcfg/print-dhcp6c-info";
};

id-assoc na 0 {
};
EOF
    dhcp6c -c /var/lib/netcfg/dhcp6c.conf "$ethx" || true
    sleep $DHCP_TIMEOUT # 等待获取 ip 和写入 dns
    # kill-all-dhcp
    kill -9 "$(cat /var/run/dhcp6c.pid)" || true
    db_progress STEP 1

    # 静态 + 检测网络提示
    db_subst netcfg/link_detect_progress interface "$ethx"
    db_progress INFO netcfg/link_detect_progress
else
    # 兜底分支使用 udhcpc/udhcpc6；避免额外后台守护进程改写租约
    method=udhcpc

    case "$method" in
    udhcpc)
        udhcpc -i "$ethx" -f -q -n || true
        udhcpc6 -i "$ethx" -f -q -n || true
        sleep $DNS_FILE_TIMEOUT # 好像不用等待写入 dns，但是以防万一
        ;;
    dhcpcd)
        # https://gitlab.alpinelinux.org/alpine/aports/-/blob/master/main/dhcpcd/dhcpcd.pre-install
        grep -q dhcpcd /etc/group || addgroup -S dhcpcd
        grep -q dhcpcd /etc/passwd || adduser -S -D -H \
            -h /var/lib/dhcpcd \
            -s /sbin/nologin \
            -G dhcpcd \
            -g dhcpcd \
            dhcpcd

        # --noipv4ll 禁止生成 169.254.x.x
        # 等待 DNS
        dhcpcd --persistent --noipv4ll "$ethx" # 获取到 IP 后立即切换到后台
        sleep $DNS_FILE_TIMEOUT                # 需要等待写入 dns
        dhcpcd -x "$ethx"                      # 终止
        # autoconf 和 accept_ra 会被 dhcpcd 自动关闭，因此需要重新打开
        # 如果没重新打开，重新运行 dhcpcd 命令依然可以正常生成 slaac 地址和路由
        sysctl -w "net.ipv6.conf.$ethx.autoconf=1"
        sysctl -w "net.ipv6.conf.$ethx.accept_ra=1"
        ;;
    esac
fi

# 等待slaac
# 有ipv6地址就跳过，不管是slaac或者dhcpv6
# 因为会在trans里判断
# 这里等待5秒就够了，因为之前尝试获取dhcp6也用了一段时间
for i in $(seq 5 -1 0); do
    if is_have_ipv6; then
        break
    fi
    echo "waiting slaac for ${i}s"
    sleep 1
done

# 记录是否有动态地址
# 由于还没设置静态ip，所以有条目表示有动态地址
if is_have_ipv4_addr; then
    dhcpv4=true
else
    dhcpv4=false
fi
if is_have_ipv6_addr; then
    dhcpv6_or_slaac=true
else
    dhcpv6_or_slaac=false
fi
if is_have_ipv6_gateway; then
    ra_has_gateway=true
else
    ra_has_gateway=false
fi

# 如果自动获取的地址与重装前不同，则切回静态配置
# 这里只比较地址本身；掩码和网关差异留到后续连通性检测再处理
if $dhcpv4 && [ -n "$ipv4_addr" ] && [ -n "$ipv4_gateway" ] &&
    ! [ "$(echo "$ipv4_addr" | cut -d/ -f1)" = "$(get_first_ipv4_addr | cut -d/ -f1)" ]; then
    echo "IPv4 address obtained from DHCP is different from old system."
    should_disable_dhcpv4=true
    flush_ipv4_config
fi
if $dhcpv6_or_slaac && [ -n "$ipv6_addr" ] && [ -n "$ipv6_gateway" ] &&
    ! [ "$(echo "$ipv6_addr" | cut -d/ -f1)" = "$(get_first_ipv6_addr | cut -d/ -f1)" ]; then
    echo "IPv6 address obtained from SLAAC/DHCPv6 is different from old system."
    should_disable_accept_ra=true
    should_disable_autoconf=true
    flush_ipv6_config
fi

# 设置静态地址，必要时补齐 DHCP 未正确下发的网关
add_missing_ipv4_config
add_missing_ipv6_config

# 检查 ipv4/ipv6 是否连接联网
ipv4_has_internet=false
ipv6_has_internet=false
ipv4_has_internet_with_dns=false
ipv6_has_internet_with_dns=false
test_internet

# 如果无法上网，并且自动获取的 掩码/网关 不是重装前的，则改成静态
# ip_addr 包括 IP/掩码，所以可以用来判断掩码是否不同
# IP 不同的情况在前面已经改成静态了
if ! $ipv4_has_internet &&
    $dhcpv4 && [ -n "$ipv4_addr" ] && [ -n "$ipv4_gateway" ] &&
    ! { [ "$ipv4_addr" = "$(get_first_ipv4_addr)" ] && [ "$ipv4_gateway" = "$(get_first_ipv4_gateway)" ]; }; then
    echo "IPv4 netmask/gateway obtained from DHCP is different from old system."
    should_disable_dhcpv4=true
    flush_ipv4_config
    add_missing_ipv4_config
    test_internet
fi
# 有可能是静态 IPv6 但能从 RA 获取到网关，因此加上 || $ra_has_gateway
if ! $ipv6_has_internet &&
    { $dhcpv6_or_slaac || $ra_has_gateway; } &&
    [ -n "$ipv6_addr" ] && [ -n "$ipv6_gateway" ] &&
    ! { [ "$ipv6_addr" = "$(get_first_ipv6_addr)" ] && [ "$ipv6_gateway" = "$(get_first_ipv6_gateway)" ]; }; then
    echo "IPv6 netmask/gateway obtained from SLAAC/DHCPv6 is different from old system."
    should_disable_accept_ra=true
    should_disable_autoconf=true
    flush_ipv6_config
    add_missing_ipv6_config
    test_internet
fi

# 删除不通协议的地址，避免后续下载优先走到坏路径
# 即使 IPv4/IPv6 分别落在不同网卡，也要分别按协议裁剪
if ! $ipv4_has_internet; then
    if $dhcpv4; then
        should_disable_dhcpv4=true
    fi
    flush_ipv4_config
fi
if ! $ipv6_has_internet; then
    # 防止删除 IPv6 后再次通过 SLAAC 获得
    # 不用判断 || $ra_has_gateway ，因为没有 IPv6 地址但有 IPv6 网关时，不会出现下载问题
    if $dhcpv6_or_slaac; then
        should_disable_accept_ra=true
        should_disable_autoconf=true
    fi
    flush_ipv6_config
fi

configure_dns

# 传参给 trans.start
netconf="/dev/netconf/$ethx"
mkdir -p "$netconf"
if $ipv4_has_internet; then
    sed -n 's/^nameserver[[:space:]]\+\([^[:space:]]*\).*/\1/p' /etc/resolv.conf | grep -F . >"$netconf/ipv4_dns" || true
else
    : >"$netconf/ipv4_dns"
fi
if $ipv6_has_internet; then
    sed -n 's/^nameserver[[:space:]]\+\([^[:space:]]*\).*/\1/p' /etc/resolv.conf | grep -F : >"$netconf/ipv6_dns" || true
else
    : >"$netconf/ipv6_dns"
fi
if $should_add_ipv4_static_dns; then echo 1; else echo 0; fi >"$netconf/should_add_ipv4_static_dns"
if $should_add_ipv6_static_dns; then echo 1; else echo 0; fi >"$netconf/should_add_ipv6_static_dns"
if $dhcpv4; then
    echo 1 >"$netconf/dhcpv4"
else
    echo 0 >"$netconf/dhcpv4"
fi
if $dhcpv6_or_slaac; then
    echo 1 >"$netconf/dhcpv6_or_slaac"
else
    echo 0 >"$netconf/dhcpv6_or_slaac"
fi
if $should_disable_dhcpv4; then
    echo 1 >"$netconf/should_disable_dhcpv4"
else
    echo 0 >"$netconf/should_disable_dhcpv4"
fi
if $should_disable_accept_ra; then
    echo 1 >"$netconf/should_disable_accept_ra"
else
    echo 0 >"$netconf/should_disable_accept_ra"
fi
if $should_disable_autoconf; then
    echo 1 >"$netconf/should_disable_autoconf"
else
    echo 0 >"$netconf/should_disable_autoconf"
fi
if $is_in_china; then
    echo 1 >"$netconf/is_in_china"
else
    echo 0 >"$netconf/is_in_china"
fi
echo "$ethx" >"$netconf/ethx"
echo "$mac_addr" >"$netconf/mac_addr"
echo "$ipv4_addr" >"$netconf/ipv4_addr"
echo "$ipv4_gateway" >"$netconf/ipv4_gateway"
echo "$ipv6_addr" >"$netconf/ipv6_addr"
echo "$ipv6_gateway" >"$netconf/ipv6_gateway"
echo "$ipv6_extra_addrs" >"$netconf/ipv6_extra_addrs"
if $ipv4_has_internet; then
    echo 1 >"$netconf/ipv4_has_internet"
else
    echo 0 >"$netconf/ipv4_has_internet"
fi
if $ipv6_has_internet; then
    echo 1 >"$netconf/ipv6_has_internet"
else
    echo 0 >"$netconf/ipv6_has_internet"
fi
