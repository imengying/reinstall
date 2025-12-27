#!/usr/bin/env bash
# nixos 默认的配置不会生成 /bin/bash
# shellcheck disable=SC2086

set -eE
confhome=https://raw.githubusercontent.com/imengying/reinstall/main

# 用于判断 reinstall.sh 和 trans.sh 是否兼容
SCRIPT_VERSION=4BACD833-A585-23BA-6CBB-9AA4E08E0003

# 强制 linux 程序输出英文，防止 grep 不到想要的内容
# https://www.gnu.org/software/gettext/manual/html_node/The-LANGUAGE-variable.html
export LC_ALL=C

# 处理部分用户用 su 切换成 root 导致环境变量没 sbin 目录
# 也能处理 cygwin bash 没有添加 -l 运行 reinstall.sh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

# 如果不是 bash 的话，继续执行会有语法错误，因此在这里判断是否 bash
if [ -z "$BASH" ]; then
    if [ -f /etc/alpine-release ]; then
        if ! apk add bash; then
            echo "Error while install bash." >&2
            exit 1
        fi
    fi
    if command -v bash >/dev/null; then
        exec bash "$0" "$@"
    else
        echo "Please run this script with bash." >&2
        exit 1
    fi
fi

# 记录日志，过滤含有 password 的行
exec > >(tee >(grep -iv password >>/reinstall.log)) 2>&1
THIS_SCRIPT=$(readlink -f "$0")
trap 'trap_err $LINENO $?' ERR

trap_err() {
    line_no=$1
    ret_no=$2

    error "Line $line_no return $ret_no"
    sed -n "$line_no"p "$THIS_SCRIPT"
}

usage_and_exit() {
    cat <<EOF
Usage: ./reinstall.sh debian [9|10|11|12|13]

       Options:        [--password  PASSWORD]
                       [--ssh-key   KEY]
                       [--ssh-port  PORT]
                       [--web-port  PORT]
                       [--frpc-toml PATH]

EOF
    exit 1
}

info() {
    local msg
    if [ "$1" = false ]; then
        shift
        msg=$*
    else
        msg="***** $(to_upper <<<"$*") *****"
    fi
    echo_color_text '\e[32m' "$msg" >&2
}

warn() {
    local msg
    if [ "$1" = false ]; then
        shift
        msg=$*
    else
        msg="Warning: $*"
    fi
    echo_color_text '\e[33m' "$msg" >&2
}

error() {
    echo_color_text '\e[31m' "***** ERROR *****" >&2
    echo_color_text '\e[31m' "$*" >&2
}

echo_color_text() {
    color="$1"
    shift
    plain="\e[0m"
    echo -e "$color$*$plain"
}

error_and_exit() {
    error "$@"
    exit 1
}

curl() {
    is_have_cmd curl || install_pkg curl

    # 添加 -f, --fail，不然 404 退出码也为0
    # 32位 cygwin 已停止更新，证书可能有问题，先添加 --insecure
    # centos 7 curl 不支持 --retry-connrefused --retry-all-errors
    # 因此手动 retry
    grep -o 'http[^ ]*' <<<"$@" >&2
    for i in $(seq 5); do
        if command curl --insecure --connect-timeout 10 -f "$@"; then
            return
        else
            ret=$?
            # 403 404 错误，或者达到重试次数
            if [ $ret -eq 22 ] || [ $i -eq 5 ]; then
                return $ret
            fi
            sleep 1
        fi
    done
}

mask2cidr() {
    local x=${1##*255.}
    set -- 0^^^128^192^224^240^248^252^254^ $(((${#1} - ${#x}) * 2)) ${x%%.*}
    x=${1%%"$3"*}
    echo $(($2 + (${#x} / 4)))
}

is_in_china() {
    [ "$force_cn" = 1 ] && return 0

    if [ -z "$_loc" ]; then
        # www.cloudflare.com/dash.cloudflare.com 国内访问的是美国服务器，而且部分地区被墙
        # 没有ipv6 www.visa.cn
        # 没有ipv6 www.bose.cn
        # 没有ipv6 www.garmin.com.cn
        # 备用 www.prologis.cn
        # 备用 www.autodesk.com.cn
        # 备用 www.keysight.com.cn
        if ! _loc=$(curl -L http://www.qualcomm.cn/cdn-cgi/trace | grep '^loc=' | cut -d= -f2 | grep .); then
            error_and_exit "Can not get location."
        fi
        echo "Location: $_loc" >&2
    fi
    [ "$_loc" = CN ]
}
is_in_alpine() {
    [ -f /etc/alpine-release ]
}

is_use_cloud_image() {
    [ -n "$cloud_image" ] && [ "$cloud_image" = 1 ]
}

is_boot_in_separate_partition() {
    mount | grep -q ' on /boot type '
}

is_os_in_btrfs() {
    mount | grep -q ' on / type btrfs '
}

is_os_in_subvol() {
    subvol=$(awk '($2=="/") { print $i }' /proc/mounts | grep -o 'subvol=[^ ]*' | cut -d= -f2)
    [ "$subvol" != / ]
}

get_os_part() {
    awk '($2=="/") { print $1 }' /proc/mounts
}

umount_all() {
    if mount_lists=$(mount | grep -w "on $1" | awk '{print $3}' | grep .); then
        # alpine 没有 -R
        if umount --help 2>&1 | grep -wq -- '-R'; then
            umount -R "$1"
        else
            echo "$mount_lists" | tac | xargs -n1 umount
        fi
    fi
}

cp_to_btrfs_root() {
    mount_dir=$tmp/reinstall-btrfs-root
    if ! grep -q $mount_dir /proc/mounts; then
        mkdir -p $mount_dir
        mount "$(get_os_part)" $mount_dir -t btrfs -o subvol=/
    fi
    cp -rf "$@" "$mount_dir"
}

is_host_has_ipv4_and_ipv6() {
    host=$1

    install_pkg dig
    # dig会显示cname结果，cname结果以.结尾，grep -v '\.$' 用于去除 cname 结果
    res=$(dig +short $host A $host AAAA | grep -v '\.$')
    # 有.表示有ipv4地址，有:表示有ipv6地址
    grep -q \. <<<$res && grep -q : <<<$res
}

is_use_firmware() {
    # shellcheck disable=SC2154
    [ "$nextos_distro" = debian ] && ! is_virt
}

is_digit() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

is_port_valid() {
    is_digit "$1" && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

get_host_by_url() {
    cut -d/ -f3 <<<$1
}

get_function() {
    declare -f "$1"
}

get_function_content() {
    declare -f "$1" | sed '1d;2d;$d'
}

insert_into_file() {
    file=$1
    location=$2
    regex_to_find=$3

    line_num=$(grep -E -n "$regex_to_find" "$file" | cut -d: -f1)

    found_count=$(echo "$line_num" | wc -l)
    if [ ! "$found_count" -eq 1 ]; then
        return 1
    fi

    case "$location" in
    before) line_num=$((line_num - 1)) ;;
    after) ;;
    *) return 1 ;;
    esac

    sed -i "${line_num}r /dev/stdin" "$file"
}

test_url() {
    test_url_real false "$@"
}

test_url_grace() {
    test_url_real true "$@"
}

test_url_real() {
    grace=$1
    url=$2
    expect_types=$3
    var_to_eval=$4
    info test url

    failed() {
        $grace && return 1
        error_and_exit "$@"
    }

    tmp_file=$tmp/img-test

    # TODO: 好像无法识别 nixos 官方源的跳转
    # 有的服务器不支持 range，curl会下载整个文件
    # 所以用 head 限制 1M
    # 过滤 curl 23 错误（head 限制了大小）
    # 也可用 ulimit -f 但好像 cygwin 不支持
    # ${PIPESTATUS[n]} 表示第n个管道的返回值
    echo $url
    for i in $(seq 5 -1 0); do
        if command curl --insecure --connect-timeout 10 -Lfr 0-1048575 "$url" \
            1> >(exec head -c 1048576 >$tmp_file) \
            2> >(exec grep -v 'curl: (23)' >&2); then
            break
        else
            ret=$?
            msg="$url not accessible"
            case $ret in
            22)
                # 403 404
                # 这里的 failed 虽然返回 1，但是不会中断脚本，因此要手动 return
                failed "$msg"
                return "$ret"
                ;;
            23)
                # 限制了空间
                break
                ;;
            *)
                # 其他错误
                if [ $i -eq 0 ]; then
                    failed "$msg"
                    return "$ret"
                fi
                ;;
            esac
            sleep 1
        fi
    done

    # 如果要检查文件类型
    if [ -n "$expect_types" ]; then
        install_pkg file
        real_type=$(file_enhanced $tmp_file)
        echo "File type: $real_type"

        # debian 9 ubuntu 16.04-20.04 可能会将 iso 识别成 raw
        for type in $expect_types $([ "$expect_types" = iso ] && echo raw); do
            if [[ ."$real_type" = *."$type" ]]; then
                # 如果要设置变量
                if [ -n "$var_to_eval" ]; then
                    IFS=. read -r "${var_to_eval?}" "${var_to_eval}_warp" <<<"$real_type"
                fi
                return
            fi
        done

        failed "$url
Expected type: $expect_types
Actually type: $real_type"
    fi
}

fix_file_type() {
    # gzip的mime有很多种写法
    # centos7中显示为 x-gzip，在其他系统中显示为 gzip，可能还有其他
    # 所以不用mime判断
    # https://www.digipres.org/formats/sources/tika/formats/#application/gzip

    # centos 7 上的 file 显示 qcow2 的 mime 为 application/octet-stream
    # file debian-12-genericcloud-amd64.qcow2
    # debian-12-genericcloud-amd64.qcow2: QEMU QCOW Image (v3), 2147483648 bytes
    # file --mime debian-12-genericcloud-amd64.qcow2
    # debian-12-genericcloud-amd64.qcow2: application/octet-stream; charset=binary

    # --extension 不靠谱
    # file -b /reinstall-tmp/img-test --mime-type
    # application/x-qemu-disk
    # file -b /reinstall-tmp/img-test --extension
    # ???

    # 1. 删除,;#
    # DOS/MBR boot sector; partition 1: ...
    # gzip compressed data, was ...
    # # ISO 9660 CD-ROM filesystem data... (有些 file 版本开头输出有井号)

    # 2. 删除开头的空格

    # 3. 删除无意义的单词 POSIX, Unicode, UTF-8, ASCII
    # POSIX tar archive (GNU)
    # Unicode text, UTF-8 text
    # UTF-8 Unicode text, with very long lines
    # ASCII text

    # 4. 下面两种都是 raw
    # DOS/MBR boot sector
    # x86 boot sector; partition 1: ...
    sed -E \
        -e 's/[,;#]//g' \
        -e 's/^[[:space:]]*//' \
        -e 's/(POSIX|Unicode|UTF-8|ASCII)//gi' \
        -e 's/DOS\/MBR boot sector/raw/i' \
        -e 's/x86 boot sector/raw/i' \
        -e 's/Zstandard/zstd/i' \
        -e 's/Windows imaging \(WIM\) image/wim/i' |
        awk '{print $1}' | to_lower
}

# 不用 file -z，因为
# 1. file -z 只能看透一层
# 2. alpine file -z 无法看透部分镜像（前1M），例如：
# guajibao-win10-ent-ltsc-2021-x64-cn-efi.vhd.gz
# guajibao-win7-sp1-ent-x64-cn-efi.vhd.gz
# win7-ent-sp1-x64-cn-efi.vhd.gz
# 还要注意 centos 7 没有 -Z 只有 -z
file_enhanced() {
    file=$1

    full_type=
    while true; do
        type="$(file -b $file | fix_file_type)"
        full_type="$type.$full_type"
        case "$type" in
        xz | gzip | zstd)
            install_pkg "$type"
            $type -dc <"$file" | head -c 1048576 >"$file.inside"
            mv -f "$file.inside" "$file"
            ;;
        tar)
            install_pkg "$type"
            # 隐藏 gzip: unexpected end of file 提醒
            tar xf "$file" -O 2>/dev/null | head -c 1048576 >"$file.inside"
            mv -f "$file.inside" "$file"
            ;;
        *)
            break
            ;;
        esac
    done
    # shellcheck disable=SC2001
    echo "$full_type" | sed 's/\.$//'
}

add_community_repo_for_alpine() {
    local alpine_ver

    # 先检查原来的repo是不是egde
    if grep -q '^http.*/edge/main$' /etc/apk/repositories; then
        alpine_ver=edge
    else
        alpine_ver=v$(cut -d. -f1,2 </etc/alpine-release)
    fi

    if ! grep -q "^http.*/$alpine_ver/community$" /etc/apk/repositories; then
        mirror=$(grep '^http.*/main$' /etc/apk/repositories | sed 's,/[^/]*/main$,,' | head -1)
        echo $mirror/$alpine_ver/community >>/etc/apk/repositories
    fi
}

assert_not_in_container() {
    _error_and_exit() {
        error_and_exit "Not Supported OS in Container.\nPlease use https://github.com/LloydAsp/OsMutation"
    }

    if is_have_cmd systemd-detect-virt; then
        if systemd-detect-virt -qc; then
            _error_and_exit
        fi
    else
        if [ -d /proc/vz ] || grep -q container=lxc /proc/1/environ; then
            _error_and_exit
        fi
    fi
}

# 使用 | del_br ，但返回 del_br 之前返回值
run_with_del_cr() {
    "$@" | del_cr
    return ${PIPESTATUS[0]}
}

run_with_del_cr_template() {
    if get_function _$exe >/dev/null; then
        run_with_del_cr _$exe "$@"
    else
        run_with_del_cr command $exe "$@"
    fi
}

wmic() {
    if is_have_cmd wmic; then
        # 如果参数没有 GET，添加 GET，防止以下报错
        # wmic memorychip /format:list
        # 此级别的开关异常。
        has_get=false
        for i in "$@"; do
            # 如果参数有 GET
            if [ "$(to_upper <<<"$i")" = GET ]; then
                has_get=true
                break
            fi
        done

        # 输出为 /format:list 格式
        if $has_get; then
            command wmic "$@" /format:list
        else
            command wmic "$@" get /format:list
        fi
        return
    fi

    # powershell wmi 默认参数
    local namespace='root\cimv2'
    local class=
    local filter=
    local props=

    # namespace
    if [[ "$(to_upper <<<"$1")" = /NAMESPACE* ]]; then
        # 删除引号，删除 \\
        namespace=$(cut -d: -f2 <<<"$1" | sed -e "s/[\"']//g" -e 's/\\\\//g')
        shift
    fi

    # class
    if [[ "$(to_upper <<<"$1")" = PATH ]]; then
        class=$2
        shift 2
    else
        case "$(to_lower <<<"$1")" in
        nicconfig) class=Win32_NetworkAdapterConfiguration ;;
        memorychip) class=Win32_PhysicalMemory ;;
        *) class=Win32_$1 ;;
        esac
        shift
    fi

    # filter
    if [[ "$(to_upper <<<"$1")" = WHERE ]]; then
        filter=$2
        shift 2
    fi

    # props
    if [[ "$(to_upper <<<"$1")" = GET ]]; then
        props=$2
        shift 2
    fi

    if ! [ -f "$tmp/wmic.ps1" ]; then
        curl -Lo "$tmp/wmic.ps1" "$confhome/wmic.ps1"
    fi

    # shellcheck disable=SC2046
    powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
        -File "$(cygpath -w "$tmp/wmic.ps1")" \
        -Namespace "$namespace" \
        -Class "$class" \
        $([ -n "$filter" ] && echo -Filter "$filter") \
        $([ -n "$props" ] && echo -Properties "$props")
}

is_virt() {
    if [ -z "$_is_virt" ]; then
        # aws t4g debian 11
        # systemd-detect-virt: 为 none，即使装了dmidecode
        # virt-what: 未装 deidecode时结果为空，装了deidecode后结果为aws
        # 所以综合两个命令的结果来判断
        if is_have_cmd systemd-detect-virt && systemd-detect-virt -v; then
            _is_virt=true
        fi

        if [ -z "$_is_virt" ]; then
            # debian 安装 virt-what 不会自动安装 dmidecode，因此结果有误
            install_pkg dmidecode virt-what
            # virt-what 返回值始终是0，所以用是否有输出作为判断
            if [ -n "$(virt-what)" ]; then
                _is_virt=true
            fi
        fi

        if [ -z "$_is_virt" ]; then
            _is_virt=false
        fi
        echo "VM: $_is_virt"
    fi
    $_is_virt
}

is_absolute_path() {
    # 检查路径是否以/开头
    # 注意语法和 ash 不同
    [[ "$1" = /* ]]
}

is_cpu_supports_x86_64_v3() {
    # 用 ld.so/cpuid/coreinfo.exe 更准确
    # centos 7 /usr/lib64/ld-linux-x86-64.so.2 没有 --help
    # alpine gcompat /lib/ld-linux-x86-64.so.2 没有 --help

    # https://en.wikipedia.org/wiki/X86-64#Microarchitecture_levels
    # https://learn.microsoft.com/sysinternals/downloads/coreinfo

    # abm = popcnt + lzcnt
    # /proc/cpuinfo 不显示 lzcnt, 可用 abm 代替，但 cygwin 也不显示 abm
    # /proc/cpuinfo 不显示 osxsave, 故用 xsave 代替

    need_flags="avx avx2 bmi1 bmi2 f16c fma movbe xsave"
    had_flags=$(grep -m 1 ^flags /proc/cpuinfo | awk -F': ' '{print $2}')

    for flag in $need_flags; do
        if ! grep -qw $flag <<<"$had_flags"; then
            return 1
        fi
    done
}

assert_cpu_supports_x86_64_v3() {
    if ! is_cpu_supports_x86_64_v3; then
        error_and_exit "Could not install $distro $releasever because the CPU does not support x86-64-v3."
    fi
}

# sr-latn-rs 到 sr-latn
en_us() {
    echo "$lang" | awk -F- '{print $1"-"$2}'

    # zh-hk 可回落到 zh-tw
    if [ "$lang" = zh-hk ]; then
        echo zh-tw
    fi
}

# fr-ca 到 ca
us() {
    # 葡萄牙准确对应 pp
    if [ "$lang" = pt-pt ]; then
        echo pp
        return
    fi
    # 巴西准确对应 pt
    if [ "$lang" = pt-br ]; then
        echo pt
        return
    fi

    echo "$lang" | awk -F- '{print $2}'

    # hk 额外回落到 tw
    if [ "$lang" = zh-hk ]; then
        echo tw
    fi
}

# fr-ca 到 fr-fr
en_en() {
    echo "$lang" | awk -F- '{print $1"-"$1}'

    # en-gb 额外回落到 en-us
    if [ "$lang" = en-gb ]; then
        echo en-us
    fi
}

# fr-ca 到 fr
en() {
    # 巴西/葡萄牙回落到葡萄牙语
    if [ "$lang" = pt-br ] || [ "$lang" = pt-pt ]; then
        echo "pp"
        return
    fi

    echo "$lang" | awk -F- '{print $1}'
}

english() {
    case "$lang" in
    ar-sa) echo Arabic ;;
    bg-bg) echo Bulgarian ;;
    cs-cz) echo Czech ;;
    da-dk) echo Danish ;;
    de-de) echo German ;;
    el-gr) echo Greek ;;
    en-gb) echo Eng_Intl ;;
    en-us) echo English ;;
    es-es) echo Spanish ;;
    es-mx) echo Spanish_Latam ;;
    et-ee) echo Estonian ;;
    fi-fi) echo Finnish ;;
    fr-ca) echo FrenchCanadian ;;
    fr-fr) echo French ;;
    he-il) echo Hebrew ;;
    hr-hr) echo Croatian ;;
    hu-hu) echo Hungarian ;;
    it-it) echo Italian ;;
    ja-jp) echo Japanese ;;
    ko-kr) echo Korean ;;
    lt-lt) echo Lithuanian ;;
    lv-lv) echo Latvian ;;
    nb-no) echo Norwegian ;;
    nl-nl) echo Dutch ;;
    pl-pl) echo Polish ;;
    pt-pt) echo Portuguese ;;
    pt-br) echo Brazilian ;;
    ro-ro) echo Romanian ;;
    ru-ru) echo Russian ;;
    sk-sk) echo Slovak ;;
    sl-si) echo Slovenian ;;
    sr-latn | sr-latn-rs) echo Serbian_Latin ;;
    sv-se) echo Swedish ;;
    th-th) echo Thai ;;
    tr-tr) echo Turkish ;;
    uk-ua) echo Ukrainian ;;
    zh-cn) echo ChnSimp ;;
    zh-hk | zh-tw) echo ChnTrad ;;
    esac
}


setos() {
    local step=$1
    local distro=$2
    local releasever=$3
    info set $step $distro $releasever

    setos_debian() {
        is_debian_elts() {
            [ "$releasever" -le 10 ]
        }

        # 用此标记要是否 elts, 用于安装后修改 elts/etls-cn 源
        # shellcheck disable=SC2034
        is_debian_elts && elts=1 || elts=0

        case "$releasever" in
        9) codename=stretch ;;
        10) codename=buster ;;
        11) codename=bullseye ;;
        12) codename=bookworm ;;
        13) codename=trixie ;;
        14) codename=forky ;;
        15) codename=duke ;;
        esac

        if ! is_use_cloud_image && is_debian_elts && is_in_china; then
            warn "
Due to the lack of Debian Freexian ELTS instaler mirrors in China, the installation time may be longer.
Continue?

由于没有 Debian Freexian ELTS 国内安装源，安装时间可能会比较长。
继续安装?
"
            read -r -p '[y/N]: '
            if ! [[ "$REPLY" = [Yy] ]]; then
                exit
            fi
        fi

        # udeb_mirror 安装时的源
        # deb_mirror 安装后要修改成的源
        if is_debian_elts; then
            if is_in_china; then
                # https://github.com/tuna/issues/issues/1999
                # nju 也没同步
                udeb_mirror=deb.freexian.com/extended-lts
                deb_mirror=mirror.nju.edu.cn/debian-elts
                initrd_mirror=mirror.nju.edu.cn/debian-archive/debian
            else
                # 按道理不应该用官方源，但找不到其他源
                udeb_mirror=deb.freexian.com/extended-lts
                deb_mirror=deb.freexian.com/extended-lts
                initrd_mirror=archive.debian.org/debian
            fi
        else
            if is_in_china; then
                # ftp.cn.debian.org 不在国内还严重丢包
                # https://www.itdog.cn/ping/ftp.cn.debian.org
                mirror=mirror.nju.edu.cn/debian
            else
                mirror=deb.debian.org/debian # fastly
            fi
            udeb_mirror=$mirror
            deb_mirror=$mirror
            initrd_mirror=$mirror
        fi

        # 云镜像和 firmware 下载源
        if is_in_china; then
            cdimage_mirror=https://mirror.nju.edu.cn/debian-cdimage
        else
            cdimage_mirror=https://cdimage.debian.org/images # 在瑞典，不是 cdn
            # cloud.debian.org 同样在瑞典，不是 cdn
        fi

        is_virt && flavour=-cloud || flavour=
        # debian 10 云内核 vultr efi vnc 没有显示
        [ "$releasever" -le 10 ] && flavour=
        # 甲骨文 arm64 cloud 内核 vnc 没有显示
        [ "$basearch_alt" = arm64 ] && flavour=

        if is_use_cloud_image; then
            # cloud image
            # https://salsa.debian.org/cloud-team/debian-cloud-images/-/tree/master/config_space/bookworm/files/etc/default/grub.d
            # cloud 包括各种奇怪的优化，例如不显示 grub 菜单
            # 因此使用 nocloud
            ci_type=nocloud
            eval ${step}_img=$cdimage_mirror/cloud/$codename/latest/debian-$releasever-$ci_type-$basearch_alt.qcow2
        else
            # 传统安装
            initrd_dir=dists/$codename/main/installer-$basearch_alt/current/images/netboot/debian-installer/$basearch_alt

            eval ${step}_udeb_mirror=$udeb_mirror
            eval ${step}_vmlinuz=https://$initrd_mirror/$initrd_dir/linux
            eval ${step}_initrd=https://$initrd_mirror/$initrd_dir/initrd.gz
            eval ${step}_ks=$confhome/debian.cfg
            eval ${step}_firmware=$cdimage_mirror/unofficial/non-free/firmware/$codename/current/firmware.cpio.gz
            eval ${step}_codename=$codename
        fi

        # 官方安装和云镜像都会用到的
        eval ${step}_deb_mirror=$deb_mirror
        eval ${step}_kernel=linux-image$flavour-$basearch_alt
    }

    eval ${step}_distro=$distro
    eval ${step}_releasever=$releasever

    case "$distro" in
    *) setos_$distro ;;
    esac

    # debian <=256M 必须使用云内核，否则不够内存
    if is_distro_like_debian && [ "$ram_size" -le 256 ]; then
        exit_if_cant_use_cloud_kernel
    fi

    # 集中测试云镜像格式
    if is_use_cloud_image && [ "$step" = finalos ]; then
        # shellcheck disable=SC2154
        test_url $finalos_img 'qemu qemu.gzip qemu.xz qemu.zstd raw.xz' finalos_img_type
    fi
}

is_distro_like_debian() {
    return 0
}

get_latest_distro_releasever() {
    get_function_content verify_os_name |
        grep -wo "$1 [^'\"]*" | awk -F'|' '{print $NF}'
}

# 检查是否为正确的系统名
verify_os_name() {
    if [ -z "$*" ]; then
        usage_and_exit
    fi

    for os in 'debian 9|10|11|12|13'; do
        read -r ds vers <<<"$os"
        vers_=${vers//\./\\\.}
        finalos=$(echo "$@" | to_lower | sed -n -E "s,^($ds)[ :-]?(|$vers_)$,\1 \2,p")
        if [ -n "$finalos" ]; then
            read -r distro releasever <<<"$finalos"
            # 默认版本号
            if [ -z "$releasever" ] && [ -n "$vers" ]; then
                releasever=$(awk -F '|' '{print $NF}' <<<"|$vers")
            fi
            return
        fi
    done

    error "Please specify debian [version]"
    usage_and_exit
}

verify_os_args() {
    # Debian 没有特殊参数要求
    return 0
}

get_cmd_path() {
    # arch 云镜像不带 which
    # command -v 包括脚本里面的方法
    # ash 无效
    type -f -p $1
}

is_have_cmd() {
    get_cmd_path $1 >/dev/null 2>&1
}

install_pkg() {
    find_pkg_mgr() {
        [ -n "$pkg_mgr" ] && return

        # 查找方法1: 通过 ID / ID_LIKE
        # 因为可能装了多种包管理器
        if [ -f /etc/os-release ]; then
            # shellcheck source=/dev/null
            . /etc/os-release
            for id in $ID $ID_LIKE; do
                # https://github.com/chef/os_release
                case "$id" in
                rhel | almalinux) is_have_cmd dnf && pkg_mgr=dnf || pkg_mgr=yum ;;
                debian) pkg_mgr=apt-get ;;
                alpine) pkg_mgr=apk ;;
                esac
                [ -n "$pkg_mgr" ] && return
            done
        fi

        # 查找方法 2
        for mgr in dnf yum apt-get apk; do
            is_have_cmd $mgr && pkg_mgr=$mgr && return
        done

        return 1
    }

    cmd_to_pkg() {
        unset USE
        case $cmd in
        ar)
            case "$pkg_mgr" in
            *) pkg="binutils" ;;
            esac
            ;;
        xz)
            case "$pkg_mgr" in
            apt-get) pkg="xz-utils" ;;
            *) pkg="xz" ;;
            esac
            ;;
        lsblk | findmnt)
            case "$pkg_mgr" in
            apk) pkg="$cmd" ;;
            *) pkg="util-linux" ;;
            esac
            ;;
        lsmem)
            case "$pkg_mgr" in
            apk) pkg="util-linux-misc" ;;
            *) pkg="util-linux" ;;
            esac
            ;;
        fdisk)
            case "$pkg_mgr" in
            apt-get) pkg="fdisk" ;;
            apk) pkg="util-linux-misc" ;;
            *) pkg="util-linux" ;;
            esac
            ;;
        hexdump)
            case "$pkg_mgr" in
            apt-get) pkg="bsdmainutils" ;;
            *) pkg="util-linux" ;;
            esac
            ;;
        unsquashfs)
            case "$pkg_mgr" in
            zypper) pkg="squashfs" ;;
            emerge) pkg="squashfs-tools" && export USE="lzma" ;;
            *) pkg="squashfs-tools" ;;
            esac
            ;;
        nslookup | dig)
            case "$pkg_mgr" in
            apt-get) pkg="dnsutils" ;;
            pacman) pkg="bind" ;;
            apk | emerge) pkg="bind-tools" ;;
            yum | dnf | zypper) pkg="bind-utils" ;;
            esac
            ;;
        iconv)
            case "$pkg_mgr" in
            apk) pkg="musl-utils" ;;
            *) error_and_exit "Which GNU/Linux do not have iconv built-in?" ;;
            esac
            ;;
        *) pkg=$cmd ;;
        esac
    }

    # 系统                       package名称                                    repo名称
    # centos/alma/rocky/fedora   epel-release                                   epel
    # oracle linux               oracle-epel-release                            ol9_developer_EPEL
    # opencloudos                epol-release                                   EPOL
    # alibaba cloud linux 3      epel-release/epel-aliyuncs-release(qcow2自带)  epel
    # anolis 23                  anolis-epao-release                            EPAO

    # anolis 8
    # [root@localhost ~]# yum search *ep*-release | grep -v next
    # ========================== Name Matched: *ep*-release ==========================
    # anolis-epao-release.noarch : EPAO Packages for Anolis OS 8 repository configuration
    # epel-aliyuncs-release.noarch : Extra Packages for Enterprise Linux repository configuration
    # epel-release.noarch : Extra Packages for Enterprise Linux repository configuration (qcow2自带)

    check_is_need_epel() {
        is_need_epel() {
            case "$pkg" in
            dpkg) true ;;
            jq) is_have_cmd yum && ! is_have_cmd dnf ;; # el7/ol7 的 jq 在 epel 仓库
            *) false ;;
            esac
        }

        get_epel_repo_name() {
            # el7 不支持 yum repolist --all，要使用 yum repolist all
            # el7 yum repolist 第一栏有 /x86_64 后缀，因此要去掉。而 el9 没有
            $pkg_mgr repolist all | awk '{print $1}' | awk -F/ '{print $1}' | grep -Ei 'ep(el|ol|ao)$'
        }

        get_epel_pkg_name() {
            # el7 不支持 yum list --available，要使用 yum list available
            $pkg_mgr list available | grep -E '(.*-)?ep(el|ol|ao)-(.*-)?release' |
                awk '{print $1}' | cut -d. -f1 | grep -v next | head -1
        }

        if is_need_epel; then
            if ! epel=$(get_epel_repo_name); then
                $pkg_mgr install -y "$(get_epel_pkg_name)"
                epel=$(get_epel_repo_name)
            fi
            enable_epel="--enablerepo=$epel"
        else
            enable_epel=
        fi
    }

    install_pkg_real() {
        text="$pkg"
        if [ "$pkg" != "$cmd" ]; then
            text+=" ($cmd)"
        fi
        echo "Installing package '$text'..."

        case $pkg_mgr in
        dnf)
            check_is_need_epel
            dnf install $enable_epel -y --setopt=install_weak_deps=False $pkg
            ;;
        yum)
            check_is_need_epel
            yum install $enable_epel -y $pkg
            ;;
        emerge) emerge --oneshot $pkg ;;
        pacman) pacman -Syu --noconfirm --needed $pkg ;;
        zypper) zypper install -y $pkg ;;
        apk)
            add_community_repo_for_alpine
            apk add $pkg
            ;;
        apt-get)
            [ -z "$apt_updated" ] && apt-get update && apt_updated=1
            DEBIAN_FRONTEND=noninteractive apt-get install -y $pkg
            ;;
        nix-env)
            # 不指定 channel 会很慢，而且很占内存
            [ -z "$nix_updated" ] && nix-channel --update && nix_updated=1
            nix-env -iA nixos.$pkg
            ;;
        esac
    }

    is_need_reinstall() {
        cmd=$1

        # gentoo 默认编译的 unsquashfs 不支持 xz
        if [ "$cmd" = unsquashfs ] && is_have_cmd emerge && ! $cmd |& grep -wq xz; then
            echo "unsquashfs not supported xz. rebuilding."
            return 0
        fi

        # busybox fdisk 无法显示 mbr 分区表的 id
        if [ "$cmd" = fdisk ] && is_have_cmd apk && $cmd |& grep -wq BusyBox; then
            return 0
        fi

        # busybox grep 不支持 -oP
        if [ "$cmd" = grep ] && is_have_cmd apk && $cmd |& grep -wq BusyBox; then
            return 0
        fi

        return 1
    }

    for cmd in "$@"; do
        if ! is_have_cmd $cmd || is_need_reinstall $cmd; then
            if ! find_pkg_mgr; then
                error_and_exit "Can't find compatible package manager. Please manually install $cmd."
            fi
            cmd_to_pkg
            install_pkg_real
        fi
    done >&2
}

is_valid_ram_size() {
    is_digit "$1" && [ "$1" -gt 0 ]
}

check_ram() {
    ram_standard=256
    ram_cloud_image=256
    has_cloud_image=true

    # lsmem最准确但 centos7 arm 和 alpine 不能用，debian 9 util-linux 没有 lsmem
    # arm 24g dmidecode 显示少了128m
    # arm 24g lshw 显示23BiB
    # ec2 t4g arm alpine 用 lsmem 和 dmidecode 都无效，要用 lshw，但结果和free -m一致，其他平台则没问题
    install_pkg lsmem
    ram_size=$(lsmem -b 2>/dev/null | grep 'Total online memory:' | awk '{ print $NF/1024/1024 }')

    if ! is_valid_ram_size "$ram_size"; then
        install_pkg dmidecode
        ram_size=$(dmidecode -t 17 | grep "Size.*[GM]B" | awk '{if ($3=="GB") s+=$2*1024; else s+=$2} END {if(s>0) print s}')
    fi

    if ! is_valid_ram_size "$ram_size"; then
        install_pkg lshw
        # 不能忽略 -i，alpine 显示的是 System memory
        ram_str=$(lshw -c memory -short | grep -i 'System Memory' | awk '{print $3}')
        ram_size=$(grep <<<$ram_str -o '[0-9]*')
        grep <<<$ram_str GiB && ram_size=$((ram_size * 1024))
    fi

    # 用于兜底，不太准确
    # cygwin 要装 procps-ng 才有 free 命令
    if ! is_valid_ram_size "$ram_size"; then
        ram_size_k=$(grep '^MemTotal:' /proc/meminfo | awk '{print $2}')
        ram_size=$((ram_size_k / 1024 + 64 + 4))
    fi

    if ! is_valid_ram_size "$ram_size"; then
        error_and_exit "Could not detect RAM size."
    fi

    # ram 足够就用普通方法安装，否则如果内存大于512就用 cloud image
    # TODO: 测试 256 384 内存
    if ! is_use_cloud_image && [ $ram_size -lt $ram_standard ]; then
        if $has_cloud_image; then
            info "RAM < $ram_standard MB. Fallback to cloud image mode"
            cloud_image=1
        else
            error_and_exit "Could not install $distro: RAM < $ram_standard MB."
        fi
    fi

    if is_use_cloud_image && [ $ram_size -lt $ram_cloud_image ]; then
        error_and_exit "Could not install $distro using cloud image: RAM < $ram_cloud_image MB."
    fi
}

is_efi() {
    [ -d /sys/firmware/efi ]
}

is_grub_dir_linked() {
    # cloudcone 重装前/重装后(方法1)
    [ "$(readlink -f /boot/grub/grub.cfg)" = /boot/grub2/grub.cfg ] ||
        [ "$(readlink -f /boot/grub2/grub.cfg)" = /boot/grub/grub.cfg ] ||
        # cloudcone 重装后(方法2)
        { [ -f /boot/grub2/grub.cfg ] && [ "$(cat /boot/grub2/grub.cfg)" = 'chainloader (hd0)+1' ]; }
}

is_secure_boot_enabled() {
    if is_efi; then
        if dmesg | grep -i 'Secure boot enabled'; then
            return 0
        fi
        install_pkg mokutil
        mokutil --sb-state 2>&1 | grep -i 'SecureBoot enabled'
    else
        return 1
    fi
}

is_need_grub_extlinux() {
    return 0
}

# 只有 linux bios 是用本机的 grub/extlinux
is_use_local_grub_extlinux() {
    is_need_grub_extlinux && ! is_efi
}

is_use_local_grub() {
    is_use_local_grub_extlinux && is_mbr_using_grub
}

is_use_local_extlinux() {
    is_use_local_grub_extlinux && ! is_mbr_using_grub
}

is_mbr_using_grub() {
    find_main_disk
    # 各发行版不一定自带 strings hexdump xxd od 命令
    head -c 440 /dev/$xda | grep --text -iq 'GRUB'
}

to_upper() {
    tr '[:lower:]' '[:upper:]'
}

to_lower() {
    tr '[:upper:]' '[:lower:]'
}

del_cr() {
    # wmic/reg 换行符是 \r\r\n
    # wmic nicconfig where InterfaceIndex=$id get MACAddress,IPAddress,IPSubnet,DefaultIPGateway | hexdump -c
    sed -E 's/\r+$//'
}

del_empty_lines() {
    sed '/^[[:space:]]*$/d'
}

trim() {
    # sed -E -e 's/^[[:space:]]+//' -e 's/[[:space:]]+$//'
    sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

prompt_password() {
    info "prompt password"
    warn false "Leave blank to use a random password."
    warn false "不填写则使用随机密码"
    while true; do
        # 特殊字符列表
        # https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994562(v=ws.11)
        # 有的机器运行 centos 7 ，用 /dev/random 产生 16 位密码，开启了 rngd 也要 5 秒，关闭了 rngd 则长期阻塞
        chars='A-Za-z0-9~!@#$%^&*_=+`|(){}[]:;"<>,.?/-'
        random_password=$(tr -dc "$chars" </dev/urandom | head -c16)
        IFS= read -r -p "Password: " password
        if [ -n "$password" ]; then
            IFS= read -r -p "Retype password: " password_confirm
            if [ "$password" = "$password_confirm" ]; then
                break
            else
                error "Passwords don't match. Try again."
            fi
        else
            password=$random_password
            break
        fi
    done
}

save_password() {
    dir=$1

    # mkpasswd 有三个
    # expect 里的 mkpasswd 是用来生成随机密码的
    # whois 里的 mkpasswd 才是我们想要的，可能不支持 yescrypt，alpine 的 mkpasswd 是独立的包
    # busybox 里的 mkpasswd 也是我们想要的，但多数不支持 yescrypt

    # alpine 这两个包有冲突
    # apk add expect mkpasswd

    # 不要用 echo "$password" 保存密码，原因：
    # password="-n"
    # echo "$password"  # 空白

    # 明文密码
    # 假如用户运行 alpine live 直接打包硬盘镜像，如果保存了明文密码，则会暴露明文密码，因为 netboot initrd 在里面
    # 通过 --password 传入密码，history 有记录，也会暴露明文密码
    # /reinstall.log 也会暴露明文密码（已处理）
    # sha512
    # 以下系统均支持 sha512 密码，但是生成密码需要不同的工具
    # 兼容性     openssl   mkpasswd          busybox  python
    # centos 7     ×      只有expect的       需要编译    √
    # centos 8     √      只有expect的
    # debian 9     ×         √
    # ubuntu 16    ×         √
    # alpine       √      可能系统装了expect     √
    # cygwin       √
    # others       √

    # alpine
    if is_have_cmd busybox && busybox mkpasswd --help 2>&1 | grep -wq sha512; then
        crypted=$(printf '%s' "$password" | busybox mkpasswd -m sha512)
    # others
    elif install_pkg openssl && openssl passwd --help 2>&1 | grep -wq '\-6'; then
        crypted=$(printf '%s' "$password" | openssl passwd -6 -stdin)
    # debian 9 / ubuntu 16
    elif is_have_cmd apt-get && install_pkg whois && mkpasswd -m help | grep -wq sha-512; then
        crypted=$(printf '%s' "$password" | mkpasswd -m sha-512 --stdin)
    # centos 7
    # crypt.mksalt 是 python3 的
    # 红帽把它 backport 到了 centos7 的 python2 上
    # 在其它发行版的 python2 上运行会出错
    elif is_have_cmd yum && is_have_cmd python2; then
        crypted=$(python2 -c "import crypt, sys; print(crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_SHA512)))" "$password")
    else
        error_and_exit "Could not generate sha512 password."
    fi
    echo "$crypted" >"$dir/password-linux-sha512"

}

# 记录主硬盘
find_main_disk() {
    if [ -n "$main_disk" ]; then
        return
    fi

    # centos7下测试     lsblk --inverse $mapper | grep -w disk     grub2-probe -t disk /
    # 跨硬盘btrfs       只显示第一个硬盘                            显示两个硬盘
    # 跨硬盘lvm         显示两个硬盘                                显示/dev/mapper/centos-root
    # 跨硬盘软raid      显示两个硬盘                                显示/dev/md127

    # 还有 findmnt

    # 改成先检测 /boot/efi /efi /boot 分区？

    install_pkg lsblk
    # 查找主硬盘时，优先查找 /boot 分区，再查找 / 分区
    # lvm 显示的是 /dev/mapper/xxx-yyy，再用第二条命令得到sda
    mapper=$(mount | awk '$3=="/boot" {print $1}' | grep . || mount | awk '$3=="/" {print $1}')
    xda=$(lsblk -rn --inverse $mapper | grep -w disk | awk '{print $1}' | sort -u)

    # 检测主硬盘是否横跨多个磁盘
    os_across_disks_count=$(wc -l <<<"$xda")
    if [ $os_across_disks_count -eq 1 ]; then
        info "Main disk: $xda"
    else
        error_and_exit "OS across $os_across_disks_count disk: $xda"
    fi

    # 可以用 dd 找出 guid?

    # centos7 blkid lsblk 不显示 PTUUID
    # centos7 sfdisk 不显示 Disk identifier
    # alpine blkid 不显示 gpt 分区表的 PTUUID
    # 因此用 fdisk

    # Disk identifier: 0x36778223                                  # gnu fdisk + mbr
    # Disk identifier: D6B17C1A-FA1E-40A1-BDCB-0278A3ED9CFC        # gnu fdisk + gpt
    # Disk identifier (GUID): d6b17c1a-fa1e-40a1-bdcb-0278a3ed9cfc # busybox fdisk + gpt
    # 不显示 Disk identifier                                        # busybox fdisk + mbr

    # 获取 xda 的 id
    install_pkg fdisk
    main_disk=$(fdisk -l /dev/$xda | grep 'Disk identifier' | awk '{print $NF}' | sed 's/0x//')

    # 检查 id 格式是否正确
    if ! grep -Eix '[0-9a-f]{8}' <<<"$main_disk" &&
        ! grep -Eix '[0-9a-f-]{36}' <<<"$main_disk"; then
        error_and_exit "Disk ID is invalid: $main_disk"
    fi
}

is_found_ipv4_netconf() {
    [ -n "$ipv4_mac" ] && [ -n "$ipv4_addr" ] && [ -n "$ipv4_gateway" ]
}

is_found_ipv6_netconf() {
    [ -n "$ipv6_mac" ] && [ -n "$ipv6_addr" ] && [ -n "$ipv6_gateway" ]
}

# TODO: 单网卡多IP
collect_netconf() {
    # linux
    # 通过默认网关得到默认网卡

    # 多个默认路由下
    # ip -6 route show default dev ens3 完全不显示

    # ip -6 route show default
    # default proto static metric 1024 pref medium
    #         nexthop via 2a01:1111:262:4940::2 dev ens3 weight 1 onlink
    #         nexthop via fe80::5054:ff:fed4:5286 dev ens3 weight 1

    # ip -6 route show default
    # default via 2602:1111:0:80::1 dev eth0 metric 1024 onlink pref medium

    # arch + vultr
    # ip -6 route show default
    # default nhid 4011550343 via fe80::fc00:5ff:fe3d:2714 dev enp1s0 proto ra metric 1024 expires 1504sec pref medium

    for v in 4 6; do
        if via_gateway_dev_ethx=$(ip -$v route show default | grep -Ewo 'via [^ ]+ dev [^ ]+' | head -1 | grep .); then
            read -r _ gateway _ ethx <<<"$via_gateway_dev_ethx"
            eval ipv${v}_ethx="$ethx" # can_use_cloud_kernel 要用
            eval ipv${v}_mac="$(ip link show dev $ethx | grep link/ether | head -1 | awk '{print $2}')"
            eval ipv${v}_gateway="$gateway"
            eval ipv${v}_addr="$(ip -$v -o addr show scope global dev $ethx | grep -v temporary | head -1 | awk '{print $4}')"
        fi
    done

    if ! is_found_ipv4_netconf && ! is_found_ipv6_netconf; then
        error_and_exit "Can not get IP info."
    fi

    info "Network Info"
    echo "IPv4 MAC: $ipv4_mac"
    echo "IPv4 Address: $ipv4_addr"
    echo "IPv4 Gateway: $ipv4_gateway"
    echo "---"
    echo "IPv6 MAC: $ipv6_mac"
    echo "IPv6 Address: $ipv6_addr"
    echo "IPv6 Gateway: $ipv6_gateway"
    echo
}

get_maybe_efi_dirs_in_linux() {
    # arch云镜像efi分区挂载在/efi，且使用 autofs，挂载后会有两个 /efi 条目
    # openEuler 云镜像 boot 分区是 vfat 格式，但 vfat 可以当 efi 分区用
    # TODO: 最好通过 lsblk/blkid 检查是否为 efi 分区类型
    mount | awk '$5=="vfat" || $5=="autofs" {print $3}' | grep -E '/boot|/efi' | sort -u
}

get_disk_by_part() {
    dev_part=$1
    install_pkg lsblk >&2
    lsblk -rn --inverse "$dev_part" | grep -w disk | awk '{print $1}'
}

get_part_num_by_part() {
    dev_part=$1
    grep -oE '[0-9]*$' <<<"$dev_part"
}

grep_efi_entry() {
    # efibootmgr
    # BootCurrent: 0002
    # Timeout: 1 seconds
    # BootOrder: 0000,0002,0003,0001
    # Boot0000* sles-secureboot
    # Boot0001* CD/DVD Rom
    # Boot0002* Hard Disk
    # Boot0003* sles-secureboot
    # MirroredPercentageAbove4G: 0.00
    # MirrorMemoryBelow4GB: false

    # 根据文档，* 表示 active，也就是说有可能没有*(代表inactive)
    # https://manpages.debian.org/testing/efibootmgr/efibootmgr.8.en.html
    grep -E '^Boot[0-9a-fA-F]{4}'
}

# trans.sh 有同名方法
grep_efi_index() {
    awk '{print $1}' | sed -e 's/Boot//' -e 's/\*//'
}

add_efi_entry_in_linux() {
    source=$1

    install_pkg efibootmgr

    for efi_part in $(get_maybe_efi_dirs_in_linux); do
        if find $efi_part -iname "*.efi" >/dev/null; then
            dist_dir=$efi_part/EFI/reinstall
            basename=$(basename $source)
            mkdir -p $dist_dir

            if [[ "$source" = http* ]]; then
                curl -Lo "$dist_dir/$basename" "$source"
            else
                cp -f "$source" "$dist_dir/$basename"
            fi

            install_pkg findmnt
            # arch findmnt 会得到
            # systemd-1
            # /dev/sda2
            dev_part=$(findmnt -T "$dist_dir" -no SOURCE | grep '^/dev/')

            id=$(efibootmgr --create-only \
                --disk "/dev/$(get_disk_by_part $dev_part)" \
                --part "$(get_part_num_by_part $dev_part)" \
                --label "$(get_entry_name)" \
                --loader "\\EFI\\reinstall\\$basename" |
                grep_efi_entry | tail -1 | grep_efi_index)
            efibootmgr --bootnext $id
            return
        fi
    done

    error_and_exit "Can't find efi partition."
}

get_grub_efi_filename() {
    case "$basearch" in
    x86_64) echo grubx64.efi ;;
    aarch64) echo grubaa64.efi ;;
    esac
}

install_grub_linux_efi() {
    info 'download grub efi'

    # fedora 39 的 efi 无法识别 opensuse tumbleweed 的 xfs
    efi_distro=fedora
    grub_efi=$(get_grub_efi_filename)

    # 不要用 download.opensuse.org 和 download.fedoraproject.org
    # 因为 ipv6 访问有时跳转到 ipv4 地址，造成 ipv6 only 机器无法下载
    # 日韩机器有时得到国内镜像源，但镜像源屏蔽了国外 IP 导致连不上
    # https://mirrors.bfsu.edu.cn/opensuse/ports/aarch64/tumbleweed/repo/oss/EFI/BOOT/grub.efi

    # fcix 经常 404
    # https://mirror.fcix.net/opensuse/tumbleweed/repo/oss/EFI/BOOT/bootx64.efi
    # https://mirror.fcix.net/opensuse/tumbleweed/appliances/openSUSE-Tumbleweed-Minimal-VM.x86_64-Cloud.qcow2

    # dl.fedoraproject.org 不支持 ipv6

    if [ "$efi_distro" = fedora ]; then
        # 使用固定的 Fedora 版本，因为本脚本只支持 Debian
        # get_latest_distro_releasever 无法解析 Fedora 版本
        fedora_ver=41

        if is_in_china; then
            mirror=https://mirror.nju.edu.cn/fedora
        else
            mirror=https://d2lzkl7pfhq30w.cloudfront.net/pub/fedora/linux
        fi

        curl -Lo $tmp/$grub_efi $mirror/releases/$fedora_ver/Everything/$basearch/os/EFI/BOOT/$grub_efi
    else
        if is_in_china; then
            mirror=https://mirror.nju.edu.cn/opensuse
        else
            mirror=https://downloadcontentcdn.opensuse.org
        fi

        [ "$basearch" = x86_64 ] && ports='' || ports=/ports/$basearch

        curl -Lo $tmp/$grub_efi $mirror$ports/tumbleweed/repo/oss/EFI/BOOT/grub.efi
    fi

    add_efi_entry_in_linux $tmp/$grub_efi
}

download_and_extract_apk() {
    local alpine_ver=$1
    local package=$2
    local extract_dir=$3

    install_pkg tar xz
    is_in_china && mirror=http://mirror.nju.edu.cn/alpine || mirror=https://dl-cdn.alpinelinux.org/alpine
    package_apk=$(curl -L $mirror/v$alpine_ver/main/$basearch/ | grep -oP "$package-[^-]*-[^-]*\.apk" | sort -u)
    if ! [ "$(wc -l <<<"$package_apk")" -eq 1 ]; then
        error_and_exit "find no/multi apks."
    fi
    mkdir -p "$extract_dir"

    # 屏蔽警告
    tar 2>&1 | grep -q BusyBox && tar_args= || tar_args=--warning=no-unknown-keyword
    curl -L "$mirror/v$alpine_ver/main/$basearch/$package_apk" | tar xz $tar_args -C "$extract_dir"
}


find_grub_extlinux_cfg() {
    dir=$1
    filename=$2
    keyword=$3

    # 当 ln -s /boot/grub /boot/grub2 时
    # find /boot/ 会自动忽略 /boot/grub2 里面的文件
    cfgs=$(
        # 只要 $dir 存在
        # 无论是否找到结果，返回值都是 0
        find $dir \
            -type f -name $filename \
            -exec grep -E -l "$keyword" {} \;
    )

    count="$(wc -l <<<"$cfgs")"
    if [ "$count" -eq 1 ]; then
        echo "$cfgs"
    else
        error_and_exit "Find $count $filename."
    fi
}

# 空格、&、用户输入的网址要加引号，否则 grub 无法正确识别
is_need_quote() {
    [[ "$1" = *' '* ]] || [[ "$1" = *'&'* ]] || [[ "$1" = http* ]]
}

# 转换 finalos_a=1 为 finalos.a=1 ，排除 finalos_mirrorlist
build_finalos_cmdline() {
    if vars=$(compgen -v finalos_); then
        for key in $vars; do
            value=${!key}
            key=${key#finalos_}
            if [ -n "$value" ] && [ $key != "mirrorlist" ]; then
                is_need_quote "$value" &&
                    finalos_cmdline+=" finalos_$key='$value'" ||
                    finalos_cmdline+=" finalos_$key=$value"
            fi
        done
    fi
}

build_extra_cmdline() {
    # 使用 extra_xxx=yyy 而不是 extra.xxx=yyy
    # 因为 debian installer /lib/debian-installer-startup.d/S02module-params
    # 会将 extra.xxx=yyy 写入新系统的 /etc/modprobe.d/local.conf
    # https://answers.launchpad.net/ubuntu/+question/249456
    # https://salsa.debian.org/installer-team/rootskel/-/blob/master/src/lib/debian-installer-startup.d/S02module-params?ref_type=heads
    for key in confhome force_cn cloud_image main_disk \
        elts deb_mirror \
        ssh_port web_port; do
        value=${!key}
        if [ -n "$value" ]; then
            is_need_quote "$value" &&
                extra_cmdline+=" extra_$key='$value'" ||
                extra_cmdline+=" extra_$key=$value"
        fi
    done

    # 指定最终安装系统的 mirrorlist，链接有&，在grub中是特殊字符，所以要加引号
    if [ -n "$finalos_mirrorlist" ]; then
        extra_cmdline+=" extra_mirrorlist='$finalos_mirrorlist'"
    elif [ -n "$nextos_mirrorlist" ]; then
        extra_cmdline+=" extra_mirrorlist='$nextos_mirrorlist'"
    fi

    # cloudcone 特殊处理
    if is_grub_dir_linked; then
        finalos_cmdline+=" extra_link_grub_dir=1"
    fi
}

echo_tmp_ttys() {
    case "$basearch" in
    x86_64) echo "console=ttyS0,115200n8 console=tty0" ;;
    aarch64) echo "console=ttyS0,115200n8 console=ttyAMA0,115200n8 console=tty0" ;;
    esac
}

get_entry_name() {
    printf 'reinstall ('
    printf '%s' "$distro"
    [ -n "$releasever" ] && printf ' %s' "$releasever"
    printf ')'
}

# shellcheck disable=SC2154
build_nextos_cmdline() {
    if [ $nextos_distro = alpine ]; then
        nextos_cmdline="alpine_repo=$nextos_repo modloop=$nextos_modloop"
    else
        nextos_cmdline="lowmem/low=1 auto=true priority=critical"
        nextos_cmdline+=" url=$nextos_ks"
        nextos_cmdline+=" mirror/http/hostname=${nextos_udeb_mirror%/*}"
        nextos_cmdline+=" mirror/http/directory=/${nextos_udeb_mirror##*/}"
        nextos_cmdline+=" base-installer/kernel/image=$nextos_kernel"
        # elts 的 debian 不能用 security 源，否则安装过程会提示无法访问
        if [ "$nextos_distro" = debian ] && is_debian_elts; then
            nextos_cmdline+=" apt-setup/services-select="
        fi
    fi

    if [ "$nextos_distro" = debian ]; then
        if [ "$basearch" = "x86_64" ]; then
            # debian installer 好像第一个 tty 是主 tty
            # 设置ttyS0,tty0,安装界面还是显示在ttyS0
            :
        else
            # debian arm 在没有ttyAMA0的机器上（aws t4g），最少要设置一个tty才能启动
            # 只设置tty0也行，但安装过程ttyS0没有显示
            nextos_cmdline+=" $(echo_tmp_ttys)"
        fi
    else
        nextos_cmdline+=" $(echo_tmp_ttys)"
    fi
    # nextos_cmdline+=" mem=256M"
    # nextos_cmdline+=" lowmem=+1"
}

build_cmdline() {
    # nextos
    build_nextos_cmdline

    # finalos
    # trans 需要 finalos_distro 识别是安装 alpine 还是其他系统
    if [ "$distro" = alpine ]; then
        finalos_distro=alpine
    fi
    if [ -n "$finalos_distro" ]; then
        build_finalos_cmdline
    fi

    # extra
    build_extra_cmdline

    cmdline="$nextos_cmdline $finalos_cmdline $extra_cmdline"
}

# 脚本可能多次运行，先清理之前的残留
mkdir_clear() {
    dir=$1

    if [ -z "$dir" ] || [ "$dir" = / ]; then
        return
    fi

    # 再次运行时，有可能 mount 了 btrfs root，因此先要 umount_all
    # 但目前不需要 mount ，因此用不到
    # umount_all $dir
    rm -rf $dir
    mkdir -p $dir
}

mod_initrd_debian_kali() {
    # hack 1
    # 允许设置 ipv4 onlink 网关
    sed -Ei 's,&&( onlink=),||\1,' etc/udhcpc/default.script

    # hack 2
    # 修改 /var/lib/dpkg/info/netcfg.postinst 运行我们的脚本
    netcfg() {
        #!/bin/sh
        # shellcheck source=/dev/null
        . /usr/share/debconf/confmodule
        db_progress START 0 5 debian-installer/netcfg/title

        : get_ip_conf_cmd

        # 运行 trans.sh，保存配置
        db_progress INFO base-installer/progress/netcfg
        sh /trans.sh
        db_progress STEP 1
    }

    # 直接覆盖 net-retriever，方便调试
    # curl -Lo /usr/lib/debian-installer/retriever/net-retriever $confhome/net-retriever

    postinst=var/lib/dpkg/info/netcfg.postinst
    get_function_content netcfg >$postinst
    get_ip_conf_cmd | insert_into_file $postinst after ": get_ip_conf_cmd"
    # cat $postinst

    change_priority() {
        while IFS= read -r line; do
            if [[ "$line" = Package:* ]]; then
                package=$(echo "$line" | cut -d' ' -f2-)

            elif [[ "$line" = Priority:* ]]; then
                # shellcheck disable=SC2154
                if [ "$line" = "Priority: standard" ]; then
                    for p in $disabled_list; do
                        if [ "$package" = "$p" ]; then
                            line="Priority: optional"
                            break
                        fi
                    done
                elif [[ "$package" = ata-modules* ]]; then
                    # 改成强制安装
                    # 因为是 pata-modules sata-modules scsi-modules 的依赖
                    # 但我们没安装它们，也就不会自动安装 ata-modules
                    line="Priority: standard"
                fi
            fi
            echo "$line"
        done
    }

    # shellcheck disable=SC2012
    kver=$(ls -d lib/modules/* | awk -F/ '{print $NF}')

    net_retriever=usr/lib/debian-installer/retriever/net-retriever
    # shellcheck disable=SC2016
    sed -i 's,>> "$1",| change_priority >> "$1",' $net_retriever
    insert_into_file $net_retriever after '#!/bin/sh' <<EOF
disabled_list="
depthcharge-tools-installer
kickseed-common
nobootloader

partman-cros
partman-iscsi
partman-jfs
partman-md
partman-xfs
rescue-check
wpasupplicant-udeb
lilo-installer
systemd-boot-installer
nic-modules-$kver-di
nic-pcmcia-modules-$kver-di
nic-usb-modules-$kver-di
nic-wireless-modules-$kver-di
nic-shared-modules-$kver-di
pcmcia-modules-$kver-di
pcmcia-storage-modules-$kver-di
cdrom-core-modules-$kver-di
firewire-core-modules-$kver-di
usb-storage-modules-$kver-di
isofs-modules-$kver-di
jfs-modules-$kver-di
xfs-modules-$kver-di
loop-modules-$kver-di
pata-modules-$kver-di
sata-modules-$kver-di
scsi-modules-$kver-di
"

$(get_function change_priority)
EOF

    # https://github.com/linuxhw/LsPCI?tab=readme-ov-file#storageata-pci
    # https://debian.pkgs.org/12/debian-main-amd64/linux-image-6.1.0-18-cloud-amd64_6.1.76-1_amd64.deb.html
    # https://deb.debian.org/debian/pool/main/l/linux-signed-amd64/
    # https://deb.debian.org/debian/dists/bookworm/main/debian-installer/binary-all/Packages.xz
    # https://deb.debian.org/debian/dists/bookworm/main/debian-installer/binary-amd64/Packages.xz
    # 以下是 debian-installer 有的驱动，这些驱动云内核不一定都有，(+)表示云内核有
    # scsi-core-modules 默认安装（不用修改），是 ata-modules 的依赖
    #                   包含 sd_mod.ko(+) scsi_mod.ko(+) scsi_transport_fc.ko(+) scsi_transport_sas.ko(+) scsi_transport_spi.ko(+)
    # ata-modules       默认可选（改成必装），是下方模块的依赖。只有 ata_generic.ko(+) 和 libata.ko(+) 两个驱动

    # pata-modules      默认安装（改成可选），里面的驱动都是 pata_ 开头，但只有 pata_legacy.ko(+) 在云内核中
    # sata-modules      默认安装（改成可选），里面的驱动大部分是 sata_ 开头的，其他重要的还有 ahci.ko libahci.ko ata_piix.ko(+)
    #                   云内核没有 sata 模块，也没有内嵌，有一个 CONFIG_SATA_HOST=y，libata-$(CONFIG_SATA_HOST)	+= libata-sata.o
    # scsi-modules      默认安装（改成可选），包含 nvme.ko(+) 和各种虚拟化驱动(+)

    download_and_extract_udeb() {
        package=$1
        extract_dir=$2

        # 获取 udeb 列表
        udeb_list=$tmp/udeb_list
        if ! [ -f $udeb_list ]; then
            # shellcheck disable=SC2154
            curl -L http://$nextos_udeb_mirror/dists/$nextos_codename/main/debian-installer/binary-$basearch_alt/Packages.gz |
                zcat | grep 'Filename:' | awk '{print $2}' >$udeb_list
        fi

        # 下载 udeb
        curl -Lo $tmp/tmp.udeb http://$nextos_udeb_mirror/"$(grep -F /${package}_ $udeb_list)"

        # 使用 ar tar xz
        # cygwin 需安装 binutils
        # centos7 ar 不支持 --output
        install_pkg ar tar xz
        (cd $tmp && ar x $tmp/tmp.udeb)
        tar xf $tmp/data.tar.xz -C $extract_dir
    }

    # 在 debian installer 中判断能否用云内核
    create_can_use_cloud_kernel_sh can_use_cloud_kernel.sh

    # 下载 fix-eth-name 脚本
    curl -LO "$confhome/fix-eth-name.sh"
    curl -LO "$confhome/fix-eth-name.service"

    # 有段时间 kali initrd 删除了原版 wget
    # 但 initrd 的 busybox wget 又不支持 https
    # 因此改成在这里下载
    curl -LO "$confhome/get-xda.sh"
    curl -LO "$confhome/ttys.sh"
    if [ -n "$frpc_config" ]; then
        curl -LO "$confhome/get-frpc-url.sh"
        curl -LO "$confhome/frpc.service"
    fi

    # 可以节省一点内存？
    echo 'export DEBCONF_DROP_TRANSLATIONS=1' |
        insert_into_file lib/debian-installer/menu before 'exec debconf'

    # 还原 kali netinst.iso 的 simple-cdd 机制
    # 主要用于调用 kali.postinst 设置 zsh 为默认 shell
    # 但 mini.iso 又没有这种机制
    # https://gitlab.com/kalilinux/build-scripts/kali-live/-/raw/main/kali-config/common/includes.installer/kali-finish-install?ref_type=heads
    # https://salsa.debian.org/debian/simple-cdd/-/blob/master/debian/14simple-cdd?ref_type=heads
    # https://http.kali.org/pool/main/s/simple-cdd/simple-cdd-profiles_0.6.9_all.udeb
    if [ "$distro" = kali ]; then
        # 但我们没有使用 iso，因此没有 kali.postinst，需要另外下载
        mkdir -p cdrom/simple-cdd
        curl -Lo cdrom/simple-cdd/kali.postinst https://gitlab.com/kalilinux/build-scripts/kali-live/-/raw/main/kali-config/common/includes.installer/kali-finish-install?ref_type=heads
        chmod a+x cdrom/simple-cdd/kali.postinst
    fi

    if [ "$distro" = debian ] && is_debian_elts; then
        curl -Lo usr/share/keyrings/debian-archive-keyring.gpg https://deb.freexian.com/extended-lts/archive-key.gpg
    fi

    # 提前下载 fdisk
    # 因为 fdisk-udeb 包含 fdisk 和 sfdisk，提前下载可减少占用
    mkdir_clear $tmp/fdisk
    download_and_extract_udeb fdisk-udeb $tmp/fdisk
    cp -f $tmp/fdisk/usr/sbin/fdisk usr/sbin/

    # >256M
    if [ $ram_size -gt 256 ]; then
        sed -i '/^pata-modules/d' $net_retriever
        sed -i '/^sata-modules/d' $net_retriever
        sed -i '/^scsi-modules/d' $net_retriever
    else
        # <=256M 极限优化
        find_main_disk
        extra_drivers=
        for driver in $(get_disk_drivers $xda); do
            echo "using driver: $driver"
            case $driver in
            nvme) extra_drivers+=" nvme nvme-core" ;;
                # xen 的横杠特别不同
            xen_blkfront) extra_drivers+=" xen-blkfront" ;;
            xen_scsifront) extra_drivers+=" xen-scsifront" ;;
            virtio_blk | virtio_scsi | hv_storvsc | vmw_pvscsi) extra_drivers+=" $driver" ;;
            pata_legacy) sed -i '/^pata-modules/d' $net_retriever ;; # 属于 pata-modules
            ata_piix) sed -i '/^sata-modules/d' $net_retriever ;;    # 属于 sata-modules
            ata_generic) ;;                                          # 属于 ata-modules，不用处理，因为我们设置强制安装了 ata-modules
            esac
        done

        # extra drivers
        # xen 还需要以下两个？
        # kernel/drivers/xen/xen-scsiback.ko
        # kernel/drivers/block/xen-blkback/xen-blkback.ko
        # 但反查也找不到 curl https://deb.debian.org/debian/dists/bookworm/main/Contents-udeb-amd64.gz | zcat | grep xen
        if [ -n "$extra_drivers" ]; then
            mkdir_clear $tmp/scsi
            download_and_extract_udeb scsi-modules-$kver-di $tmp/scsi
            relative_drivers_dir=lib/modules/$kver/kernel/drivers

            udeb_drivers_dir=$tmp/scsi/$relative_drivers_dir
            dist_drivers_dir=$initrd_dir/$relative_drivers_dir
            (
                cd $udeb_drivers_dir
                for driver in $extra_drivers; do
                    # debian 模块没有压缩
                    # kali 模块有压缩
                    # 因此要有 *
                    if ! find $dist_drivers_dir -name "$driver.ko*" | grep -q .; then
                        echo "adding driver: $driver"
                        file=$(find . -name "$driver.ko*" | grep .)
                        cp -fv --parents "$file" "$dist_drivers_dir"
                    fi
                done
            )
        fi
    fi

    # amd64)
    # 	level1=737 # MT=754108, qemu: -m 780
    # 	level2=424 # MT=433340, qemu: -m 460
    # 	min=316    # MT=322748, qemu: -m 350

    # 将 use_level 2 9 修改为 use_level 1
    # x86 use_level 2 会出现 No root file system is defined.
    # arm 即使 use_level 1 也会出现 No root file system is defined.
    sed -i 's/use_level=[29]/use_level=1/' lib/debian-installer-startup.d/S15lowmem

    # hack 3
    # 修改 trans.sh
    # 1. 直接调用 create_ifupdown_config
    # shellcheck disable=SC2154
    insert_into_file $initrd_dir/trans.sh after '^: main' <<EOF
        distro=$nextos_distro
        releasever=$nextos_releasever
        create_ifupdown_config /etc/network/interfaces
        exit
EOF
    # 2. 删除 debian busybox 无法识别的语法
    # 3. 删除 apk 语句
    # 4. debian 11/12 initrd 无法识别 > >
    # 5. debian 11/12 initrd 无法识别 < <
    # 6. debian 11 initrd 无法识别 set -E
    # 7. debian 11 initrd 无法识别 trap ERR
    # 8. debian 9 initrd 无法识别 ${string//find/replace}
    # 9. debian 12 initrd 无法识别 . <(
    # 删除或注释，可能会导致空方法而报错，因此改为替换成'\n: #'
    replace='\n: #'
    sed -Ei \
        -e "s/> >/$replace/" \
        -e "s/< </$replace/" \
        -e "s/\. <\(/$replace/" \
        -e "s/^[[:space:]]*apk[[:space:]]/$replace/" \
        -e "s/^[[:space:]]*trap[[:space:]]/$replace/" \
        -e "s/\\$\{.*\/\/.*\/.*\}/$replace/" \
        -e "/^[[:space:]]*set[[:space:]]/s/E//" \
        $initrd_dir/trans.sh
}

get_disk_drivers() {
    get_drivers "/sys/block/$1"
}

get_net_drivers() {
    get_drivers "/sys/class/net/$1"
}

get_drivers() {
    # 有以下结果组合出现
    # sd_mod
    # virtio_blk
    # virtio_scsi
    # virtio_pci
    # pcieport
    # xen_blkfront
    # ahci
    # nvme
    # mptspi
    # mptsas
    # vmw_pvscsi
    (
        cd "$(readlink -f $1)"
        while ! [ "$(pwd)" = / ]; do
            if [ -d driver ]; then
                if [ -d driver/module ]; then
                    # 显示全名，例如 xen_blkfront sd_mod
                    # 但 ahci 没有这个文件，所以 else 不能省略
                    basename "$(readlink -f driver/module)"
                else
                    # 不显示全名，例如 vbd sd
                    basename "$(readlink -f driver)"
                fi
            fi
            cd ..
        done
    )
}

exit_if_cant_use_cloud_kernel() {
    find_main_disk
    collect_netconf

    # shellcheck disable=SC2154
    if ! can_use_cloud_kernel "$xda" $ipv4_ethx $ipv6_ethx; then
        error_and_exit "Can't use cloud kernel. And not enough RAM to run normal kernel."
    fi
}

can_use_cloud_kernel() {
    # initrd 下也要使用，不要用 <<<

    # 有些虚拟机用了 ahci，但云内核没有 ahci 驱动
    cloud_eth_modules='ena|gve|mana|virtio_net|xen_netfront|hv_netvsc|vmxnet3|mlx4_en|mlx4_core|mlx5_core|ixgbevf'
    cloud_blk_modules='ata_generic|ata_piix|pata_legacy|nvme|virtio_blk|virtio_scsi|xen_blkfront|xen_scsifront|hv_storvsc|vmw_pvscsi'

    # disk
    drivers="$(get_disk_drivers $1)"
    shift
    for driver in $drivers; do
        echo "using disk driver: $driver"
    done
    echo "$drivers" | grep -Ewq "$cloud_blk_modules" || return 1

    # net
    # v4 v6 eth 相同，只检查一次
    if [ "$1" = "$2" ]; then
        shift
    fi
    while [ $# -gt 0 ]; do
        drivers="$(get_net_drivers $1)"
        shift
        for driver in $drivers; do
            echo "using net driver: $driver"
        done
        echo "$drivers" | grep -Ewq "$cloud_eth_modules" || return 1
    done
}

create_can_use_cloud_kernel_sh() {
    cat <<EOF >$1
        $(get_function get_drivers)
        $(get_function get_net_drivers)
        $(get_function get_disk_drivers)
        $(get_function can_use_cloud_kernel)

        can_use_cloud_kernel "\$@"
EOF
}

get_ip_conf_cmd() {
    collect_netconf >&2
    is_in_china && is_in_china=true || is_in_china=false

    sh=/initrd-network.sh
    if is_found_ipv4_netconf && is_found_ipv6_netconf && [ "$ipv4_mac" = "$ipv6_mac" ]; then
        echo "'$sh' '$ipv4_mac' '$ipv4_addr' '$ipv4_gateway' '$ipv6_addr' '$ipv6_gateway' '$is_in_china'"
    else
        if is_found_ipv4_netconf; then
            echo "'$sh' '$ipv4_mac' '$ipv4_addr' '$ipv4_gateway' '' '' '$is_in_china'"
        fi
        if is_found_ipv6_netconf; then
            echo "'$sh' '$ipv6_mac' '' '' '$ipv6_addr' '$ipv6_gateway' '$is_in_china'"
        fi
    fi
}


mod_initrd() {
    info "mod $nextos_distro initrd"
    install_pkg gzip cpio

    # 解压
    # 先删除临时文件，避免之前运行中断有残留文件
    initrd_dir=$tmp/initrd
    mkdir_clear $initrd_dir
    cd $initrd_dir

    # cygwin 下处理 debian initrd 时
    # shellcheck disable=SC2046
    # nonmatching 是精确匹配路径
    zcat /reinstall-initrd | cpio -idm

    curl -Lo $initrd_dir/trans.sh $confhome/trans.sh
    if ! grep -iq "$SCRIPT_VERSION" $initrd_dir/trans.sh; then
        error_and_exit "
This script is outdated, please download reinstall.sh again.
脚本有更新，请重新下载 reinstall.sh"
    fi

    curl -Lo $initrd_dir/initrd-network.sh $confhome/initrd-network.sh
    chmod a+x $initrd_dir/trans.sh $initrd_dir/initrd-network.sh

    # 保存配置
    mkdir -p $initrd_dir/configs
    if [ -n "$ssh_keys" ]; then
        cat <<<"$ssh_keys" >$initrd_dir/configs/ssh_keys
    else
        save_password $initrd_dir/configs
    fi
    if [ -n "$frpc_config" ]; then
        cat "$frpc_config" >$initrd_dir/configs/frpc.toml
    fi

    if is_distro_like_debian $nextos_distro; then
        mod_initrd_debian_kali
    else
        mod_initrd_$nextos_distro
    fi

    # alpine live 不精简 initrd
    # 因为不知道用户想干什么，可能会用到精简的文件
    if is_virt; then
        remove_useless_initrd_files
    fi

    # 重建
    # 注意要用 cpio -H newc 不要用 cpio -c ，不同版本的 -c 作用不一样，很坑
    # -c    Use the old portable (ASCII) archive format
    # -c    Identical to "-H newc", use the new (SVR4)
    #       portable format.If you wish the old portable
    #       (ASCII) archive format, use "-H odc" instead.
    find . | cpio --quiet -o -H newc | gzip -1 >/reinstall-initrd
    cd - >/dev/null
}

remove_useless_initrd_files() {
    info "slim initrd"

    # 显示精简前的大小
    du -sh .

    # 删除 initrd 里面没用的文件/驱动
    rm -rf bin/brltty
    rm -rf etc/brltty
    rm -rf sbin/wpa_supplicant
    rm -rf usr/lib/libasound.so.*
    rm -rf usr/share/alsa
    (
        cd lib/modules/*/kernel/drivers/net/ethernet/
        for item in *; do
            case "$item" in
            # 甲骨文 arm 用自定义镜像支持设为 mlx5 vf 网卡，且不是 azure 那样显示两个网卡
            amazon | google | mellanox | realtek) ;;
            intel)
                (
                    cd "$item"
                    for sub_item in *; do
                        case "$sub_item" in
                        # 有 e100.ko e1000文件夹 e1000e文件夹
                        e100* | lib* | *vf) ;;
                        *) rm -rf $sub_item ;;
                        esac
                    done
                )
                ;;
            *) rm -rf $item ;;
            esac
        done
    )
    (
        cd lib/modules/*/kernel
        for item in \
            net/mac80211 \
            net/wireless \
            net/bluetooth \
            drivers/hid \
            drivers/mmc \
            drivers/mtd \
            drivers/usb \
            drivers/ssb \
            drivers/mfd \
            drivers/bcma \
            drivers/pcmcia \
            drivers/parport \
            drivers/platform \
            drivers/staging \
            drivers/net/usb \
            drivers/net/bonding \
            drivers/net/wireless \
            drivers/input/rmi4 \
            drivers/input/keyboard \
            drivers/input/touchscreen \
            drivers/bus/mhi \
            drivers/char/pcmcia \
            drivers/misc/cardreader; do
            rm -rf $item
        done
    )

    # 显示精简后的大小
    du -sh .
}

get_unix_path() {
    printf '%s' "$1"
}

# 脚本入口
if mount | grep -q 'tmpfs on / type tmpfs'; then
    error_and_exit "Can't run this script in Live OS."
fi


# 检查 root
if [ "$EUID" -ne 0 ]; then
    error_and_exit "Please run as root."
fi

long_opts=
for o in ci debug force-cn help \
    passwd: password: \
    ssh-port: \
    ssh-key: public-key: \
    web-port: http-port: \
    frpc-conf: frpc-config: frpc-toml:; do
    [ -n "$long_opts" ] && long_opts+=,
    long_opts+=$o
done

# 整理参数
if ! opts=$(getopt -n $0 -o "h" --long "$long_opts" -- "$@"); then
    exit
fi

# /tmp 挂载在内存的话，可能不够空间
# 处理 --frpc--toml 时会下载文件，因此在处理参数前就创建临时目录
tmp=/reinstall-tmp
mkdir_clear "$tmp"

eval set -- "$opts"
# shellcheck disable=SC2034
while true; do
    case "$1" in
    -h | --help)
        usage_and_exit
        ;;
    --debug)
        set -x
        shift
        ;;
    --ci)
        cloud_image=1
        shift
        ;;
    --force-cn)
        # 仅为了方便测试
        force_cn=1
        shift
        ;;
    --frpc-conf | --frpc-config | --frpc-toml)
        [ -n "$2" ] || error_and_exit "Need value for $1"

        case "$(to_lower <<<"$2")" in
        http://* | https://*)
            frpc_config_url=$2
            frpc_config=$tmp/frpc_config
            if ! curl -L "$frpc_config_url" -o "$frpc_config"; then
                error_and_exit "Can't get frpc config from $frpc_config_url"
            fi
            ;;
        *)
            # windows 路径转换
            if ! { frpc_config=$(get_unix_path "$2") && [ -f "$frpc_config" ]; }; then
                error_and_exit "File not exists: $2"
            fi
            ;;
        esac

        # 转为绝对路径
        frpc_config=$(readlink -f "$frpc_config")

        shift 2
        ;;
    --passwd | --password)
        [ -n "$2" ] || error_and_exit "Need value for $1"
        password=$2
        shift 2
        ;;
    --ssh-key | --public-key)
        ssh_key_error_and_exit() {
            error "$1"
            cat <<EOF
Available options:
  --ssh-key "ssh-rsa ..."
  --ssh-key "ssh-ed25519 ..."
  --ssh-key "ecdsa-sha2-nistp256/384/521 ..."
  --ssh-key github:your_username
  --ssh-key gitlab:your_username
  --ssh-key http://path/to/public_key
  --ssh-key https://path/to/public_key
  --ssh-key /path/to/public_key
EOF
            exit 1
        }

        # https://manpages.debian.org/testing/openssh-server/authorized_keys.5.en.html#AUTHORIZED_KEYS_FILE_FORMAT
        is_valid_ssh_key() {
            grep -qE '^(ecdsa-sha2-nistp(256|384|521)|ssh-(ed25519|rsa)) ' <<<"$1"
        }

        [ -n "$2" ] || ssh_key_error_and_exit "Need value for $1"

        case "$(to_lower <<<"$2")" in
        github:* | gitlab:* | http://* | https://*)
            if [[ "$(to_lower <<<"$2")" = http* ]]; then
                key_url=$2
            else
                IFS=: read -r site user <<<"$2"
                [ -n "$user" ] || ssh_key_error_and_exit "Need a username for $site"
                key_url="https://$site.com/$user.keys"
            fi
            if ! ssh_key=$(curl -L "$key_url"); then
                error_and_exit "Can't get ssh key from $key_url"
            fi
            ;;
        *)
            # 检测值是否为 ssh key
            if is_valid_ssh_key "$2"; then
                ssh_key=$2
            else
                # 视为路径
                if ! { ssh_key_file=$(get_unix_path "$2") && [ -f "$ssh_key_file" ]; }; then
                    ssh_key_error_and_exit "SSH Key/File/Url \"$2\" is invalid."
                fi
                ssh_key=$(<"$ssh_key_file")
            fi
            ;;
        esac

        # 检查 key 格式
        if ! is_valid_ssh_key "$ssh_key"; then
            ssh_key_error_and_exit "SSH Key/File/Url \"$2\" is invalid."
        fi

        # 保存 key
        # 不用处理注释，可以支持写入 authorized_keys
        # 安装 nixos 时再处理注释/空行，转成数组，再添加到 nix 配置文件中
        if [ -n "$ssh_keys" ]; then
            ssh_keys+=$'\n'
        fi
        ssh_keys+=$ssh_key

        shift 2
        ;;
    --ssh-port)
        is_port_valid $2 || error_and_exit "Invalid $1 value: $2"
        ssh_port=$2
        shift 2
        ;;
    --web-port | --http-port)
        is_port_valid $2 || error_and_exit "Invalid $1 value: $2"
        web_port=$2
        shift 2
        ;;
    --)
        shift
        break
        ;;
    *)
        echo "Unexpected option: $1."
        usage_and_exit
        ;;
    esac
done

# 检查目标系统名
verify_os_name "$@"

# 检查必须的参数
verify_os_args

# 不支持容器虚拟化
assert_not_in_container

# 不支持安全启动
if is_secure_boot_enabled; then
    error_and_exit "Please disable secure boot first."
fi

# 密码
if [ -z "$ssh_keys" ] && [ -z "$password" ]; then
    prompt_password
fi

# 必备组件\ninstall_pkg curl grep\n
# Debian 不强制 --ci 参数，保留用户选择

# 检查硬件架构
basearch=$(uname -m)
# 统一架构名称，并强制 64 位
case "$(echo $basearch | to_lower)" in
i?86 | x64 | x86* | amd64)
    basearch=x86_64
    basearch_alt=amd64
    ;;
arm* | aarch64)
    basearch=aarch64
    basearch_alt=arm64
    ;;
*) error_and_exit "Unsupported arch: $basearch" ;;
esac

# 所有资源直接从 GitHub 获取

# 检查内存
# 会用到 wmic，因此要在设置国内 confhome 后使用
check_ram

# Debian cloud image uses Alpine as intermediate, otherwise use Debian installer.
if ! is_use_cloud_image; then
    setos nextos $distro $releasever
else
    alpine_ver_for_trans=$(get_latest_distro_releasever alpine)
    setos finalos $distro $releasever
    setos nextos alpine $alpine_ver_for_trans
fi

# 删除之前的条目
# 防止第一次运行 netboot.xyz，第二次运行其他，但还是进入 netboot.xyz
# 防止第一次运行其他，第二次运行 netboot.xyz，但还有第一次的菜单
# bios 无论什么情况都用到 grub，所以不用处理
if is_efi; then
    # shellcheck disable=SC2046
    find $(get_maybe_efi_dirs_in_linux) $([ -d /boot ] && echo /boot) \
        -type f -name 'custom.cfg' -exec rm -f {} \;

    install_pkg efibootmgr
    efibootmgr | grep -q 'BootNext:' && efibootmgr --quiet --delete-bootnext
    efibootmgr | grep_efi_entry | grep 'reinstall' | grep_efi_index |
        xargs -I {} efibootmgr --quiet --bootnum {} --delete-bootnum
fi

# 有的机器开启了 kexec，例如腾讯云轻量 debian，要禁用
if [ -f /etc/default/kexec ]; then
    sed -i 's/LOAD_KEXEC=true/LOAD_KEXEC=false/' /etc/default/kexec
fi

# 下载 nextos 内核
info download vmlnuz and initrd
curl -Lo /reinstall-vmlinuz $nextos_vmlinuz
curl -Lo /reinstall-initrd $nextos_initrd
if is_use_firmware; then
    curl -Lo /reinstall-firmware $nextos_firmware
fi

# 修改 alpine debian kali initrd
if [ "$nextos_distro" = alpine ] || is_distro_like_debian "$nextos_distro"; then
    mod_initrd
fi

# 将内核/netboot.xyz.lkrn 放到正确的位置

# grub / extlinux
if is_need_grub_extlinux; then
    # linux efi 使用外部 grub，因为
    # 1. 原系统 grub 可能没有去除 aarch64 内核 magic number 校验
    # 2. 原系统可能不是用 grub
    if is_efi; then
        install_grub_linux_efi
    fi

    # 寻找 grub.cfg / extlinux.conf
    if is_efi; then
        # 现在 linux-efi 是使用 reinstall 目录下的 grub
        # shellcheck disable=SC2046
        efi_reinstall_dir=$(find $(get_maybe_efi_dirs_in_linux) -type d -name "reinstall" | head -1)
        grub_cfg=$efi_reinstall_dir/grub.cfg
    else
        if is_mbr_using_grub; then
            if is_have_cmd update-grub; then
                # alpine debian ubuntu
                grub_cfg=$(grep -o '[^ ]*grub.cfg' "$(get_cmd_path update-grub)" | head -1)
            else
                # 找出主配置文件（含有menuentry|blscfg）
                # 现在 efi 用下载的 grub，因此不需要查找 efi 目录
                grub_cfg=$(find_grub_extlinux_cfg '/boot/grub*' grub.cfg 'menuentry|blscfg')
            fi
        else
            # extlinux
            extlinux_cfg=$(find_grub_extlinux_cfg /boot extlinux.conf LINUX)
        fi
    fi

    # 找到 grub 程序的前缀
    # 并重新生成 grub.cfg
    # 因为有些机子例如hython debian的grub.cfg少了40_custom 41_custom
    if is_use_local_grub; then
        if is_have_cmd grub2-mkconfig; then
            grub=grub2
        elif is_have_cmd grub-mkconfig; then
            grub=grub
        else
            error_and_exit "grub not found"
        fi

        # nixos 手动执行 grub-mkconfig -o /boot/grub/grub.cfg 会丢失系统启动条目
        # 正确的方法是修改 configuration.nix 的 boot.loader.grub.extraEntries
        # 但是修改 configuration.nix 不是很好，因此改成修改 grub.cfg
        if [ -x /nix/var/nix/profiles/system/bin/switch-to-configuration ]; then
            # 生成 grub.cfg
            /nix/var/nix/profiles/system/bin/switch-to-configuration boot
            # 手动启用 41_custom
            nixos_grub_home="$(dirname "$(readlink -f "$(get_cmd_path grub-mkconfig)")")/.."
            $nixos_grub_home/etc/grub.d/41_custom >>$grub_cfg
        elif is_have_cmd update-grub; then
            update-grub
        else
            $grub-mkconfig -o $grub_cfg
        fi
    fi

    # 重新生成 extlinux.conf
    if is_use_local_extlinux; then
        if is_have_cmd update-extlinux; then
            update-extlinux
        fi
    fi

    # 选择用 custom.cfg (linux-bios) 还是 grub.cfg (linux-efi / win)
    if is_use_local_grub; then
        target_cfg=$(dirname $grub_cfg)/custom.cfg
    else
        target_cfg=$grub_cfg
    fi

    # 找到 /reinstall-vmlinuz /reinstall-initrd 的绝对路径
    # extlinux + 单独的 boot 分区
    # 把内核文件放在 extlinux.conf 所在的目录
    if is_use_local_extlinux && is_boot_in_separate_partition; then
        dir=
    else
        # 获取当前系统根目录在 btrfs 中的绝对路径
        if is_os_in_btrfs; then
            # btrfs subvolume show /
            # 输出可能是 / 或 root 或 @/.snapshots/1/snapshot
            dir=$(btrfs subvolume show / | head -1)
            if ! [ "$dir" = / ]; then
                dir="/$dir/"
            fi
        else
            dir=/
        fi
    fi

    vmlinuz=${dir}reinstall-vmlinuz
    initrd=${dir}reinstall-initrd
    firmware=${dir}reinstall-firmware

    # 设置 linux initrd 命令
    if is_use_local_extlinux; then
        linux_cmd=LINUX
        initrd_cmd=INITRD
    else
        linux_cmd="linux$efi"
        initrd_cmd="initrd$efi"
    fi

    # 设置 cmdlind initrds
    find_main_disk
    build_cmdline

    initrds="$initrd"
    if is_use_firmware; then
        initrds+=" $firmware"
    fi

    if is_use_local_extlinux; then
        info extlinux
        echo $extlinux_cfg
        extlinux_dir="$(dirname $extlinux_cfg)"

        # 不起作用
        # 好像跟 extlinux --once 有冲突
        sed -i "/^MENU HIDDEN/d" $extlinux_cfg
        sed -i "/^TIMEOUT /d" $extlinux_cfg

        del_empty_lines <<EOF | tee -a $extlinux_cfg
TIMEOUT 5
LABEL reinstall
  MENU LABEL $(get_entry_name)
  $linux_cmd $vmlinuz
  $([ -n "$initrds" ] && echo "$initrd_cmd $initrds")
  $([ -n "$cmdline" ] && echo "APPEND $cmdline")
EOF
        # 设置重启引导项
        extlinux --once=reinstall $extlinux_dir

        # 复制文件到 extlinux 工作目录
        if is_boot_in_separate_partition; then
            info "copying files to $extlinux_dir"
            cp -f /reinstall-initrd $extlinux_dir
            is_use_firmware && cp -f /reinstall-firmware $extlinux_dir
            # 放最后，防止前两条返回非 0 而报错
            cp -f /reinstall-vmlinuz $extlinux_dir
        fi
    else
        # cloudcone 从光驱的 grub 启动，再加载硬盘的 grub.cfg
        # menuentry "Grub 2" --id grub2 {
        #         set root=(hd0,msdos1)
        #         configfile /boot/grub2/grub.cfg
        # }

        # 加载后 $prefix 依然是光驱的 (hd96)/boot/grub
        # 导致找不到 $prefix 目录的 grubenv，因此读取不到 next_entry
        # 以下方法为 cloudcone 重新加载 grubenv

        # 需查找 2*2 个文件夹
        # 分区：系统 / boot
        # 文件夹：grub / grub2
        # shellcheck disable=SC2121,SC2154
        # cloudcone debian 能用但 ubuntu 模板用不了
        # ubuntu 模板甚至没显示 reinstall menuentry
        load_grubenv_if_not_loaded() {
            if ! [ -s $prefix/grubenv ]; then
                for dir in /boot/grub /boot/grub2 /grub /grub2; do
                    set grubenv="($root)$dir/grubenv"
                    if [ -s $grubenv ]; then
                        load_env --file $grubenv
                        if [ "${next_entry}" ]; then
                            set default="${next_entry}"
                            set next_entry=
                            save_env --file $grubenv next_entry
                        else
                            set default="0"
                        fi
                        return
                    fi
                done
            fi
        }

        # 生成 grub 配置
        # 实测 centos 7 lvm 要手动加载 lvm 模块
        info grub
        echo $target_cfg

        get_function_content load_grubenv_if_not_loaded >$target_cfg

        # 原系统为 openeuler 云镜像，需要添加 --unrestricted，否则要输入密码
        del_empty_lines <<EOF | tee -a $target_cfg
set timeout_style=menu
set timeout=5
menuentry "$(get_entry_name)" --unrestricted {
    insmod lvm
    $(is_os_in_btrfs && echo 'set btrfs_relative_path=n')
    insmod all_video
    search --no-floppy --file --set=root $vmlinuz
    $linux_cmd $vmlinuz $cmdline
    $([ -n "$initrds" ] && echo "$initrd_cmd $initrds")
}
EOF

        # 设置重启引导项
        if is_use_local_grub; then
            $grub-reboot "$(get_entry_name)"
        fi
    fi
fi

info 'info'
echo "$distro $releasever"

if [ -n "$ssh_keys" ]; then
    echo "Public Key: $ssh_keys"
else
    echo "Username: root"
    echo "Password: $password"
fi

echo "Reboot to start the installation."
