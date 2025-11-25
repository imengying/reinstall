#!/bin/ash
# shellcheck shell=dash
# trans.sh/debian.cfg 共用此脚本

# debian 9 不支持 set -E
set -e

is_in_china() {
    grep -q 1 /dev/netconf/*/is_in_china
}

is_ipv6_only() {
    ! grep -q 1 /dev/netconf/eth*/ipv4_has_internet
}

get_frpc_url() {
    local os_type=${1:-linux}
    if [ "$os_type" != linux ]; then
        echo "Unsupported os_type: $os_type" >&2
        return 1
    fi

    version=$(
        # debian 11 initrd 没有 xargs awk
        # debian 12 initrd 没有 xargs
        # github 不支持 ipv6
        if is_in_china || is_ipv6_only; then
            wget -O- https://mirrors.nju.edu.cn/github-release/fatedier/frp/LatestRelease/frp_sha256_checksums.txt |
                grep -m1 frp_ | cut -d_ -f2
        else
            # https://api.github.com/repos/fatedier/frp/releases/latest 有请求次数限制
            wget --spider -S https://github.com/fatedier/frp/releases/latest 2>&1 |
                grep -m1 '^  Location:' | sed 's,.*/tag/v,,'
        fi
    )

    if [ -z "$version" ]; then
        echo 'cannot find version'
        return 1
    fi

    suffix=tar.gz

    mirror=$(
        # github 不支持 ipv6
        # jsdelivr 不支持 github releases 文件
        if is_ipv6_only || is_in_china; then
            echo https://mirrors.nju.edu.cn/github-release/fatedier/frp
        else
            echo https://github.com/fatedier/frp/releases/download
        fi
    )

    arch=$(
        case "$(uname -m)" in
        x86_64) echo amd64 ;;
        aarch64) echo arm64 ;;
        esac
    )

    filename=frp_${version}_${os_type}_${arch}.$suffix

    echo "${mirror}/v${version}/${filename}"
}

get_frpc_url "$@"
