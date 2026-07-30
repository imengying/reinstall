#!/bin/sh
# debian ubuntu redhat 安装模式共用此脚本
# alpine 未用到此脚本

get_all_disks() {
    # shellcheck disable=SC2010
    ls /sys/block/ | grep -Ev '^(loop|sr|nbd)'
}

get_xda() {
    eval "$(grep -o 'extra_main_disk=[^ ]*' /proc/cmdline | sed 's/^extra_//')"

    if [ -z "$main_disk" ]; then
        echo 'Main disk ID was not provided.' >&2
        return 1
    fi

    main_disk=$(printf '%s' "$main_disk" | sed 's/^0x//' | tr '[:upper:]' '[:lower:]')
    matched_disk=
    match_count=0
    for disk in $(get_all_disks); do
        disk_id=$(fdisk -l "/dev/$disk" 2>/dev/null | grep 'Disk identifier' | head -1 | sed 's/.*[[:space:]]//' | sed 's/^0x//' | tr '[:upper:]' '[:lower:]')
        if [ -n "$disk_id" ] && [ "$disk_id" = "$main_disk" ]; then
            matched_disk=$disk
            match_count=$((match_count + 1))
        fi
    done

    case "$match_count" in
    1)
        echo "$matched_disk"
        ;;
    0)
        echo "No disk matches ID $main_disk." >&2
        return 1
        ;;
    *)
        echo "Disk ID $main_disk is not unique ($match_count matches)." >&2
        return 1
        ;;
    esac
}

get_xda
