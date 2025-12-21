#!/bin/sh
set -e

fstab=/etc/fstab

if ! findmnt -no FSTYPE / | grep -qx btrfs; then
    exit 0
fi

sed -i 's/subvol=@rootfs/subvol=\/@/' "$fstab"
if grep -qE '^[^#][^[:space:]]+[[:space:]]+/[[:space:]].*btrfs' "$fstab"; then
    sed -i '/^[^#][^[:space:]]+[[:space:]]+\/[[:space:]].*btrfs/ { /compress=zstd/! s/btrfs[[:space:]]\+/btrfs   compress=zstd,/ }' "$fstab"
fi

mount -o remount,compress=zstd / || true

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now ensure-btrfs-zstd.service || true
    rm -f /etc/systemd/system/ensure-btrfs-zstd.service
    systemctl daemon-reload || true
fi

rm -f /usr/local/sbin/ensure-btrfs-zstd.sh
