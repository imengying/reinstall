#!/bin/sh
set -e

fstab=/etc/fstab
tmp=${fstab}.tmp

if ! findmnt -no FSTYPE / | grep -qx btrfs; then
    exit 0
fi

if grep -q 'subvol=@rootfs' "$fstab"; then
    sed -i 's/subvol=@rootfs/subvol=\/@/' "$fstab"
fi

if awk '
BEGIN { OFS="\t"; changed=0 }
{ line=$0 }
/^[[:space:]]*#/ { print line; next }
$2 == "/" && $3 == "btrfs" {
    if ($4 !~ /compress=zstd/) {
        $4 = "compress=zstd," $4
        changed=1
    }
}
{ print }
END { if (changed) exit 0; exit 1 }
' "$fstab" >"$tmp"; then
    mv "$tmp" "$fstab"
else
    rm -f "$tmp"
fi

mount -o remount,compress=zstd / || true

if grep -q 'compress=zstd' "$fstab"; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now ensure-btrfs-zstd.service || true
        rm -f /etc/systemd/system/ensure-btrfs-zstd.service
        systemctl daemon-reload || true
    fi
    rm -f /usr/local/sbin/ensure-btrfs-zstd.sh
fi
