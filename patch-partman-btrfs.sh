#!/bin/sh

partman_root=${PARTMAN_ROOT:-}
mount_script=${partman_root}/lib/partman/mount.d/70btrfs
fstab_script=${partman_root}/lib/partman/fstab.d/btrfs

[ -f "$mount_script" ] || exit 0
[ -f "$fstab_script" ] || exit 0

sed -i \
    -e 's#/@rootfs#/@#g' \
    -e 's#subvol=@rootfs#subvol=@#g' \
    "$mount_script" "$fstab_script"
