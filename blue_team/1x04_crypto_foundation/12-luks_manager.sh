#!/bin/bash
set -euo pipefail

IMG="encrypted_volume.img"
MAP="secure_vol"
MNT="/mnt/secure_test"

MODE="$1"

case "$MODE" in
    create)
        dd if=/dev/zero of="$IMG" bs=1M count=500 status=none
        cryptsetup luksFormat "$IMG"
        cryptsetup luksOpen "$IMG" "$MAP"
        mkfs.ext4 -q "/dev/mapper/$MAP"
        cryptsetup luksClose "$MAP"
        ;;
    open)
        [[ -f "$IMG" ]] || { echo "[-] Error: $IMG missing."; exit 1; }
        cryptsetup luksOpen "$IMG" "$MAP"
        mkdir -p "$MNT"
        mount "/dev/mapper/$MAP" "$MNT"
        ;;
    close)
        umount "$MNT" 2>/dev/null || true
        cryptsetup luksClose "$MAP" 2>/dev/null || true
        ;;
    *)
        echo "Usage: $0 {create|open|close}"
        echo "Optional positional targets: \$2=$IMG \$3=$MAP \$4=$MNT"
        exit 1
        ;;
esac
