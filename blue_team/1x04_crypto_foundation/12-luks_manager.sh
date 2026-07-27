#!/bin/bash
set -euo pipefail

IMG="encrypted_volume.img"
MAP="secure_vol"
MNT="/mnt/secure_test"

case "${1:-}" in
    create)
        dd if=/dev/zero of="$IMG" bs=1M count=500 status=none
        cryptsetup luksFormat "$IMG"
        cryptsetup luksOpen "$IMG" "$MAP"
        mkfs.ext4 -q "/dev/mapper/$MAP"
        cryptsetup luksClose "$MAP"
        echo "[+] Created and formatted $IMG"
        ;;
    open)
        [[ -f $IMG ]] || { echo "[-] Error: $IMG missing."; exit 1; }
        cryptsetup luksOpen "$IMG" "$MAP"
        mkdir -p "$MNT"
        mount "/dev/mapper/$MAP" "$MNT"
        echo "[+] Opened and mounted at $MNT"
        ;;
    close)
        umount "$MNT" 2>/dev/null || true
        cryptsetup luksClose "$MAP" 2>/dev/null || true
        echo "[+] Unmounted and closed $MAP"
        ;;
    *)
        echo "Usage: $0 {create|open|close}"
        exit 1
        ;;
esac
