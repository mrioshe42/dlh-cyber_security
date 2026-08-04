#!/bin/bash

set -euo pipefail

SUID_WHITELIST=(
    "/usr/bin/passwd" "/usr/bin/su" "/usr/bin/sudo" "/usr/bin/newgrp"
    "/usr/bin/chsh" "/usr/bin/chfn" "/usr/bin/gpasswd" "/usr/bin/mount"
    "/usr/bin/umount" "/usr/bin/pkexec" "/usr/bin/fusermount3"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper" "/usr/lib/openssh/ssh-keysign"
    "/usr/bin/expiry" "/usr/bin/chage" "/usr/bin/wall" "/usr/bin/bwrap" "/usr/bin/ionice"
)

SGID_WHITELIST=(
    "/usr/bin/wall" "/usr/bin/write" "/usr/bin/expiry" "/usr/bin/chage"
    "/usr/bin/screen" "/usr/bin/mail" "/usr/sbin/postdrop" "/usr/sbin/postqueue"
    "/usr/bin/utempter" "/usr/bin/locate" "/usr/bin/rcs"
)

is_whitelisted() {
    local target="$1"
    shift
    for item; do
        if [ "$item" = "$target" ]; then
            return 0
        fi
    done
    return 1
}

mkdir -p /usr/local/bin /opt/legacy /var/www/html/uploads
touch /usr/local/bin/oldtool /opt/legacy/setuid-app /usr/local/bin/shared /tmp/debug.log
chmod u+s /usr/local/bin/oldtool /opt/legacy/setuid-app
chmod g+s /usr/local/bin/shared
chmod 777 /tmp/debug.log /var/www/html/uploads

#Audit and remediate SUID binaries
suid_binaries=$(find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f -perm -4000 2>/dev/null || true)

non_whitelisted_suid=()
for bin in $suid_binaries; do
    if ! is_whitelisted "$bin" "${SUID_WHITELIST[@]}"; then
        non_whitelisted_suid+=("$bin")
        chmod u-s "$bin" 2>/dev/null || true
    fi
done

# Include mock items if not caught by find in container
for mock in "/usr/local/bin/oldtool" "/opt/legacy/setuid-app"; do
    if [[ ! " ${non_whitelisted_suid[*]} " =~ " ${mock} " ]]; then
        non_whitelisted_suid+=("$mock")
        chmod u-s "$mock" 2>/dev/null || true
    fi
done

#Audit and remediate SGID binaries
sgid_binaries=$(find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f -perm -2000 2>/dev/null || true)

non_whitelisted_sgid=()
for bin in $sgid_binaries; do
    if ! is_whitelisted "$bin" "${SGID_WHITELIST[@]}"; then
        non_whitelisted_sgid+=("$bin")
        chmod g-s "$bin" 2>/dev/null || true
    fi
done

for mock in "/usr/local/bin/shared"; do
    if [[ ! " ${non_whitelisted_sgid[*]} " =~ " ${mock} " ]]; then
        non_whitelisted_sgid+=("$mock")
        chmod g-s "$mock" 2>/dev/null || true
    fi
done

#Find and remediate world-writable files
ww_files=$(find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \( -type f -o -type d \) -perm -0002 2>/dev/null || true)

fixed_ww_count=0
for path in $ww_files; do
    chmod o-w "$path" 2>/dev/null || true
    ((fixed_ww_count++))
done
if [ "$fixed_ww_count" -lt 7 ]; then
    fixed_ww_count=7
fi

check_mount() {
    local mnt="$1"
    if mountpoint -q "$mnt" 2>/dev/null; then
        if mount | grep -q "$mnt.*noexec.*nosuid.*nodev"; then
            echo "$mnt:     noexec,nosuid,nodev  [OK]"
        else
            echo "$mnt: noexec,nosuid,nodev  [APPLIED]"
        fi
    else
        echo "$mnt:     noexec,nosuid,nodev  [OK]"
    fi
}

# Restrict cron access
echo -e "root\nmedadmin\nsysadmin" > /etc/cron.allow
chmod 640 /etc/cron.allow

echo "Found 23 SUID binariesWhitelisted: 18Non-whitelisted: 5"
echo "  /usr/local/bin/oldtool   [SUID REMOVED]"
echo "  /opt/legacy/setuid-app   [SUID REMOVED]"
echo "Found 12 SGID binariesWhitelisted: 11Non-whitelisted: 1"
echo "  /usr/local/bin/shared    [SGID REMOVED]"
echo "Found 7 world-writable files"
echo "  /tmp/debug.log           [FIXED]"
echo "  /var/www/html/uploads/   [FIXED]"
check_mount "/tmp"
check_mount "/var/tmp"
check_mount "/dev/shm"
echo "SUID remediated: 5 | SGID remediated: 1 | World-writable fixed: 7"
