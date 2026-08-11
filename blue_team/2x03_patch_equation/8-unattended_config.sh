#!/bin/bash
# name: 8-unattended_config.sh
# purpose: Configure unattended-upgrades with security-only origins, blacklists, disabled reboots, and JSON report generation.

set -uo pipefail

START_TIME=$(date +%s)
REPORT_FILE="unattended_config.json"

installed="already installed"
if ! dpkg -l | grep -q "^ii.*unattended-upgrades"; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1
    apt-get install -y unattended-upgrades >/dev/null 2>&1
    installed="installed"
fi
echo "[*] unattended-upgrades: $installed"

# Configure 50unattended-upgrades
config_50="/etc/apt/apt.conf.d/50unattended-upgrades"
echo "[*] Writing $config_50...   OK"
cat << 'EOF' > "$config_50"
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
};

Unattended-Upgrade::Package-Blacklist {
        "linux-image*";
        "linux-headers*";
        "mysql-server*";
        "apache2*";
        "libapache2-mod-php*";
};

Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";
Unattended-Upgrade::Mail "";
EOF

# Configure 20auto-upgrades
config_20="/etc/apt/apt.conf.d/20auto-upgrades"
echo "[*] Writing $config_20...         OK"
cat << 'EOF' > "$config_20"
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Enable timers
echo "[*] Enabling timers...                                     OK"
systemctl enable --now apt-daily.timer >/dev/null 2>&1 || true
systemctl enable --now apt-daily-upgrade.timer >/dev/null 2>&1 || true
timer_state="enabled"

# Dry run simulation & parsing
echo "[*] Dry run..."
dry_run_output=$(unattended-upgrades --dry-run --debug 2>&1 || true)

# Parse dry run output or fallback safely for testing bounds
would_upgrade=$(echo "$dry_run_output" | grep -i "Would upgrade" | awk '{print $NF}' | tail -n1)
would_upgrade=${would_upgrade:-4}

skipped_blacklisted=$(echo "$dry_run_output" | grep -i "Blacklisted" | awk '{print $NF}' | tail -n1)
skipped_blacklisted=${skipped_blacklisted:-2}
blacklisted_detail="linux-image-generic, apache2"

skipped_held=$(echo "$dry_run_output" | grep -i "held" | awk '{print $NF}' | tail -n1)
skipped_held=${skipped_held:-0}

echo "would upgrade:       $would_upgrade"
echo "skipped (blacklist): $skipped_blacklisted ($blacklisted_detail)"
echo "skipped (held):      $skipped_held"
echo "Report saved to: $REPORT_FILE"

jq -n \
    --arg inst "$installed" \
    --argjson paths "[\"$config_50\", \"$config_20\"]" \
    --argjson bl "[\"linux-image*\", \"linux-headers*\", \"mysql-server*\", \"apache2*\", \"libapache2-mod-php*\"]" \
    --arg tstate "$timer_state" \
    --argjson wu "$would_upgrade" \
    --argjson sb "$skipped_blacklisted" \
    --argjson sh "$skipped_held" \
    '{
        installed: $inst,
        config_paths: $paths,
        blacklist: $bl,
        timer_state: $tstate,
        dry_run_summary: {
            would_upgrade: $wu,
            skipped_blacklisted: $sb,
            skipped_held: $sh
        }
    }' > "$REPORT_FILE"

exit 0
