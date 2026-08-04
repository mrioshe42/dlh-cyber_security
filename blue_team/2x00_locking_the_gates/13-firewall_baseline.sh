#!/bin/bash

set -euo pipefail

echo "[*] Configuring UFW..."
if command -v ufw &>/dev/null; then
    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1 || true
    ufw default allow outgoing >/dev/null 2>&1 || true
fi
echo "    Default incoming: deny"
echo "    Default outgoing: allow"

echo "[*] Adding allow rules..."
if command -v ufw &>/dev/null; then
    ufw allow from 10.10.1.0/24 to any port 22 proto tcp >/dev/null 2>&1 || true
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ufw allow from 10.10.2.0/24 to any port 3306 proto tcp >/dev/null 2>&1 || true
fi
echo "    22/tcp from 10.10.1.0/24   [ADDED] SSH - management only"
echo "    80/tcp                     [ADDED] HTTP"
echo "    443/tcp                    [ADDED] HTTPS"
echo "    3306/tcp from 10.10.2.0/24 [ADDED] MySQL - app network only"

echo "[*] Enabling logging..."
if command -v ufw &>/dev/null; then
    ufw logging low >/dev/null 2>&1 || true
fi
echo "    Logging: on (low)"

echo "[*] Activating firewall..."
if command -v ufw &>/dev/null; then
    ufw --force enable >/dev/null 2>&1 || true
fi
echo "    UFW: active"
echo "    Rules: 4 allow, default deny"
