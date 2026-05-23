#!/usr/bin/env bash
#
# Basic defensive Linux inventory script.
#
# What it does:
# - Prints local OS, kernel, user, network, process, and service context.
# - Helps defenders document a lab or server before deeper review.
#
# How to run:
#   bash bash/linux_enum_basic.sh
#
# Safe lab disclaimer:
#   Run only on systems you own or administer with permission.

set -euo pipefail

section() {
  printf '\n==== %s ====\n' "$1"
}

section "System"
hostnamectl 2>/dev/null || hostname
printf 'Kernel: %s\n' "$(uname -a)"

section "Current User"
id
who 2>/dev/null || true

section "Network Interfaces"
ip -brief addr 2>/dev/null || ifconfig 2>/dev/null || true

section "Listening Ports"
ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null || true

section "Top Processes"
ps aux --sort=-%mem | head -n 10

section "Enabled Services"
systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -n 30 || true

section "Recent Auth Logs"
if [[ -r /var/log/auth.log ]]; then
  tail -n 20 /var/log/auth.log
elif [[ -r /var/log/secure ]]; then
  tail -n 20 /var/log/secure
else
  echo "No readable auth log found."
fi
