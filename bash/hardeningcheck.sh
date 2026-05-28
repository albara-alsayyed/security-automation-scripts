#!/usr/bin/env bash
#
# Basic Linux hardening checker.
#
# What it does:
# - Checks common defensive configuration items.
# - Prints PASS/WARN/INFO results for quick review.
#
# How to run:
#   bash bash/hardening_check.sh
#
# Safe lab disclaimer:
#   Run only on Linux systems you own or are authorized to assess.

set -euo pipefail

pass() { printf '[PASS] %s\n' "$1"; }
warn() { printf '[WARN] %s\n' "$1"; }
info() { printf '[INFO] %s\n' "$1"; }

echo "Linux Hardening Check"
echo "====================="

if [[ $EUID -ne 0 ]]; then
  warn "Run as root or with sudo for the most complete results."
fi

if command -v ufw >/dev/null 2>&1; then
  ufw_status="$(ufw status 2>/dev/null | head -n 1 || true)"
  [[ "$ufw_status" == *active* ]] && pass "UFW firewall is active." || warn "UFW firewall is not active."
elif command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --state >/dev/null 2>&1 && pass "firewalld is active." || warn "firewalld is not active."
else
  info "No UFW/firewalld command found. Check firewall controls manually."
fi

sshd_config="/etc/ssh/sshd_config"
if [[ -r "$sshd_config" ]]; then
  if grep -Eiq '^\s*PermitRootLogin\s+no' "$sshd_config"; then
    pass "SSH root login is disabled."
  else
    warn "SSH root login is not explicitly disabled."
  fi

  if grep -Eiq '^\s*PasswordAuthentication\s+no' "$sshd_config"; then
    pass "SSH password authentication is disabled."
  else
    warn "SSH password authentication is not explicitly disabled."
  fi
else
  info "SSH config not readable at $sshd_config."
fi

if [[ -r /etc/login.defs ]]; then
  pass_max_days="$(awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs | tail -n 1)"
  if [[ -n "${pass_max_days:-}" && "$pass_max_days" -le 90 ]]; then
    pass "Password max age is $pass_max_days days."
  else
    warn "Password max age is not set to 90 days or less."
  fi
fi

if command -v findmnt >/dev/null 2>&1; then
  if findmnt /tmp | grep -q noexec; then
    pass "/tmp has noexec mount option."
  else
    warn "/tmp does not appear to have noexec enabled."
  fi
fi

world_writable_count="$(find /tmp -xdev -type d -perm -0002 2>/dev/null | wc -l | tr -d ' ')"
info "World-writable directories under /tmp: $world_writable_count"

echo
echo "Review WARN items and confirm against your organization's baseline."
