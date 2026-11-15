#!/usr/bin/env bash
set -euo pipefail
if ! nft list table inet trafficmon >/dev/null 2>&1; then
  nft add table inet trafficmon
  nft 'add chain inet trafficmon input { type filter hook input priority filter + 10; policy accept; }'
  nft 'add chain inet trafficmon output { type filter hook output priority filter + 10; policy accept; }'
  nft add rule inet trafficmon input tcp dport 2443 counter comment '"anytls-in"'
  nft add rule inet trafficmon output tcp sport 2443 counter comment '"anytls-out"'
fi
