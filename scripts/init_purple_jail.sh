#!/usr/bin/env bash
set -euo pipefail

CHAIN_NAME="${1:-PURPLE_JAIL}"

if ! iptables -n -L "$CHAIN_NAME" >/dev/null 2>&1; then
    iptables -N "$CHAIN_NAME"
fi

if ! iptables -C INPUT -j "$CHAIN_NAME" >/dev/null 2>&1; then
    iptables -I INPUT 1 -j "$CHAIN_NAME"
fi

iptables -L "$CHAIN_NAME" -v -n --line-numbers
