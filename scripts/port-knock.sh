#!/usr/bin/env bash
# scripts/port-knock.sh — Port knocking client for CTF boxes
# NuRichter · CySec Arsenal  [Authorized use only]
# Usage: ./scripts/port-knock.sh 10.10.10.x 7000 8000 9000
TARGET="${1:-}"; shift || true
PORTS=("$@")
[[ -z "$TARGET" || ${#PORTS[@]} -eq 0 ]] && { echo "Usage: $0 <host> <port1> <port2> ..."; exit 1; }
echo "[*] Port knocking: $TARGET  sequence: ${PORTS[*]}"
for port in "${PORTS[@]}"; do
  echo "  [>] Knocking $TARGET:$port"
  nc -zw1 "$TARGET" "$port" 2>/dev/null || true
  sleep 0.5
done
echo "[+] Knock sequence complete."
