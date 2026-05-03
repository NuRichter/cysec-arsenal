#!/usr/bin/env bash
# scripts/scan-full.sh — Full port + service scan using pscan + nmap fallback
# NuRichter · CySec Arsenal  [Authorized use only]
set -euo pipefail
GRN='\033[0;32m'; CYN='\033[0;36m'; MAG='\033[0;35m'; YLW='\033[0;33m'; RST='\033[0m'
TARGET="${1:-}"; [[ -z "$TARGET" ]] && { echo "Usage: $0 <host/CIDR>"; exit 1; }
ok()    { echo -e "  ${GRN}[+]${RST} $*"; }
info()  { echo -e "  ${CYN}[*]${RST} $*"; }
found() { echo -e "  ${MAG}[>]${RST} $*"; }
warn()  { echo -e "  ${YLW}[!]${RST} $*"; }

OUTDIR="output/scan_$(echo $TARGET | tr '/.' '__')_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

echo -e "\n${CYN}  ── Full Scan: $TARGET ──${RST}\n"
info "Output: $OUTDIR"

# Phase 1: Fast top-100 scan
info "Phase 1: Fast top-100 scan..."
if [[ -x ./target/release/pscan ]]; then
  ./target/release/pscan -t "$TARGET" --top100 --banner --json > "$OUTDIR/top100.json" 2>/dev/null || true
  OPEN=$(python3 -c "import json; d=json.load(open('$OUTDIR/top100.json')); print(','.join(str(r['port']) for r in d))" 2>/dev/null || echo "")
  [[ -n "$OPEN" ]] && found "Open ports: $OPEN" || info "No ports from top-100"
fi

# Phase 2: Full range
info "Phase 2: Full port scan (1-65535)..."
if [[ -x ./target/release/pscan ]]; then
  ./target/release/pscan -t "$TARGET" -p 1-65535 --timeout 400 --concurrency 1000 --json \
    > "$OUTDIR/full.json" 2>/dev/null || true
  FULL_OPEN=$(python3 -c "import json; d=json.load(open('$OUTDIR/full.json')); print(len(d), 'ports')" 2>/dev/null || echo "?")
  found "Full scan: $FULL_OPEN"
fi

# Phase 3: Nmap version/script scan on known-open ports
if command -v nmap &>/dev/null && [[ -n "${OPEN:-}" ]]; then
  info "Phase 3: Nmap service/version detection on open ports..."
  nmap -sV -sC -p "$OPEN" "$TARGET" -oA "$OUTDIR/nmap" 2>/dev/null || true
  ok "Nmap results: $OUTDIR/nmap.*"
fi

info "Phase 4: OS detection..."
command -v nmap &>/dev/null && nmap -O "$TARGET" -oN "$OUTDIR/os.txt" 2>/dev/null | tail -5 || true

ok "Scan complete → $OUTDIR/"
