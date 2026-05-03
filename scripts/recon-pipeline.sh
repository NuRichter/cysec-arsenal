#!/usr/bin/env bash
# scripts/recon-pipeline.sh — Automated Recon Pipeline
# NuRichter · CySec Arsenal
#
# Runs: port scan → subdomain enum → web tech detect → output report
# Requires: target/release/pscan, target/release/subenum, nmap (optional)
#
# Usage:
#   ./scripts/recon-pipeline.sh example.com
#   ./scripts/recon-pipeline.sh example.com --full
#   ./scripts/recon-pipeline.sh 10.10.10.5 --ip-only

set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; CYN='\033[0;36m'
MAG='\033[0;35m'; YLW='\033[0;33m'; DIM='\033[2m'; RST='\033[0m'

TARGET="${1:-}"
FULL=0; IP_ONLY=0
for arg in "${@:2}"; do
  [[ "$arg" == "--full" ]]    && FULL=1
  [[ "$arg" == "--ip-only" ]] && IP_ONLY=1
done

[[ -z "$TARGET" ]] && { echo "Usage: $0 <domain|ip> [--full] [--ip-only]"; exit 1; }

STAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="output/recon/${TARGET//\//_}_${STAMP}"
mkdir -p "$OUTDIR"

ARSENAL="./target/release"

ok()    { echo -e "  ${GRN}[+]${RST} $*"; }
info()  { echo -e "  ${CYN}[*]${RST} $*"; }
found() { echo -e "  ${MAG}[>]${RST} $*"; }
warn()  { echo -e "  ${YLW}[!]${RST} $*"; }
hdr()   { echo -e "\n${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n  $*\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"; }

hdr "🔍 CySec Arsenal · Recon Pipeline"
info "Target  : $TARGET"
info "Output  : $OUTDIR"
info "Started : $(date)"
echo ""

# ─── 1. Resolve / IP info ─────────────────────────────────────────────────────
hdr "1 · IP Resolution"
TARGET_IP=$(python3 -c "import socket; print(socket.gethostbyname('$TARGET'))" 2>/dev/null || echo "$TARGET")
info "Resolved: $TARGET → $TARGET_IP"
echo "$TARGET_IP" > "$OUTDIR/ip.txt"

# ─── 2. Port scan ─────────────────────────────────────────────────────────────
hdr "2 · Port Scan"
if [[ -x "$ARSENAL/pscan" ]]; then
  info "Running pscan (top100 + banner)..."
  "$ARSENAL/pscan" -t "$TARGET_IP" --top100 --banner --json \
    > "$OUTDIR/ports.json" 2>/dev/null || true
  OPEN_PORTS=$(python3 -c "
import json, sys
try:
  data = json.load(open('$OUTDIR/ports.json'))
  ports = [str(r['port']) for r in data]
  print(','.join(ports))
except: print('')
" 2>/dev/null)
  [[ -n "$OPEN_PORTS" ]] && found "Open ports: $OPEN_PORTS" || warn "No open ports found"
  info "Port scan saved: $OUTDIR/ports.json"
else
  warn "pscan not built — skipping (run: cargo build --release)"
fi

# ─── 3. Web detection ─────────────────────────────────────────────────────────
hdr "3 · Web Technology Detection"
detect_web() {
  local url="$1"
  info "Probing: $url"
  local resp
  resp=$(curl -sI --max-time 8 -L --user-agent "cysec-arsenal/1.0" "$url" 2>/dev/null) || return

  echo "$resp" > "$OUTDIR/http_headers_$(echo $url | tr ':/' '_').txt"

  # Server
  local server
  server=$(echo "$resp" | grep -i "^server:" | head -1 | awk '{print $2}')
  [[ -n "$server" ]] && found "Server header : $server"

  # X-Powered-By
  local powered
  powered=$(echo "$resp" | grep -i "^x-powered-by:" | head -1)
  [[ -n "$powered" ]] && found "Tech stack    : $powered"

  # CMS hints
  for hint in WordPress Drupal Joomla Laravel Django Flask Rails; do
    echo "$resp" | grep -qi "$hint" && found "CMS/Framework : $hint"
  done

  # Security headers
  for hdr_name in "Strict-Transport-Security" "Content-Security-Policy" \
                  "X-Frame-Options" "X-XSS-Protection"; do
    echo "$resp" | grep -qi "^$hdr_name" \
      && ok  "Security header present: $hdr_name" \
      || warn "Missing security header: $hdr_name"
  done
}

# Check HTTP/HTTPS
for port in 80 443 8080 8443; do
  proto="http"; [[ $port == 443 || $port == 8443 ]] && proto="https"
  echo "$OPEN_PORTS" | grep -q "$port" 2>/dev/null && detect_web "${proto}://${TARGET}:${port}"
done
# Always probe 80/443 regardless
detect_web "http://$TARGET"
detect_web "https://$TARGET"

# ─── 4. Subdomain enum ────────────────────────────────────────────────────────
if [[ $IP_ONLY -eq 0 ]]; then
  hdr "4 · Subdomain Enumeration"
  if [[ -x "$ARSENAL/subenum" ]]; then
    info "Running subenum (passive crt.sh)..."
    "$ARSENAL/subenum" -d "$TARGET" --passive --json \
      > "$OUTDIR/subdomains.json" 2>/dev/null || true
    SUB_COUNT=$(python3 -c "import json; d=json.load(open('$OUTDIR/subdomains.json')); print(len(d))" 2>/dev/null || echo 0)
    found "$SUB_COUNT subdomain(s) discovered"
    info "Saved: $OUTDIR/subdomains.json"
  else
    warn "subenum not built — skipping"
  fi
fi

# ─── 5. OSINT harvest ─────────────────────────────────────────────────────────
if [[ $FULL -eq 1 ]]; then
  hdr "5 · OSINT Harvest"
  if [[ -x "$ARSENAL/osint" ]]; then
    "$ARSENAL/osint" -d "$TARGET" --no-whois --json \
      > "$OUTDIR/osint.json" 2>/dev/null || true
    ok "OSINT data saved: $OUTDIR/osint.json"
  fi
fi

# ─── 6. Report ───────────────────────────────────────────────────────────────
hdr "6 · Summary Report"
REPORT="$OUTDIR/report.md"
cat > "$REPORT" <<MDEOF
# Recon Report: $TARGET
**Date:** $(date)
**Arsenal:** NuRichter CySec Arsenal

## IP / Hostnames
- Target: \`$TARGET\`
- Resolved IP: \`$TARGET_IP\`

## Open Ports
\`\`\`
$(cat "$OUTDIR/ports.json" 2>/dev/null | python3 -c "
import json,sys
try:
  data=json.load(sys.stdin)
  for r in data: print(f\"{r['port']:>5}/tcp  {r['service']}\")
except: print('(no data)')
")
\`\`\`

## Subdomains
$(cat "$OUTDIR/subdomains.json" 2>/dev/null | python3 -c "
import json,sys
try:
  data=json.load(sys.stdin)
  print('\n'.join(f'- \`{r[\"fqdn\"]}\`' for r in data[:20]))
except: print('- (none / not run)')
")

## Notes
- [ ] Manual web enumeration (Burp, gobuster)
- [ ] Check for default credentials
- [ ] Look for version-specific CVEs on open services
MDEOF

ok "Report written: $REPORT"
info "All output in: $OUTDIR/"
echo ""
