#!/usr/bin/env bash
# scripts/osint-domain.sh — Passive OSINT for a domain (no active probing)
# NuRichter · CySec Arsenal
set -euo pipefail
GRN='\033[0;32m'; CYN='\033[0;36m'; MAG='\033[0;35m'; YLW='\033[0;33m'; RST='\033[0m'
DOMAIN="${1:-}"; [[ -z "$DOMAIN" ]] && { echo "Usage: $0 <domain>"; exit 1; }
ok()    { echo -e "  ${GRN}[+]${RST} $*"; }
info()  { echo -e "  ${CYN}[*]${RST} $*"; }
found() { echo -e "  ${MAG}[>]${RST} $*"; }
warn()  { echo -e "  ${YLW}[!]${RST} $*"; }
hdr()   { echo -e "\n${CYN}  ── $* ──${RST}"; }
get()   { curl -sL --max-time 15 -A "cysec-arsenal/1.0" "$1" 2>/dev/null; }

echo -e "\n${CYN}  ── Passive OSINT: $DOMAIN ──${RST}\n"
OUTDIR="output/osint_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$OUTDIR"

# crt.sh
hdr "Certificate Transparency (crt.sh)"
get "https://crt.sh/?q=%.${DOMAIN}&output=json" > "$OUTDIR/crt.json"
python3 - <<PY
import json, sys
try:
  data = json.load(open("$OUTDIR/crt.json"))
  names = sorted({e.get("name_value","").strip().lstrip("*.").lower()
                  for e in data if "$DOMAIN" in e.get("name_value","")})
  print(f"  crt.sh: {len(names)} names")
  for n in names[:30]: print(f"  \033[35m[>]\033[0m {n}")
  if len(names)>30: print(f"  ... and {len(names)-30} more")
except Exception as e: print(f"  Parse error: {e}")
PY

# DNS records
hdr "DNS Records"
for rtype in A AAAA MX NS TXT CNAME SOA; do
  result=$(dig +short "$DOMAIN" "$rtype" 2>/dev/null || true)
  [[ -n "$result" ]] && { echo "  $rtype:"; echo "$result" | sed 's/^/    /'; }
done | tee "$OUTDIR/dns.txt"

# WHOIS
hdr "WHOIS"
whois "$DOMAIN" 2>/dev/null | grep -iE "registrar|creation|expir|name server|status" \
  | head -20 | tee "$OUTDIR/whois.txt" || warn "whois not available"

# Shodan InternetDB
hdr "Shodan InternetDB"
IP=$(dig +short "$DOMAIN" A 2>/dev/null | head -1)
if [[ -n "$IP" ]]; then
  info "IP: $IP"
  get "https://internetdb.shodan.io/$IP" | python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  print(f\"  Ports: {d.get('ports','')}\")
  print(f\"  Vulns: {d.get('vulns','')}\")
  print(f\"  Tags : {d.get('tags','')}\")
except: print('  No data')
"
fi

ok "OSINT complete → $OUTDIR/"
