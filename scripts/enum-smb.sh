#!/usr/bin/env bash
# scripts/enum-smb.sh — SMB Share & User Enumeration
# NuRichter · CySec Arsenal
#
# For authorized penetration testing and CTF labs only.
# Requires: smbclient (apt install smbclient)
#
# Usage:
#   ./scripts/enum-smb.sh 10.10.10.40
#   ./scripts/enum-smb.sh 10.10.10.40 --user admin --pass secret

set -euo pipefail

GRN='\033[0;32m'; CYN='\033[0;36m'; MAG='\033[0;35m'
YLW='\033[0;33m'; RED='\033[0;31m'; DIM='\033[2m'; RST='\033[0m'

TARGET="${1:-}"
SMB_USER="${SMB_USER:-}"
SMB_PASS="${SMB_PASS:-}"

for i in "$@"; do
  [[ "$i" == "--user" ]]  && { SMB_USER="${2:-}"; shift 2 || true; }
  [[ "$i" == "--pass" ]]  && { SMB_PASS="${2:-}"; shift 2 || true; }
done

[[ -z "$TARGET" ]] && { echo "Usage: $0 <ip> [--user USER] [--pass PASS]"; exit 1; }

ok()    { echo -e "  ${GRN}[+]${RST} $*"; }
info()  { echo -e "  ${CYN}[*]${RST} $*"; }
found() { echo -e "  ${MAG}[>]${RST} $*"; }
warn()  { echo -e "  ${YLW}[!]${RST} $*"; }
hdr()   { echo -e "\n${CYN}  ── $* ──${RST}"; }

echo -e "\n${CYN}  ── SMB Enumeration: $TARGET ──${RST}\n"

# ─── Dependency check ────────────────────────────────────────────────────────
for dep in smbclient; do
  command -v $dep &>/dev/null || { warn "$dep not found (apt install smbclient)"; }
done

# ─── 1. SMB port check ────────────────────────────────────────────────────────
hdr "Port Check"
for port in 139 445; do
  nc -zw2 "$TARGET" "$port" 2>/dev/null \
    && found "Port $port/tcp OPEN" \
    || info  "Port $port/tcp closed"
done

# ─── 2. Null session share listing ────────────────────────────────────────────
hdr "Share Enumeration"
info "Trying null session (no credentials)..."
SHARES=$(smbclient -L "//$TARGET" -N 2>/dev/null || true)
if [[ -n "$SHARES" ]]; then
  echo "$SHARES" | grep -E "Disk|IPC|Print" | while IFS= read -r line; do
    echo -e "  ${DIM}$line${RST}"
    # Flag interesting shares
    echo "$line" | grep -iqE "users|home|backup|admin|share|data|files|wwwroot|inetpub|htdocs" \
      && found "Interesting share: $line" || true
  done
else
  warn "Null session failed — trying with credentials..."
  if [[ -n "$SMB_USER" ]]; then
    smbclient -L "//$TARGET" -U "$SMB_USER%$SMB_PASS" 2>/dev/null || true
  fi
fi

# ─── 3. Common share access attempt ──────────────────────────────────────────
hdr "Share Access Test"
for share in C$ ADMIN$ IPC$ SYSVOL NETLOGON Users Backup Data; do
  result=$(smbclient "//$TARGET/$share" -N -c "ls" 2>&1 | head -3 || true)
  if echo "$result" | grep -q "blocks"; then
    found "Readable share: \\\\$TARGET\\$share"
    echo "$result" | head -5 | sed 's/^/    /'
  fi
done

# ─── 4. Authenticated enumeration ─────────────────────────────────────────────
if [[ -n "$SMB_USER" ]]; then
  hdr "Authenticated Enumeration (user: $SMB_USER)"
  info "Listing all shares..."
  smbclient -L "//$TARGET" -U "$SMB_USER%$SMB_PASS" 2>/dev/null \
    | grep -E "Disk|IPC" | sed 's/^/  /' || true
fi

# ─── 5. Common CVE checks ─────────────────────────────────────────────────────
hdr "Known Vulnerability Hints"
info "Check Shodan/NVD for these if SMB version is obtained:"
echo "  EternalBlue (MS17-010) — SMBv1, Windows 7/2008"
echo "  PrintNightmare (CVE-2021-34527) — Windows print spooler"
echo "  SambaCry (CVE-2017-7494) — Samba 3.5.0–4.6.4"
echo ""
info "Detect SMBv1: nmap -p 445 --script smb-protocols $TARGET"
info "Vuln scan:    nmap -p 445 --script smb-vuln-* $TARGET"

echo ""
ok "SMB enumeration complete."
