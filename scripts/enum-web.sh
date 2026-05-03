#!/usr/bin/env bash
# scripts/enum-web.sh — Web Enumeration Helper
# NuRichter · CySec Arsenal
#
# Quick web recon: robots.txt, common files, headers, tech detection.
# For authorized testing and CTF only.
#
# Usage:
#   ./scripts/enum-web.sh http://target.ctf
#   ./scripts/enum-web.sh http://target.ctf --deep

set -euo pipefail

GRN='\033[0;32m'; CYN='\033[0;36m'; MAG='\033[0;35m'
YLW='\033[0;33m'; RED='\033[0;31m'; DIM='\033[2m'; RST='\033[0m'

URL="${1:-}"
DEEP=0
[[ "${2:-}" == "--deep" ]] && DEEP=1
[[ -z "$URL" ]] && { echo "Usage: $0 <url> [--deep]"; exit 1; }

# Normalize URL
URL="${URL%/}"

ok()    { echo -e "  ${GRN}[+]${RST} $*"; }
info()  { echo -e "  ${CYN}[*]${RST} $*"; }
found() { echo -e "  ${MAG}[>]${RST} $*"; }
warn()  { echo -e "  ${YLW}[!]${RST} $*"; }
err()   { echo -e "  ${RED}[-]${RST} $*"; }
hdr()   { echo -e "\n${CYN}  ── $* ──${RST}"; }

UA="Mozilla/5.0 (cysec-arsenal/1.0 CTF)"
CURL="curl -sL --max-time 8 -A \"$UA\" --insecure"

echo -e "\n${CYN}  ── Web Enumeration: $URL ──${RST}\n"

# ─── 1. HTTP Headers ─────────────────────────────────────────────────────────
hdr "HTTP Headers"
HEADERS=$(curl -sI --max-time 8 -A "$UA" --insecure "$URL" 2>/dev/null) || true
if [[ -n "$HEADERS" ]]; then
  echo "$HEADERS" | while IFS= read -r line; do
    echo -e "  ${DIM}$line${RST}"
  done

  # Interesting headers
  for hname in Server X-Powered-By X-Generator X-Framework Via X-AspNet-Version; do
    val=$(echo "$HEADERS" | grep -i "^$hname:" | head -1 | cut -d: -f2-)
    [[ -n "$val" ]] && found "Tech header: $hname:$val"
  done

  # Security headers
  for sec in Strict-Transport-Security Content-Security-Policy X-Frame-Options \
             X-Content-Type-Options Referrer-Policy Permissions-Policy; do
    echo "$HEADERS" | grep -qi "^$sec:" \
      && ok  "Security header: $sec" \
      || warn "Missing: $sec"
  done
else
  err "Could not reach $URL"
  exit 1
fi

# ─── 2. Common paths ──────────────────────────────────────────────────────────
hdr "Common Path Probe"
PATHS=(
  /robots.txt /sitemap.xml /.git/HEAD /.git/config /.env /.env.local
  /admin /administrator /login /wp-admin /phpmyadmin /console /debug
  /api /api/v1 /graphql /swagger /swagger-ui.html /api-docs /openapi.json
  /backup /backup.zip /backup.sql /.DS_Store /web.config /web.xml
  /server-status /server-info /phpinfo.php /.htaccess
  /flag /flag.txt /secret /secret.txt /.well-known/security.txt
)

for path in "${PATHS[@]}"; do
  status=$(curl -sIo /dev/null -w "%{http_code}" --max-time 5 -A "$UA" --insecure "$URL$path" 2>/dev/null || echo 0)
  case "$status" in
    200|201|204)
      found "[$status] $URL$path"
      # Fetch content for interesting files
      case "$path" in
        /robots.txt|/.env|/.git/HEAD|/flag*|/secret*)
          content=$(curl -s --max-time 5 -A "$UA" --insecure "$URL$path" 2>/dev/null | head -20)
          [[ -n "$content" ]] && echo -e "  ${DIM}$(echo "$content" | head -5)${RST}"
          ;;
      esac
      ;;
    301|302|307|308) ok  "[$status→redirect] $URL$path" ;;
    403)             warn "[403-forbidden] $URL$path" ;;
    401)             warn "[401-auth] $URL$path" ;;
  esac
done

# ─── 3. CMS / Framework Detection ────────────────────────────────────────────
hdr "CMS / Framework Detection"
BODY=$(curl -s --max-time 8 -A "$UA" --insecure "$URL" 2>/dev/null | head -200) || true

for cms in WordPress Drupal Joomla Laravel CodeIgniter Django Flask Rails \
           Express Nginx Apache "IIS" Symfony CakePHP; do
  echo "$BODY$HEADERS" | grep -qi "$cms" && found "Detected: $cms"
done

# JS framework hints
for fw in "react" "vue" "angular" "next.js" "nuxt" "svelte" "jquery"; do
  echo "$BODY" | grep -qi "$fw" && found "JS framework: $fw"
done

# ─── 4. Directory brute (if dbust available) ─────────────────────────────────
if [[ $DEEP -eq 1 ]] && [[ -x "./target/release/dbust" ]]; then
  hdr "Directory Brute Force"
  WL="wordlists/dirs/common.txt"
  if [[ ! -f "$WL" ]]; then
    warn "Wordlist not found: $WL  (run: scripts/wordlist-fetch.sh)"
  else
    ./target/release/dbust -u "$URL" -w "$WL" --ext "php,html,txt,bak" -t 80
  fi
fi

# ─── 5. Cookie analysis ──────────────────────────────────────────────────────
hdr "Cookie Analysis"
COOKIES=$(echo "$HEADERS" | grep -i "set-cookie:" || true)
if [[ -n "$COOKIES" ]]; then
  echo "$COOKIES" | while IFS= read -r line; do
    echo -e "  ${DIM}$line${RST}"
    echo "$line" | grep -qi "httponly" || warn "Cookie missing HttpOnly flag"
    echo "$line" | grep -qi "secure"   || warn "Cookie missing Secure flag"
    echo "$line" | grep -qi "samesite" || warn "Cookie missing SameSite attribute"
  done
else
  info "No Set-Cookie headers"
fi

echo ""
ok "Web enumeration complete."
echo ""
