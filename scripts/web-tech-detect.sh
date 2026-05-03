#!/usr/bin/env bash
# scripts/web-tech-detect.sh — Detect web server / CMS / framework
# NuRichter · CySec Arsenal
set -euo pipefail
URL="${1:-}"; [[ -z "$URL" ]] && { echo "Usage: $0 <url>"; exit 1; }
GRN='\033[0;32m'; CYN='\033[0;36m'; MAG='\033[0;35m'; RST='\033[0m'
found() { echo -e "  ${MAG}[>]${RST} $*"; }
info()  { echo -e "  ${CYN}[*]${RST} $*"; }
ok()    { echo -e "  ${GRN}[+]${RST} $*"; }

echo -e "\n${CYN}  ── Web Tech Detection: $URL ──${RST}\n"
UA="Mozilla/5.0 (cysec-arsenal/1.0)"
HEADERS=$(curl -sIL --max-time 10 -A "$UA" --insecure "$URL" 2>/dev/null)
BODY=$(curl -sL --max-time 10 -A "$UA" --insecure "$URL" 2>/dev/null | head -300)

info "Headers:"
for h in Server X-Powered-By X-Generator X-Drupal-Cache X-Wordpress-Cache \
         X-Framework X-AspNet-Version X-AspNetMvc-Version; do
  val=$(echo "$HEADERS" | grep -i "^$h:" | cut -d: -f2- | tr -d '\r')
  [[ -n "$val" ]] && found "$h:$val"
done

info "Body fingerprints:"
declare -A SIGS=(
  ["WordPress"]="wp-content|wp-includes|wordpress"
  ["Drupal"]="drupal|sites/default/files"
  ["Joomla"]="joomla|/components/com_"
  ["Laravel"]="laravel_session|/vendor/laravel"
  ["Django"]="csrfmiddlewaretoken|django"
  ["Flask"]="__flask|werkzeug"
  ["Express.js"]="express|x-powered-by: express"
  ["React"]="react-root|__react|reactDOM"
  ["Vue.js"]="__vue|v-app|vue-app"
  ["Angular"]="ng-version|angular.js"
  ["Next.js"]="__NEXT_DATA__|_next/static"
  ["phpMyAdmin"]="phpmyadmin|PMA_token"
  ["Grafana"]="grafana|g-app"
)
for name in "${!SIGS[@]}"; do
  pattern="${SIGS[$name]}"
  (echo "$BODY$HEADERS" | grep -qiE "$pattern") && found "Detected: $name"
done

info "Security headers:"
for h in Strict-Transport-Security Content-Security-Policy X-Frame-Options \
         X-Content-Type-Options Referrer-Policy; do
  echo "$HEADERS" | grep -qi "^$h:" \
    && ok  "Present: $h" \
    || echo -e "  \033[33m[!]\033[0m Missing: $h"
done
echo ""
ok "Done."
