#!/usr/bin/env bash
# scripts/wordlist-fetch.sh — Download standard CTF/pentest wordlists
# NuRichter · CySec Arsenal
#
# Downloads: SecLists subsets, rockyou.txt, common dirs/params
# Usage:
#   ./scripts/wordlist-fetch.sh
#   ./scripts/wordlist-fetch.sh --minimal   (small fast set only)

set -euo pipefail

GRN='\033[0;32m'; CYN='\033[0;36m'; YLW='\033[0;33m'; DIM='\033[2m'; RST='\033[0m'
ok()   { echo -e "  ${GRN}[+]${RST} $*"; }
info() { echo -e "  ${CYN}[*]${RST} $*"; }
warn() { echo -e "  ${YLW}[!]${RST} $*"; }

MINIMAL=0
[[ "${1:-}" == "--minimal" ]] && MINIMAL=1

WL="wordlists"
mkdir -p "$WL"/{subdomains,passwords,dirs,params,usernames,fuzz}

echo -e "\n${CYN}  ── Wordlist Fetcher — NuRichter CySec Arsenal ──${RST}\n"

# ─── Helper: download with resume ────────────────────────────────────────────
dl() {
  local url="$1" dest="$2" desc="${3:-}"
  [[ -f "$dest" ]] && { ok "Already exists: $dest"; return; }
  info "Downloading${desc:+: $desc}..."
  curl -sL --max-time 60 -o "$dest" "$url" && ok "Saved: $dest" || warn "Failed: $url"
}

# ─── Subdomains ───────────────────────────────────────────────────────────────
info "Subdomain wordlists..."
dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
   "$WL/subdomains/top5000.txt" "top 5000 subdomains"

dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt" \
   "$WL/subdomains/top100k.txt" "top 100k subdomains"

# ─── Directory brute force ────────────────────────────────────────────────────
info "Directory/file wordlists..."
dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
   "$WL/dirs/common.txt" "common.txt"

dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" \
   "$WL/dirs/raft-medium.txt" "raft medium dirs"

if [[ $MINIMAL -eq 0 ]]; then
  dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt" \
     "$WL/dirs/dirbuster-medium.txt" "dirbuster medium"
fi

# ─── Parameters ──────────────────────────────────────────────────────────────
info "Parameter wordlists..."
dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt" \
   "$WL/params/burp-params.txt" "Burp Suite params"

# ─── Usernames ────────────────────────────────────────────────────────────────
info "Username wordlists..."
dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt" \
   "$WL/usernames/top-short.txt" "top usernames (short)"

# ─── Passwords ────────────────────────────────────────────────────────────────
info "Password wordlists..."
dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt" \
   "$WL/passwords/top10k.txt" "top 10k passwords"

dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/best1050.txt" \
   "$WL/passwords/best1050.txt" "best 1050"

if [[ $MINIMAL -eq 0 ]]; then
  # rockyou is large — optional
  if [[ -f /usr/share/wordlists/rockyou.txt ]]; then
    ln -sf /usr/share/wordlists/rockyou.txt "$WL/passwords/rockyou.txt"
    ok "Linked system rockyou.txt → $WL/passwords/rockyou.txt"
  elif [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
    info "Decompressing system rockyou.txt.gz..."
    gunzip -c /usr/share/wordlists/rockyou.txt.gz > "$WL/passwords/rockyou.txt"
    ok "Saved: $WL/passwords/rockyou.txt"
  else
    warn "rockyou.txt not found — install: apt install wordlists"
  fi
fi

# ─── Fuzzing payloads ─────────────────────────────────────────────────────────
info "Fuzzing payloads..."
dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt" \
   "$WL/fuzz/lfi-paths.txt" "LFI paths"

dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt" \
   "$WL/fuzz/xss-payloads.txt" "XSS payloads"

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
ok "Wordlist download complete."
echo ""
echo "  Directory layout:"
for d in "$WL"/*/; do
  count=$(find "$d" -type f | wc -l)
  echo -e "  ${DIM}$(printf '%-30s' "$d") ${count} file(s)${RST}"
done
echo ""
