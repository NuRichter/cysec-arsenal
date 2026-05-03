#!/usr/bin/env bash
# scripts/privesc-check.sh — Linux Privilege Escalation Enumeration
# NuRichter · CySec Arsenal
#
# Checks for common privesc vectors in CTF boxes and authorized pentest engagements.
# Run as low-privilege user to enumerate escalation paths.
#
# Usage:
#   ./scripts/privesc-check.sh
#   ./scripts/privesc-check.sh --quiet    (findings only)

set -euo pipefail

GRN='\033[0;32m'; CYN='\033[0;36m'; MAG='\033[0;35m'
YLW='\033[0;33m'; RED='\033[0;31m'; DIM='\033[2m'; RST='\033[0m'

QUIET=0
[[ "${1:-}" == "--quiet" ]] && QUIET=1

ok()    { echo -e "  ${GRN}[+]${RST} $*"; }
info()  { [[ $QUIET -eq 0 ]] && echo -e "  ${CYN}[*]${RST} $*" || true; }
found() { echo -e "  ${MAG}[>]${RST} $*"; }
warn()  { echo -e "  ${YLW}[!]${RST} $*"; }
hdr()   { [[ $QUIET -eq 0 ]] && echo -e "\n${CYN}  ── $* ──${RST}" || true; }

echo -e "\n  ${RED}[!] privesc-check — FOR AUTHORIZED CTF/PENTEST USE ONLY${RST}\n"
info "User: $(id)"
info "Host: $(hostname)"
info "OS:   $(uname -a)"
echo ""

# ─── 1. Sudo permissions ──────────────────────────────────────────────────────
hdr "Sudo Permissions"
SUDO_OUT=$(sudo -l 2>/dev/null || echo "sudo: not available or needs password")
echo "$SUDO_OUT" | while IFS= read -r line; do
  echo -e "  ${DIM}$line${RST}"
  echo "$line" | grep -qiE "(ALL|NOPASSWD)" && found "Potential sudo vector: $line" || true
done

# ─── 2. SUID / SGID binaries ──────────────────────────────────────────────────
hdr "SUID / SGID Binaries"
SUID=$(find / -perm -4000 -type f 2>/dev/null | sort)
GTFO_BINS=(bash sh python python3 perl ruby php vim vi nano nmap find awk
           less more man wget curl tee cp mv tar zip gzip nohup strace
           env time watch socat nc netcat dd ld.so node lua lua5.1 lua5.3
           git ftp irb gimp ksh csh zsh tcsh)

while IFS= read -r bin; do
  base=$(basename "$bin")
  for gtfo in "${GTFO_BINS[@]}"; do
    [[ "$base" == "$gtfo" ]] && found "SUID GTFOBin: $bin  → gtfobins.github.io/$gtfo" && break
  done
  [[ $QUIET -eq 0 ]] && echo -e "  ${DIM}$bin${RST}" || true
done <<< "$SUID"

# ─── 3. Writable paths in $PATH ───────────────────────────────────────────────
hdr "Writable Directories in PATH"
IFS=':' read -ra PATH_DIRS <<< "$PATH"
for dir in "${PATH_DIRS[@]}"; do
  [[ -d "$dir" ]] && [[ -w "$dir" ]] && found "Writable PATH dir: $dir  (PATH hijack possible)"
done

# ─── 4. Cron jobs ─────────────────────────────────────────────────────────────
hdr "Cron Jobs"
for cron_loc in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
  [[ -f "$cron_loc" ]] && [[ -r "$cron_loc" ]] && {
    info "Cron file: $cron_loc"
    cat "$cron_loc" | grep -vE "^#|^$" | while IFS= read -r line; do
      echo -e "  ${DIM}$line${RST}"
      # Check if cron script is writable
      script_path=$(echo "$line" | awk '{print $NF}' | grep "^/")
      [[ -n "$script_path" ]] && [[ -w "$script_path" ]] \
        && found "WRITABLE cron script: $script_path" || true
    done
  }
done

# ─── 5. Writable /etc/passwd / shadow ────────────────────────────────────────
hdr "Critical File Permissions"
for f in /etc/passwd /etc/shadow /etc/sudoers; do
  [[ -f "$f" ]] && {
    [[ -w "$f" ]] && found "WRITABLE: $f  ← critical!" \
      || info "  $f: $(ls -la "$f" | awk '{print $1, $3, $4}')"
  }
done

# ─── 6. Running processes & services ─────────────────────────────────────────
hdr "Interesting Processes"
ps aux 2>/dev/null | grep -E "root|mysql|postgres|redis|mongo|elastic" \
  | grep -v grep | while IFS= read -r line; do
  echo -e "  ${DIM}$line${RST}"
done

# ─── 7. Network services (localhost only) ─────────────────────────────────────
hdr "Localhost-Only Services"
ss -tlnp 2>/dev/null | grep "127.0.0.1\|::1" | while IFS= read -r line; do
  found "Localhost service: $line"
done

# ─── 8. Kernel version ────────────────────────────────────────────────────────
hdr "Kernel"
KVER=$(uname -r)
info "Kernel: $KVER"
info "Check: https://www.kernel-exploits.com/?version=$KVER"

# ─── 9. Capabilities ──────────────────────────────────────────────────────────
hdr "Capabilities (cap_setuid / cap_sys_admin)"
getcap -r / 2>/dev/null | grep -E "cap_setuid|cap_sys_admin|cap_net_raw|cap_dac" \
  | while IFS= read -r line; do
  found "Interesting capability: $line"
done

# ─── 10. Sensitive files ──────────────────────────────────────────────────────
hdr "Sensitive Files"
for f in \
  ~/.bash_history ~/.zsh_history ~/.python_history \
  ~/.ssh/id_rsa ~/.ssh/id_ed25519 ~/.ssh/authorized_keys \
  /var/www/html/.env /opt/*/.env \
  /root/flag.txt /home/*/user.txt /home/*/flag.txt; do
  [[ -f "$f" ]] && [[ -r "$f" ]] && found "Readable: $f"
done

echo ""
ok "Privesc check complete. Review findings above."
info "Reference: https://gtfobins.github.io"
echo ""
