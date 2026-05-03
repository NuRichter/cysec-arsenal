#!/usr/bin/env bash
# scripts/ctf-init.sh — Initialize a structured CTF workspace
# NuRichter · CySec Arsenal
#
# Creates a workspace with categories, templates, and solve stubs.
#
# Usage:
#   ./scripts/ctf-init.sh "HackTheBox2026"
#   ./scripts/ctf-init.sh "PicoCTF" --categories "web pwn crypto forensics misc"

set -euo pipefail

CYN='\033[0;36m'; GRN='\033[0;32m'; YLW='\033[0;33m'; RST='\033[0m'
ok()   { echo -e "  ${GRN}[+]${RST} $*"; }
info() { echo -e "  ${CYN}[*]${RST} $*"; }

CTF_NAME="${1:-CTF_$(date +%Y%m%d)}"
CATEGORIES="web pwn crypto forensics misc osint reversing"

# Parse --categories override
for i in "$@"; do
  if [[ "$i" == "--categories" && -n "${2:-}" ]]; then
    CATEGORIES="$2"; shift 2; break
  fi
done

WORKSPACE="ctf_workspace/${CTF_NAME}"

echo -e "\n${CYN}  ── CySec Arsenal · CTF Init ──${RST}\n"
info "Creating workspace: $WORKSPACE"
info "Categories: $CATEGORIES"

mkdir -p "$WORKSPACE"

# ─── Per-category structure ───────────────────────────────────────────────────
for cat in $CATEGORIES; do
  dir="$WORKSPACE/$cat"
  mkdir -p "$dir"

  # Category README
  cat > "$dir/README.md" <<CATEOF
# $CTF_NAME — $(echo $cat | tr '[:lower:]' '[:upper:]')

## Challenges

| Challenge | Points | Solved | Flag |
|-----------|--------|--------|------|
|           |        | ☐      |      |

## Notes

_Add notes here_
CATEOF

  # Stub solve script based on category
  case "$cat" in
    web)
      cp ctf/templates/template_web.py "$dir/solve.py" 2>/dev/null || \
        echo "# Web solve template — see ctf/templates/template_web.py" > "$dir/solve.py"
      ;;
    pwn)
      cp ctf/templates/template_pwn.py "$dir/solve.py" 2>/dev/null || \
        echo "# Pwn solve template — see ctf/templates/template_pwn.py" > "$dir/solve.py"
      ;;
    crypto)
      cp ctf/templates/template_crypto.py "$dir/solve.py" 2>/dev/null || \
        echo "# Crypto solve template — see ctf/templates/template_crypto.py" > "$dir/solve.py"
      ;;
    *)
      echo "#!/usr/bin/env python3" > "$dir/solve.py"
      echo "# Solve script for $cat challenges" >> "$dir/solve.py"
      ;;
  esac

  ok "Created: $dir/"
done

# ─── Top-level workspace files ────────────────────────────────────────────────
cat > "$WORKSPACE/README.md" <<WEOF
# $CTF_NAME Workspace
**Arsenal:** NuRichter CySec Arsenal
**Date:** $(date +%Y-%m-%d)

## Progress

| Category | Total | Solved | Points |
|----------|-------|--------|--------|
$(for cat in $CATEGORIES; do echo "| $cat | | | |"; done)

## Flags

\`\`\`
# Paste collected flags here
\`\`\`

## Tools Used

- Port scan: \`pscan\`
- Web fuzz:  \`wfuzz\` / \`dbust\`
- Crypto:    \`cipher\` / \`hcrack\`
- Forensics: \`fcarve\`
- Binary:    \`ropx\` / pwntools

## Writeup Links

_Add links after event ends_
WEOF

# ─── Shared resources dir ────────────────────────────────────────────────────
mkdir -p "$WORKSPACE/shared/"{downloads,payloads,notes}
touch "$WORKSPACE/shared/notes/scratch.md"

echo ""
ok "Workspace ready: $WORKSPACE/"
echo ""
echo -e "  ${YLW}Structure:${RST}"
find "$WORKSPACE" -maxdepth 2 | sort | sed 's|[^/]*/|  |g'
echo ""
