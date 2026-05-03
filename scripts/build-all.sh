#!/usr/bin/env bash
# scripts/build-all.sh — Build entire arsenal in one shot
# NuRichter · CySec Arsenal
set -euo pipefail
GRN='\033[0;32m'; CYN='\033[0;36m'; YLW='\033[0;33m'; RED='\033[0;31m'; RST='\033[0m'
ok()   { echo -e "  ${GRN}[+]${RST} $*"; }
info() { echo -e "  ${CYN}[*]${RST} $*"; }
warn() { echo -e "  ${YLW}[!]${RST} $*"; }
err()  { echo -e "  ${RED}[-]${RST} $*"; }

echo -e "\n${CYN}  ── Build All — NuRichter CySec Arsenal ──${RST}\n"

# ─── Rust ─────────────────────────────────────────────────────────────────
info "Building Rust workspace (release)..."
if command -v cargo &>/dev/null; then
  cargo build --release --workspace 2>&1 | grep -E "Compiling|Finished|error" | tail -20
  ok "Rust binaries → target/release/"
  for b in pscan subenum wfuzz hcrack sqliprobe lfiprobe xssprobe cipher fcarve osint netmon ropx dbust; do
    [[ -f "target/release/$b" ]] && ok "  ✓ $b" || warn "  ✗ $b (failed)"
  done
else
  warn "cargo not found — skipping Rust build"
fi

# ─── C ────────────────────────────────────────────────────────────────────
info "Building C tools..."
if command -v gcc &>/dev/null; then
  pushd c >/dev/null
  make all 2>&1 | tail -8
  make vuln 2>&1 | tail -8
  popd >/dev/null
  ok "C binaries → c/bin/"
else
  warn "gcc not found — skipping C build"
fi

# ─── Python venv ──────────────────────────────────────────────────────────
info "Setting up Python environment..."
if command -v python3 &>/dev/null; then
  [[ ! -d .venv ]] && python3 -m venv .venv
  source .venv/bin/activate
  pip install -q requests Pillow pwntools 2>/dev/null || true
  ok "Python venv at .venv/"
fi

echo -e "\n  ${GRN}[+] Build complete.${RST}\n"
