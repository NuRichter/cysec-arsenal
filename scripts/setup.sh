#!/usr/bin/env bash
# scripts/setup.sh — Bootstrap CySec Arsenal full environment
# NuRichter · CySec Arsenal
#
# Installs: Rust toolchain, Python deps, C compiler, optional apt tools
# Usage: ./scripts/setup.sh [--skip-apt] [--skip-rust] [--skip-python]

set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; CYN='\033[0;36m'
YLW='\033[0;33m'; DIM='\033[2m'; RST='\033[0m'

SKIP_APT=0; SKIP_RUST=0; SKIP_PYTHON=0

for arg in "$@"; do
  case $arg in
    --skip-apt)    SKIP_APT=1    ;;
    --skip-rust)   SKIP_RUST=1   ;;
    --skip-python) SKIP_PYTHON=1 ;;
  esac
done

banner() {
  echo -e "${RED}"
  echo "  ██████╗██╗   ██╗███████╗███████╗ ██████╗"
  echo " ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝██╔════╝"
  echo " ██║      ╚████╔╝ ███████╗█████╗  ██║     "
  echo " ╚██████╗   ██║   ███████║███████╗╚██████╗"
  echo "  ╚═════╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝"
  echo -e "${RST}${DIM}  Setup Script v2.0 — NuRichter Workspace${RST}\n"
}

ok()   { echo -e "  ${GRN}[+]${RST} $*"; }
info() { echo -e "  ${CYN}[*]${RST} $*"; }
warn() { echo -e "  ${YLW}[!]${RST} $*"; }
err()  { echo -e "  ${RED}[-]${RST} $*"; }
step() { echo -e "\n  ${CYN}── $* ──${RST}"; }

banner

# ─── OS detection ────────────────────────────────────────────────────────────
OS="unknown"
if   [[ -f /etc/debian_version ]]; then OS="debian"
elif [[ -f /etc/arch-release ]];   then OS="arch"
elif [[ "$(uname)" == "Darwin" ]]; then OS="macos"
fi
info "OS: $OS  |  Arch: $(uname -m)"

# ─── System packages ─────────────────────────────────────────────────────────
if [[ $SKIP_APT -eq 0 && "$OS" == "debian" ]]; then
  step "System packages"
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends \
    build-essential gcc gdb \
    git curl wget \
    nmap netcat-openbsd \
    python3 python3-pip python3-venv \
    binutils file xxd \
    libssl-dev pkg-config \
    2>/dev/null || true
  ok "System packages installed"
fi

# ─── Rust toolchain ──────────────────────────────────────────────────────────
if [[ $SKIP_RUST -eq 0 ]]; then
  step "Rust toolchain"
  if ! command -v rustc &>/dev/null; then
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
    ok "Rust $(rustc --version) installed"
  else
    ok "Rust already installed: $(rustc --version)"
  fi

  info "Updating toolchain..."
  rustup update stable --no-self-update 2>/dev/null || true
  ok "Toolchain up to date"
fi

# ─── Build Rust crates ───────────────────────────────────────────────────────
if command -v cargo &>/dev/null; then
  step "Building Rust Arsenal binaries"
  # Source cargo env in case it was just installed
  [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

  info "Compiling all crates (release build)..."
  cargo build --release --workspace 2>&1 | tail -5

  BINS=(pscan subenum wfuzz hcrack sqliprobe lfiprobe xssprobe cipher fcarve osint netmon ropx dbust)
  for bin in "${BINS[@]}"; do
    if [[ -f "target/release/$bin" ]]; then
      ok "Built: $bin"
    else
      warn "Not found: $bin (compile may have failed)"
    fi
  done

  info "Binaries in: $(pwd)/target/release/"
fi

# ─── Build C tools ───────────────────────────────────────────────────────────
if command -v gcc &>/dev/null; then
  step "Building C tools"
  pushd c >/dev/null
  make all 2>&1 | grep -E "Built:|Error" || true
  make vuln 2>&1 | grep -E "Built:|Error" || true
  popd >/dev/null
  ok "C tools in: c/bin/"
fi

# ─── Python environment ──────────────────────────────────────────────────────
if [[ $SKIP_PYTHON -eq 0 ]]; then
  step "Python environment"
  if [[ ! -d ".venv" ]]; then
    python3 -m venv .venv
    ok "Virtualenv created at .venv/"
  fi
  source .venv/bin/activate
  pip install --upgrade pip -q
  pip install requests Pillow pwntools -q 2>/dev/null || true
  ok "Python deps installed"
fi

# ─── Directory setup ─────────────────────────────────────────────────────────
mkdir -p logs wordlists/{subdomains,passwords,dirs,params} output/{recon,web,pwn,crypto}

# ─── Done ─────────────────────────────────────────────────────────────────────
step "Setup complete"
echo ""
echo -e "  ${GRN}Quick start:${RST}"
echo "    source .venv/bin/activate       # Python env"
echo "    source ~/.cargo/env             # Rust env"
echo "    ./target/release/pscan -t 127.0.0.1 --top100"
echo "    ./target/release/subenum -d example.com"
echo "    ./c/bin/hexdump ./c/bin/bof_demo"
echo ""
echo -e "  ${DIM}Docs: docs/methodology.md | docs/cheatsheet.md${RST}"
echo ""
