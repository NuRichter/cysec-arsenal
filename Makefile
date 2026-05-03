# Makefile — CySec Arsenal Root
# NuRichter · CySec Arsenal
#
# Delegates to cargo (Rust), c/Makefile (C), and Python venv.
#
# Usage:
#   make all       — build everything
#   make rust      — build Rust workspace (release)
#   make c         — build C tools
#   make vuln      — build intentionally-vulnerable C lab targets
#   make check     — cargo check + clippy
#   make test      — run all tests
#   make clean     — clean build artifacts
#   make zip       — create distributable archive

.PHONY: all rust c vuln check test clean zip install help

CARGO       = cargo
CARGO_FLAGS = --workspace --release

all: rust c
	@echo ""
	@echo "  ✓ CySec Arsenal built."
	@echo "  Binaries : target/release/{pscan,subenum,wfuzz,hcrack,cipher,fcarve,osint,ropx,dbust,...}"
	@echo "  C tools  : c/bin/{hexdump,bof_demo,fmt_string,heap_demo}"
	@echo ""

# ─── Rust ────────────────────────────────────────────────────────────────────
rust:
	$(CARGO) build $(CARGO_FLAGS)

check:
	$(CARGO) fmt --all -- --check
	$(CARGO) check --workspace --all-targets
	$(CARGO) clippy --workspace --all-targets -- -D warnings

test:
	$(CARGO) test --workspace --lib 2>/dev/null || true

# ─── C ───────────────────────────────────────────────────────────────────────
c:
	$(MAKE) -C c all

vuln:
	@echo "  [!] Building intentionally-vulnerable lab targets (CTF training only)"
	$(MAKE) -C c vuln

# ─── Misc ─────────────────────────────────────────────────────────────────────
clean:
	$(CARGO) clean
	$(MAKE) -C c clean
	rm -rf output/ logs/ ctf_workspace/
	@echo "  [+] Cleaned."

zip:
	@STAMP=$$(date +%Y%m%d_%H%M%S); \
	NAME="cysec-arsenal-$$STAMP"; \
	zip -r "$$NAME.zip" . \
	  --exclude "target/*" \
	  --exclude ".git/*" \
	  --exclude "*.zip" \
	  --exclude "c/bin/*" \
	  --exclude "output/*" \
	  --exclude "logs/*" \
	  --exclude "wordlists/passwords/rockyou.txt" \
	  --exclude "ctf_workspace/*" \
	  --exclude ".venv/*" \
	  --exclude "__pycache__/*" \
	  --exclude "*.pyc"; \
	echo "  [+] Created: $$NAME.zip"

install:
	@echo "  Installing binaries to /usr/local/bin..."
	@for bin in pscan subenum wfuzz hcrack sqliprobe lfiprobe xssprobe \
	            cipher fcarve osint netmon ropx dbust; do \
	  [ -f "target/release/$$bin" ] && \
	    install -m 755 "target/release/$$bin" "/usr/local/bin/$$bin" && \
	    echo "  [+] $$bin" || echo "  [-] $$bin (not built)"; \
	done
	@install -m 755 c/bin/hexdump /usr/local/bin/hexdump 2>/dev/null && \
	  echo "  [+] hexdump" || true

help:
	@echo ""
	@echo "  CySec Arsenal — Makefile targets"
	@echo ""
	@echo "  make all       Build Rust workspace + C tools (release)"
	@echo "  make rust      Build Rust workspace only"
	@echo "  make c         Build C hardened tools"
	@echo "  make vuln      Build intentionally-vulnerable C training targets"
	@echo "  make check     Run cargo fmt / check / clippy"
	@echo "  make test      Run Rust unit tests"
	@echo "  make clean     Remove all build artifacts"
	@echo "  make zip       Create distributable .zip archive"
	@echo "  make install   Install release binaries to /usr/local/bin"
	@echo ""
