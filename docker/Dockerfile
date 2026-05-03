# docker/Dockerfile — CySec Arsenal Lab Container
# NuRichter · CySec Arsenal
#
# Based on Kali Linux Rolling for full tool availability.
#
# Build:
#   docker build -t cysec-arsenal -f docker/Dockerfile .
#
# Run:
#   docker run -it --rm cysec-arsenal bash

FROM kalilinux/kali-rolling:latest

LABEL maintainer="NuRichter <nurichter-workspace.vercel.app>"
LABEL description="CySec Arsenal — CTF & Security Research Toolkit"
LABEL org.opencontainers.image.source="https://github.com/NuRichter/cysec-arsenal"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV RUST_LOG=info
ENV PATH="/root/.cargo/bin:/arsenal/target/release:$PATH"

# ── System packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools
    build-essential gcc gdb curl wget git \
    # Python
    python3 python3-pip \
    # Network tools
    nmap netcat-openbsd \
    # Forensics
    binwalk exiftool file xxd \
    # General utilities
    tmux vim less jq \
    libssl-dev pkg-config \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Rust toolchain ────────────────────────────────────────────────────────────
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal \
    && . "$HOME/.cargo/env"

# ── Copy source ───────────────────────────────────────────────────────────────
WORKDIR /arsenal
COPY . .

# ── Build Rust workspace ──────────────────────────────────────────────────────
RUN . "$HOME/.cargo/env" \
    && cargo build --release --workspace \
    && strip target/release/pscan target/release/subenum \
              target/release/wfuzz target/release/hcrack \
              target/release/cipher target/release/fcarve \
              target/release/osint  target/release/netmon \
              target/release/ropx   target/release/dbust \
    2>/dev/null || true

# ── Build C tools ─────────────────────────────────────────────────────────────
RUN make -C c all 2>/dev/null || true

# ── Python dependencies ───────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir requests Pillow pwntools 2>/dev/null || true

# ── Setup workspace ───────────────────────────────────────────────────────────
RUN mkdir -p logs output wordlists/{subdomains,passwords,dirs,params}

# ── Entrypoint ────────────────────────────────────────────────────────────────
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
