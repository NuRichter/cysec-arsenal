# ☠ CySec Arsenal — Rust Edition

> *"I break into systems to understand them. I build systems so others don't have to guess."*
> — NuRichter

[![Rust](https://img.shields.io/badge/Rust-2021-1E1432?style=for-the-badge&logo=rust&logoColor=C73E3A)](https://rust-lang.org)
[![C](https://img.shields.io/badge/C-C11-1E1432?style=for-the-badge&logo=c&logoColor=C0A0E8)](https://gcc.gnu.org)
[![Shell](https://img.shields.io/badge/Shell-Bash5-1E1432?style=for-the-badge&logo=gnu-bash&logoColor=C0A0E8)](https://gnu.org/software/bash)
[![Python](https://img.shields.io/badge/Python-3.11+-1E1432?style=for-the-badge&logo=python&logoColor=C73E3A)](https://python.org)
[![CTF](https://img.shields.io/badge/CTF-Ready-1E1432?style=for-the-badge&logo=hackthebox&logoColor=C0A0E8)](https://ctftime.org)

A modular, research-grade cybersecurity toolkit built primarily in **Rust** for maximum performance.
Part of the **NuRichter Workspace** ecosystem.

---

## ⚠ Disclaimer

> This toolkit is intended **strictly for educational purposes**, authorized penetration testing,
> and Capture The Flag (CTF) competitions. Usage against systems without explicit written
> permission is illegal and unethical. The author assumes no responsibility for misuse.

---

## 🗂 Structure

```
cysec-arsenal/
│
├── rust/                     # ── Core tools (Rust, ~70% of codebase)
│   ├── arsenal-core/         #    Shared lib: colors, banner, logging, types
│   ├── port-scanner/         #    pscan  — Async TCP scanner + banner grab
│   ├── subdomain-enum/       #    subenum — crt.sh + DNS brute force
│   ├── web-fuzzer/           #    wfuzz  — HTTP path/param fuzzer (FUZZ marker)
│   ├── hash-cracker/         #    hcrack — Identify + parallel dictionary crack
│   ├── sqli-probe/           #    sqliprobe — Error/boolean/time SQLi detection
│   ├── lfi-probe/            #    lfiprobe — Path traversal + LFI confirmation
│   ├── xss-probe/            #    xssprobe — Reflected XSS + context detection
│   ├── cipher-tools/         #    cipher — Caesar/Vigenere/XOR/Morse/auto-detect
│   ├── file-carver/          #    fcarve — Signature-based binary file carver
│   ├── osint-harvest/        #    osint  — crt.sh + ip-api + Shodan InternetDB
│   ├── net-monitor/          #    netmon — /proc/net connection tracker
│   ├── rop-analyzer/         #    ropx   — ELF checksec + gadget search + hexdump
│   └── dir-buster/           #    dbust  — Async HTTP directory brute-forcer
│
├── c/                        # ── Low-level tools (C, ~15%)
│   ├── shellcode_runner/     #    RWX shellcode executor (lab only)
│   ├── bof_demo/             #    Stack BOF training target (intentionally vuln)
│   ├── fmt_string/           #    Format string training target (intentionally vuln)
│   ├── hexdump/              #    Portable coloured hexdump utility
│   ├── heap_demo/            #    Heap UAF/double-free demo (intentionally vuln)
│   └── Makefile
│
├── scripts/                  # ── Automation (Bash, ~15%)
│   ├── setup.sh              #    Bootstrap full environment
│   ├── build-all.sh          #    Build Rust + C in one shot
│   ├── recon-pipeline.sh     #    Automated recon: portscan → subdomain → web
│   ├── ctf-init.sh           #    Initialize structured CTF workspace
│   ├── scan-full.sh          #    Full port range scan + nmap service detect
│   ├── enum-web.sh           #    Web headers / paths / cookies / CMS detection
│   ├── enum-smb.sh           #    SMB share + null session enumeration
│   ├── privesc-check.sh      #    Linux privesc vector enumeration
│   ├── osint-domain.sh       #    Passive OSINT: crt.sh + DNS + WHOIS + Shodan
│   ├── wordlist-fetch.sh     #    Download SecLists subsets
│   ├── web-tech-detect.sh    #    Technology fingerprinting
│   ├── revshell-ref.sh       #    Reverse shell payload reference (CTF)
│   ├── port-knock.sh         #    Port knocking client
│   └── scan-full.sh          #    Multi-phase port scan
│
├── python/                   # ── Utilities (Python, ~5%)
│   ├── decode_all.py         #    Multi-encoding brute decoder
│   └── hash_id.py            #    Hash type identifier
│
├── ctf/
│   ├── templates/            #    Ready-to-use CTF solve templates
│   │   ├── template_pwn.py
│   │   ├── template_web.py
│   │   ├── template_crypto.py
│   │   └── template_forensics.py
│   └── writeups/
│
├── docker/
│   ├── Dockerfile            #    Kali-based container
│   └── docker-compose.yml    #    Lab stack: arsenal + DVWA + JuiceShop
│
├── docs/
│   ├── methodology.md        #    Red team & CTF methodology
│   ├── resources.md          #    Tools, platforms, cheatsheets
│   └── cheatsheet.md         #    One-liner quick reference
│
└── .github/workflows/
    ├── ci.yml                #    Lint + cargo check + bandit
    └── release.yml           #    Cross-compile release binaries
```

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/NuRichter/cysec-arsenal.git
cd cysec-arsenal

# Bootstrap (installs Rust, builds everything)
chmod +x scripts/setup.sh && ./scripts/setup.sh

# Or manual build
cargo build --release --workspace
make -C c all vuln

# Run tools
./target/release/pscan -t 10.10.10.1 --top100 --banner
./target/release/subenum -d example.com
./target/release/hcrack -H "5f4dcc3b5aa765d61d8327deb882cf99" -w wordlists/passwords/rockyou.txt
./target/release/cipher auto --text "SGVsbG8h"
./target/release/fcarve -f challenge.jpg --out extracted/
./target/release/ropx checksec ./c/bin/bof_demo
```

---

## ⚡ Binary Reference

| Binary | Crate | Description |
|--------|-------|-------------|
| `pscan` | port-scanner | Async TCP scanner, banner grab, CIDR sweep |
| `subenum` | subdomain-enum | crt.sh passive + DNS brute force |
| `wfuzz` | web-fuzzer | FUZZ placeholder HTTP fuzzer |
| `hcrack` | hash-cracker | Multi-algo hash ID + parallel dict crack |
| `sqliprobe` | sqli-probe | Error / time-based SQLi detection |
| `lfiprobe` | lfi-probe | Path traversal + LFI confirmation |
| `xssprobe` | xss-probe | Reflected XSS + execution context |
| `cipher` | cipher-tools | Classic cipher encode/decode + auto |
| `fcarve` | file-carver | Binary file signature carving |
| `osint` | osint-harvest | Passive OSINT aggregator |
| `netmon` | net-monitor | /proc/net connection monitor |
| `ropx` | rop-analyzer | ELF checksec + ROP gadget search |
| `dbust` | dir-buster | Async HTTP dir/file brute-forcer |

---

## 🐳 Docker Lab

```bash
# Full lab stack (Arsenal + DVWA + JuiceShop + payload server)
docker-compose -f docker/docker-compose.yml up -d
docker-compose exec arsenal bash
```

Targets:
- DVWA (vulnerable web app): `http://localhost:8080`
- OWASP Juice Shop: `http://localhost:3000`
- Payload server: `http://localhost:8888`

---

## 🌐 NuRichter Workspace

```
NuRichter Labs · Surabaya, Indonesia
Richterize The Infinity ∞
```

[![Workspace](https://img.shields.io/badge/⚡_nurichter--workspace-C73E3A?style=for-the-badge&labelColor=1E1432)](https://nurichter-workspace.vercel.app)
