# CySec Arsenal — Quick Reference Cheatsheet
**NuRichter · CySec Arsenal**

---

## Arsenal Binaries

```bash
# Port scan — top100 + banner
./target/release/pscan -t 10.10.10.5 --top100 --banner

# Port scan — full range
./target/release/pscan -t 10.10.10.5 -p 1-65535 --concurrency 1000

# Subdomain enum — passive (crt.sh)
./target/release/subenum -d example.com --passive

# Subdomain enum — active brute
./target/release/subenum -d example.com -w wordlists/subdomains/top5000.txt

# Web fuzzer — directory discovery
./target/release/wfuzz -u http://target/FUZZ -w wordlists/dirs/common.txt

# Web fuzzer — parameter fuzzing
./target/release/wfuzz -u "http://target/search?q=FUZZ" -w wordlists/fuzz/params.txt

# Hash identify + crack
./target/release/hcrack -H "5f4dcc3b5aa765d61d8327deb882cf99"
./target/release/hcrack -H "..." -w wordlists/passwords/rockyou.txt

# Cipher auto-detect (CTF crypto)
./target/release/cipher auto --text "SGVsbG8gV29ybGQ="
./target/release/cipher brute --text "Khoor Zruog" --top 5

# File carver (CTF forensics)
./target/release/fcarve -f challenge.jpg --out extracted/

# ELF binary analysis
./target/release/ropx checksec ./binary
./target/release/ropx sections ./binary
./target/release/ropx gadgets ./binary --pattern "pop rdi"
./target/release/ropx strings ./binary --interesting-only

# Directory brute force
./target/release/dbust -u http://target -w wordlists/dirs/raft-medium.txt --ext php,html,txt

# OSINT harvest
./target/release/osint -d example.com
./target/release/osint -i 93.184.216.34

# SQLi probe
./target/release/sqliprobe -u "http://target/page?id=1" --level 2

# XSS probe
./target/release/xssprobe -u "http://target/search?q=test" --level 2

# LFI probe
./target/release/lfiprobe -u "http://target/page?file=home" --deep
```

---

## Shell Scripts

```bash
# Full recon pipeline
./scripts/recon-pipeline.sh target.ctf
./scripts/recon-pipeline.sh 10.10.10.x --full

# Initialize CTF workspace
./scripts/ctf-init.sh "HackTheBox2026"

# Web enumeration
./scripts/enum-web.sh http://target.ctf
./scripts/enum-web.sh http://target.ctf --deep

# SMB enumeration
./scripts/enum-smb.sh 10.10.10.40
./scripts/enum-smb.sh 10.10.10.40 --user admin --pass secret

# Linux privilege escalation enumeration
./scripts/privesc-check.sh
./scripts/privesc-check.sh --quiet

# Download wordlists
./scripts/wordlist-fetch.sh
./scripts/wordlist-fetch.sh --minimal

# Technology detection
./scripts/web-tech-detect.sh http://target.ctf

# Passive domain OSINT
./scripts/osint-domain.sh example.com
```

---

## Nmap Quick Reference

```bash
# Fast top-port scan
nmap -sV -sC --top-ports 1000 -T4 target

# Full port scan → then version scan
nmap -p- -T4 --min-rate 5000 target -oN ports.txt
nmap -sV -sC -p <PORTS> target

# SMB scripts
nmap -p 445 --script smb-protocols,smb-vuln-ms17-010 target

# HTTP scripts
nmap -p 80,443 --script http-title,http-methods,http-robots.txt target

# UDP scan (slow, for DNS/SNMP/NFS)
sudo nmap -sU --top-ports 50 -T4 target

# OS detection + version
sudo nmap -O -sV target
```

---

## Web One-liners

```bash
# Curl with useful flags
curl -sIL -A "Mozilla/5.0" --insecure http://target    # headers only
curl -s --insecure http://target/robots.txt             # robots.txt
curl -s -X POST -d "user=admin&pass=admin" http://target/login

# Gobuster dir (if installed)
gobuster dir -u http://target -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html

# ffuf (if installed)
ffuf -u http://target/FUZZ -w wordlist.txt -mc 200,301,302,403
ffuf -u "http://target/api/FUZZ" -w api-endpoints.txt -t 100

# SQLmap (if installed, authorized only)
sqlmap -u "http://target/page?id=1" --batch --level 2

# Find hidden params (arjun)
arjun -u http://target/api/endpoint
```

---

## Linux Quick Commands

```bash
# File search
find / -name "flag*" 2>/dev/null
find / -perm -4000 -type f 2>/dev/null    # SUID
find / -writable -type f 2>/dev/null       # writable files

# Network
ss -tlnp                  # listening ports
netstat -antup            # all connections
ip route                  # routing table

# Process
ps auxf                   # process tree
ls -la /proc/*/exe 2>/dev/null | grep -v Permission   # running exes

# Creds hunting
grep -r "password\|passwd\|secret\|key\|token" /etc /var /opt 2>/dev/null | grep -v Binary

# Hashing
echo -n "text" | md5sum
echo -n "text" | sha256sum

# Base64
echo "SGVsbG8=" | base64 -d
echo "Hello" | base64

# Hex
xxd file.bin | head -20
echo "48656c6c6f" | xxd -r -p
```

---

## CTF Pattern Lookup

| Clue | Try First |
|------|-----------|
| `==` at end of string | Base64 |
| All dots/dashes | Morse code |
| Hex dump `89 50 4E 47` | PNG file |
| Hex dump `FF D8 FF` | JPEG file |
| Hex dump `50 4B 03 04` | ZIP/DOCX |
| Garbled letters, shifted | Caesar / ROT13 |
| Repeating XOR pattern | XOR cipher |
| `$2a$` or `$2b$` | bcrypt |
| `$6$` | SHA-512 Unix |
| 32 hex chars | MD5 |
| 64 hex chars | SHA-256 |
| Looks like base32 | `base32 -d` |

---

## pwntools Snippets

```python
from pwn import *

# Connect
p = process("./binary")           # local
p = remote("host", 1337)          # remote
p = gdb.debug("./binary")         # GDB

# Sending / receiving
p.sendline(b"payload")
p.sendafter(b"prompt:", b"data")
data = p.recvuntil(b">>>")
data = p.recvline()
p.interactive()

# Packing
p64(0xdeadbeef)     # little-endian 8 bytes
p32(0x41414141)     # little-endian 4 bytes
u64(data[:8])       # unpack
flat([addr1, addr2]) # flatten list → bytes

# ELF
elf = ELF("./binary")
elf.symbols["main"]   # address of main
elf.plt["system"]     # PLT entry
elf.got["puts"]       # GOT entry

# ROP
rop = ROP(elf)
rop.find_gadget(["pop rdi", "ret"])[0]
```

---

*NuRichter Workspace · Richterize The Infinity ∞*
