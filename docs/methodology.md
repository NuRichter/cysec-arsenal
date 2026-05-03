# Red Team & CTF Methodology
**NuRichter · CySec Arsenal**

---

## Engagement Phases

### 1. Reconnaissance
**Goal:** Gather maximum information with minimal footprint.

**Passive (no direct contact):**
- WHOIS, DNS records, certificate transparency (`subenum --passive`)
- Shodan, Censys, GreyNoise for exposed services
- Google Dorking: `site:target.com filetype:pdf`, `inurl:admin`
- Social media / GitHub OSINT

**Active (direct contact):**
- Port scanning (`pscan --top100`, `pscan -p 1-65535`)
- Subdomain brute-force (`subenum -d domain -w wordlist`)
- Web directory discovery (`dbust`, `wfuzz`)

---

### 2. Scanning & Enumeration
**Goal:** Map the attack surface.

```
Service Enumeration:
  FTP   (21)  : Anonymous login, directory traversal
  SSH   (22)  : Version banner, user enumeration
  HTTP  (80)  : Tech stack, endpoints, auth mechanism
  SMB   (445) : Null sessions, share access
  DB    (3306/5432) : Default creds, version exposure

Web Enumeration:
  robots.txt · sitemap.xml · .env · .git/HEAD
  API: /api/v1/ · /swagger · /graphql
  params: arjun, param-miner
```

---

### 3. Vulnerability Analysis

| Vector | Tool | Notes |
|--------|------|-------|
| SQLi | `sqliprobe` | Error → UNION → Blind → Time |
| XSS | `xssprobe` | Reflected → Stored → DOM |
| LFI | `lfiprobe` | /etc/passwd → log poisoning |
| Dir | `dbust`, `wfuzz` | Files, backup, admin paths |
| Hash | `hcrack` | Identify type → dictionary crack |
| Crypto | `cipher auto` | Auto-detect encoding/cipher |
| Binary | `ropx` | checksec → gadgets → exploit chain |

---

### 4. CTF-Specific Approach

```
Binary Exploitation:
  checksec → identify protections → choose technique
  BOF?  → find offset → ROP chain → shell
  Heap? → UAF / double-free / tcache poison

Web:
  Source available? → review code → find sinks
  Black box? → recon → fuzz params → common vulns

Crypto:
  Identify cipher → weak params?
  RSA? → small e, common modulus, factordb
  Symmetric? → ECB mode, IV reuse, padding oracle

Forensics:
  file → strings → binwalk → fcarve → steghide
  pcap? → follow TCP streams → extract files

OSINT:
  Google → social → Shodan → archive.org → metadata
```

---

### 5. Reporting (Pentest Engagements)

**Structure:**
1. Executive Summary
2. Scope & Methodology
3. Findings (Critical → High → Medium → Low → Info)
4. Technical Evidence
5. Remediation Recommendations

**CVSS v3.1** scoring for each finding.

---

## Useful Commands

```bash
# Pattern creation (BOF offset finding)
python3 -c "from pwn import *; print(cyclic(200))"
python3 -c "from pwn import *; print(cyclic_find(0x61616171))"

# Ghidra headless analysis
./analyzeHeadless /tmp/proj MyProj -import binary -postScript PrintASMScript.java

# Volatility3 memory forensics
vol -f memory.dump linux.pslist
vol -f memory.dump linux.bash

# Wireshark filters
tcp.stream eq 0          # first TCP conversation
http.request.method == "POST"
frame contains "password"
```

---

*NuRichter Workspace · Richterize The Infinity ∞*
