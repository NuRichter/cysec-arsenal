# Resources & References
**NuRichter · CySec Arsenal**

---

## Learning Platforms

| Platform | Type | URL |
|----------|------|-----|
| HackTheBox | Labs, CTF | hackthebox.com |
| TryHackMe | Guided rooms | tryhackme.com |
| PicoCTF | Beginner CTF | picoctf.org |
| CTFtime | CTF calendar | ctftime.org |
| pwn.college | Binary exploitation | pwn.college |
| PortSwigger Web Security Academy | Web security | portswigger.net/web-security |
| CryptoHack | Cryptography | cryptohack.org |
| exploit.education | Binary challenges | exploit.education |
| Nightmare | Pwn course | guyinatuxedo.github.io |

---

## Tool Reference

### Reconnaissance
- **Nmap** — Port scanner, scripting engine
- **Masscan** — High-speed port scanner
- **Subfinder** — Passive subdomain discovery
- **theHarvester** — Email, domain, host OSINT
- **Shodan CLI** — `shodan host <ip>`
- **Amass** — Attack surface mapping

### Web Testing
- **Burp Suite Community** — Proxy, intruder, scanner
- **OWASP ZAP** — Open-source web scanner
- **SQLMap** — Automated SQL injection (authorized use)
- **Nikto** — Web server vulnerability scanner
- **Nuclei** — Template-based scanner

### Binary Analysis & Exploitation
- **pwntools** — CTF framework: `pip install pwntools`
- **GDB + pwndbg** — Debugger with CTF extensions
- **Ghidra** — Reverse engineering (NSA, free)
- **Radare2** — RE framework
- **ROPgadget** — ROP chain gadget finder: `pip install ropgadget`
- **checksec** — Binary protection checker: `apt install checksec`
- **patchelf** — ELF binary patcher

### Forensics & Steganography
- **Volatility3** — Memory forensics: `pip install volatility3`
- **Autopsy** — Digital forensics platform
- **Wireshark** — Packet capture and analysis
- **binwalk** — Firmware / embedded file extraction: `apt install binwalk`
- **steghide** — Steganography embed/extract: `apt install steghide`
- **zsteg** — PNG/BMP steganography: `gem install zsteg`
- **exiftool** — Metadata extraction: `apt install libimage-exiftool-perl`

### Cryptography
- **hashcat** — GPU hash cracking: `apt install hashcat`
- **John the Ripper** — Classic password cracker: `apt install john`
- **CyberChef** — Browser-based cipher lab: `gchq.github.io/CyberChef`
- **RsaCtfTool** — RSA attack automation: github.com/RsaCtfTool/RsaCtfTool
- **dcode.fr** — Classic cipher identification

### Network
- **Wireshark** — GUI packet analysis
- **tcpdump** — CLI packet capture
- **scapy** — Python packet crafting: `pip install scapy`

---

## Wordlist Sources

```bash
# SecLists (most complete collection)
apt install seclists      # Kali
# or
git clone https://github.com/danielmiessler/SecLists /usr/share/seclists

# Kali built-in
ls /usr/share/wordlists/
gunzip /usr/share/wordlists/rockyou.txt.gz

# Download via arsenal
./scripts/wordlist-fetch.sh
```

---

## Common Ports Quick Reference

| Port | Service | Notes |
|------|---------|-------|
| 21 | FTP | `ftp -n ip` → anon login |
| 22 | SSH | `ssh user@ip` |
| 25 | SMTP | `nc ip 25` → EHLO |
| 53 | DNS | `dig axfr @ip domain` |
| 80/443 | HTTP/S | browser + curl |
| 139/445 | SMB | `smbclient -L //ip` |
| 1433 | MSSQL | `mssqlclient.py` |
| 3306 | MySQL | `mysql -h ip -u root` |
| 5432 | PostgreSQL | `psql -h ip -U postgres` |
| 6379 | Redis | `redis-cli -h ip` |
| 8080 | HTTP-Alt | common dev/proxy port |
| 27017 | MongoDB | `mongosh ip` |

---

## CTF Cheat Sheets

- **GTFOBins** — `gtfobins.github.io` — Unix binary privesc
- **HackTricks** — `book.hacktricks.xyz` — comprehensive pentest guide
- **PayloadsAllTheThings** — github.com/swisskyrepo/PayloadsAllTheThings
- **CyberChef** — `gchq.github.io/CyberChef`
- **dcode.fr** — Classic cipher identification tool

---

*NuRichter Workspace · Richterize The Infinity ∞*
