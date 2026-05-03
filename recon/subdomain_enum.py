#!/usr/bin/env python3
"""
recon/subdomain_enum.py — Passive & active subdomain enumeration
NuRichter · CySec Arsenal

Usage:
    python recon/subdomain_enum.py -d example.com -w wordlists/subdomains.txt
    python recon/subdomain_enum.py -d example.com --passive
"""
import argparse
import concurrent.futures
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import ok, warn, err, info, found, get_logger

log = get_logger("subdomain_enum")

# ─── Built-in mini wordlist for quick scans ──────────────────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging",
    "test", "beta", "cdn", "static", "assets", "media",
    "auth", "login", "portal", "app", "dashboard", "vpn",
    "remote", "ns1", "ns2", "smtp", "pop", "imap", "webmail",
    "shop", "store", "blog", "wiki", "docs", "support", "help",
    "status", "monitor", "grafana", "jenkins", "git", "gitlab",
    "jira", "confluence", "internal", "intranet", "corp",
]


def resolve(subdomain: str, domain: str) -> tuple[str, str] | None:
    """Try to resolve a FQDN; return (fqdn, ip) if successful."""
    fqdn = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except socket.gaierror:
        return None


def brute_force(domain: str, wordlist: list[str], threads: int = 50) -> list[dict]:
    results = []
    print(info(f"Brute-forcing {len(wordlist)} subdomains against {domain}"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(resolve, word, domain): word for word in wordlist}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                fqdn, ip = result
                print(found(f"{fqdn}  →  {ip}"))
                results.append({"fqdn": fqdn, "ip": ip})
                log.info(f"FOUND: {fqdn} -> {ip}")
    return results


def passive_crtsh(domain: str) -> list[str]:
    """Query crt.sh certificate transparency logs (passive, no DNS)."""
    try:
        import urllib.request, json
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "cysec-arsenal/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        names = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if domain in name:
                    names.add(name)
        return sorted(names)
    except Exception as e:
        print(warn(f"crt.sh query failed: {e}"))
        return []


def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Enumerator — NuRichter CySec Arsenal"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist")
    parser.add_argument("--passive", action="store_true",
                        help="Passive only (crt.sh, no DNS brute force)")
    parser.add_argument("-t", "--threads", type=int, default=50,
                        help="Threads for brute force (default: 50)")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  TARGET  : {args.domain}")
    print(f"  MODE    : {'passive (crt.sh)' if args.passive else 'active brute force'}")
    print(f"{'='*60}\n")

    all_found = []

    # Passive — crt.sh
    print(info("Querying crt.sh certificate transparency logs..."))
    passive = passive_crtsh(args.domain)
    for name in passive:
        print(found(f"[crt.sh] {name}"))
        all_found.append({"fqdn": name, "source": "crt.sh"})

    if not args.passive:
        # Active — DNS brute force
        if args.wordlist and Path(args.wordlist).exists():
            wordlist = Path(args.wordlist).read_text().splitlines()
        else:
            print(warn("No wordlist specified, using built-in common subdomains."))
            wordlist = COMMON_SUBDOMAINS

        brute_results = brute_force(args.domain, wordlist, args.threads)
        all_found.extend(brute_results)

    print(f"\n{ok(f'Done — {len(all_found)} subdomain(s) found.')}")


if __name__ == "__main__":
    main()
