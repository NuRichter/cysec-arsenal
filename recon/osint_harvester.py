#!/usr/bin/env python3
"""
recon/osint_harvester.py — OSINT aggregator using passive public APIs
NuRichter · CySec Arsenal

Sources: crt.sh, HackerTarget, ip-api, Shodan (key optional)

Usage:
    python recon/osint_harvester.py -d example.com
    python recon/osint_harvester.py -i 93.184.216.34
    python recon/osint_harvester.py -d example.com --shodan-key YOUR_API_KEY
"""
import argparse
import json
import socket
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import ok, warn, err, info, found, get_logger

log = get_logger("osint_harvester")


def _get(url: str, timeout: int = 10) -> str | None:
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "cysec-arsenal/1.0 (educational)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode(errors="ignore")
    except Exception as e:
        print(warn(f"Request failed [{url}]: {e}"))
        return None


# ─── Modules ──────────────────────────────────────────────────────────────────

def resolve_domain(domain: str) -> str | None:
    try:
        ip = socket.gethostbyname(domain)
        print(ok(f"Resolved: {domain} → {ip}"))
        return ip
    except socket.gaierror:
        print(err(f"Could not resolve {domain}"))
        return None


def ip_geolocation(ip: str) -> dict:
    """ip-api.com — free, no key required."""
    print(info(f"GeoIP lookup: {ip}"))
    data_str = _get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,reverse,lat,lon")
    if not data_str:
        return {}
    data = json.loads(data_str)
    if data.get("status") == "success":
        for k, v in data.items():
            if k != "status":
                print(f"  {k:<12}: {v}")
    return data


def hackertarget_whois(domain: str) -> str | None:
    """HackerTarget WHOIS — no key required."""
    print(info(f"WHOIS via HackerTarget: {domain}"))
    result = _get(f"https://api.hackertarget.com/whois/?q={domain}")
    if result:
        print(result[:2000])
    return result


def hackertarget_dns(domain: str) -> None:
    """DNS lookup via HackerTarget."""
    print(info(f"DNS records: {domain}"))
    result = _get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
    if result:
        print(result)


def hackertarget_reverse_dns(ip: str) -> None:
    """Reverse DNS via HackerTarget."""
    print(info(f"Reverse DNS: {ip}"))
    result = _get(f"https://api.hackertarget.com/reversedns/?q={ip}")
    if result:
        print(result)


def shodan_host(ip: str, api_key: str) -> dict:
    """Shodan InternetDB — free tier, or full API with key."""
    # InternetDB (no key needed)
    print(info(f"Shodan InternetDB: {ip}"))
    data_str = _get(f"https://internetdb.shodan.io/{ip}")
    if data_str:
        data = json.loads(data_str)
        print(f"  Ports    : {data.get('ports', [])}")
        print(f"  CPEs     : {data.get('cpes', [])}")
        print(f"  Tags     : {data.get('tags', [])}")
        print(f"  Vulns    : {data.get('vulns', [])}")
        return data
    return {}


def certsh_domains(domain: str) -> list[str]:
    """Certificate transparency via crt.sh."""
    print(info(f"crt.sh certificate transparency: {domain}"))
    data_str = _get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if not data_str:
        return []
    try:
        data = json.loads(data_str)
    except json.JSONDecodeError:
        return []
    names = set()
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lstrip("*.")
            if domain in name:
                names.add(name)
    unique = sorted(names)
    print(ok(f"  {len(unique)} certificate entries found"))
    for n in unique[:20]:
        print(f"  → {n}")
    if len(unique) > 20:
        print(f"  ... and {len(unique) - 20} more")
    return unique


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="OSINT Harvester — NuRichter CySec Arsenal"
    )
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-i", "--ip", help="Target IP address")
    parser.add_argument("--shodan-key", default="", help="Shodan API key (optional)")
    parser.add_argument("--no-whois", action="store_true", help="Skip WHOIS")
    args = parser.parse_args()

    if not args.domain and not args.ip:
        parser.error("Specify -d DOMAIN or -i IP")

    print(f"\n{'='*60}")
    if args.domain:
        print(f"  DOMAIN   : {args.domain}")
    if args.ip:
        print(f"  IP       : {args.ip}")
    print(f"{'='*60}\n")

    ip = args.ip

    if args.domain:
        ip = ip or resolve_domain(args.domain)
        print()
        certsh_domains(args.domain)
        print()
        hackertarget_dns(args.domain)
        print()
        if not args.no_whois:
            hackertarget_whois(args.domain)
            print()

    if ip:
        ip_geolocation(ip)
        print()
        hackertarget_reverse_dns(ip)
        print()
        shodan_host(ip, args.shodan_key)
        print()

    print(ok("OSINT harvest complete."))


if __name__ == "__main__":
    main()
