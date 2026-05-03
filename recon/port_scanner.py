#!/usr/bin/env python3
"""
recon/port_scanner.py — Fast async TCP port scanner with banner grabbing
NuRichter · CySec Arsenal

Usage:
    python recon/port_scanner.py -t 192.168.1.1
    python recon/port_scanner.py -t 10.0.0.0/24 -p 1-1000 --banner
    python recon/port_scanner.py -t target.com --top100
"""
import argparse
import asyncio
import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import ok, warn, err, info, found, get_logger

log = get_logger("port_scanner")

# ─── Top 100 common ports ─────────────────────────────────────────────────────
TOP_100 = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888,
    20, 26, 69, 79, 88, 106, 143, 179, 199, 389, 427, 444, 465,
    543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025,
    1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000,
    5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5900, 6000, 6001, 6646, 7070, 8000, 8008, 8080, 8443, 8888,
    9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
]

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 9200: "Elasticsearch",
}

OPEN_PORTS: list[dict] = []


async def scan_port(
    host: str, port: int, timeout: float = 1.0, grab_banner: bool = False
) -> dict | None:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)

        banner = ""
        if grab_banner:
            try:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(256), timeout=2.0)
                banner = data.decode(errors="ignore").strip().split("\n")[0]
            except Exception:
                pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        service = SERVICE_MAP.get(port, "unknown")
        return {"host": host, "port": port, "service": service, "banner": banner}
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def scan_host(
    host: str, ports: list[int], timeout: float, grab_banner: bool
):
    print(info(f"Scanning {host} ({len(ports)} ports)..."))
    tasks = [scan_port(host, p, timeout, grab_banner) for p in ports]
    results = await asyncio.gather(*tasks)
    open_ports = [r for r in results if r]
    for r in sorted(open_ports, key=lambda x: x["port"]):
        banner_str = f"  [{r['banner']}]" if r["banner"] else ""
        print(found(f"{host}:{r['port']}/tcp  {r['service']}{banner_str}"))
        log.info(f"OPEN: {host}:{r['port']} ({r['service']})")
        OPEN_PORTS.append(r)
    return open_ports


def parse_ports(port_str: str) -> list[int]:
    ports = set()
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def expand_targets(target: str) -> list[str]:
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
    except ValueError:
        return [target]


async def main_async(args):
    targets = expand_targets(args.target)
    ports = TOP_100 if args.top100 else parse_ports(args.ports)

    print(f"\n{'='*60}")
    print(f"  TARGETS  : {args.target}  ({len(targets)} host(s))")
    print(f"  PORTS    : {len(ports)} port(s)")
    print(f"  BANNER   : {'yes' if args.banner else 'no'}")
    print(f"{'='*60}\n")

    for host in targets:
        await scan_host(host, ports, args.timeout, args.banner)

    print(f"\n{ok(f'{len(OPEN_PORTS)} open port(s) found across {len(targets)} host(s).')}")


def main():
    parser = argparse.ArgumentParser(
        description="Async Port Scanner — NuRichter CySec Arsenal"
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP, hostname, or CIDR (e.g. 10.0.0.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range (e.g. 80,443 or 1-65535)")
    parser.add_argument("--top100", action="store_true",
                        help="Scan top 100 common ports")
    parser.add_argument("--banner", action="store_true",
                        help="Attempt banner grabbing")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
