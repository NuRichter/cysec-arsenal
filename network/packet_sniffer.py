#!/usr/bin/env python3
"""
network/packet_sniffer.py — Live packet capture & protocol dissection
NuRichter · CySec Arsenal

Requires: scapy, root/admin privileges

Usage:
    sudo python network/packet_sniffer.py -i eth0
    sudo python network/packet_sniffer.py -i eth0 -f "tcp port 80" --save capture.pcap
    sudo python network/packet_sniffer.py -i eth0 --http-only -n 100
"""
import argparse
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import ok, warn, err, info, found, get_logger

log = get_logger("packet_sniffer")

try:
    from scapy.all import (
        sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        Raw, ARP, Ether, get_if_list
    )
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


class PacketSniffer:
    def __init__(self, iface: str, bpf_filter: str = "", http_only: bool = False,
                 count: int = 0, save: str = ""):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.http_only = http_only
        self.count = count
        self.save_path = save
        self.packets = []
        self.stats = {"tcp": 0, "udp": 0, "icmp": 0, "arp": 0,
                      "dns": 0, "http": 0, "other": 0}

    def _handle(self, pkt):
        self.packets.append(pkt)
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if pkt.haslayer(ARP):
            self.stats["arp"] += 1
            op = "who-has" if pkt[ARP].op == 1 else "is-at"
            print(f"[{ts}] {info('ARP')} {pkt[ARP].psrc} {op} {pkt[ARP].pdst}")
            return

        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            self.stats["other"] += 1
            return

        src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
        dst = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst

        if pkt.haslayer(DNS):
            self.stats["dns"] += 1
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode(errors="ignore")
                print(f"[{ts}] {info('DNS')} query  {src} → {qname}")
            elif pkt.haslayer(DNSRR):
                name = pkt[DNSRR].rrname.decode(errors="ignore")
                rdata = pkt[DNSRR].rdata
                print(f"[{ts}] {info('DNS')} answer {name} → {rdata}")
            return

        if pkt.haslayer(HTTPRequest):
            self.stats["http"] += 1
            method = pkt[HTTPRequest].Method.decode(errors="ignore")
            host   = pkt[HTTPRequest].Host.decode(errors="ignore")
            path   = pkt[HTTPRequest].Path.decode(errors="ignore")
            print(f"[{ts}] {found('HTTP')} {method} http://{host}{path}  ({src}→{dst})")
            if pkt.haslayer(Raw):
                body = pkt[Raw].load.decode(errors="ignore")
                if any(k in body.lower() for k in ["password", "passwd", "pass=", "pwd="]):
                    print(f"  {warn('SENSITIVE DATA in POST body')}: {body[:200]}")
            return

        if pkt.haslayer(HTTPResponse) and not self.http_only:
            self.stats["http"] += 1
            status = pkt[HTTPResponse].Status_Code.decode(errors="ignore")
            reason = pkt[HTTPResponse].Reason_Phrase.decode(errors="ignore")
            print(f"[{ts}] {info('HTTP')} ← {status} {reason}  ({src}→{dst})")
            return

        if self.http_only:
            return

        if pkt.haslayer(TCP):
            self.stats["tcp"] += 1
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            flags = pkt[TCP].flags
            print(f"[{ts}] TCP  {src}:{sport} → {dst}:{dport}  flags={flags}")

        elif pkt.haslayer(UDP):
            self.stats["udp"] += 1
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            print(f"[{ts}] UDP  {src}:{sport} → {dst}:{dport}")

        elif pkt.haslayer(ICMP):
            self.stats["icmp"] += 1
            itype = pkt[ICMP].type
            print(f"[{ts}] ICMP {src} → {dst}  type={itype}")
        else:
            self.stats["other"] += 1

    def start(self):
        if not SCAPY_OK:
            print(err("scapy not installed. Run: pip install scapy"))
            return

        print(ok(f"Sniffing on {self.iface}  "
                 f"filter={repr(self.bpf_filter) or 'none'}  "
                 f"count={self.count or '∞'}"))
        print(info("Press Ctrl+C to stop.\n"))

        try:
            sniff(
                iface=self.iface,
                filter=self.bpf_filter or None,
                prn=self._handle,
                count=self.count or 0,
                store=False,
            )
        except KeyboardInterrupt:
            pass
        finally:
            self._summary()
            if self.save_path and self.packets:
                wrpcap(self.save_path, self.packets)
                print(ok(f"Saved {len(self.packets)} packets → {self.save_path}"))

    def _summary(self):
        total = sum(self.stats.values())
        print(f"\n{'='*50}")
        print(f"  Captured: {total} packets")
        for proto, cnt in self.stats.items():
            if cnt:
                print(f"  {proto.upper():<8}: {cnt}")
        print(f"{'='*50}")


def main():
    if not SCAPY_OK:
        print(err("scapy not installed. Run: pip install scapy"))
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Packet Sniffer — NuRichter CySec Arsenal"
    )
    parser.add_argument("-i", "--iface", default="eth0",
                        help="Network interface (default: eth0)")
    parser.add_argument("-f", "--filter", default="",
                        help="BPF filter expression (e.g. 'tcp port 80')")
    parser.add_argument("--http-only", action="store_true",
                        help="Only display HTTP requests/responses")
    parser.add_argument("-n", "--count", type=int, default=0,
                        help="Stop after N packets (0 = infinite)")
    parser.add_argument("--save", default="",
                        help="Save capture to .pcap file")
    parser.add_argument("--list-ifaces", action="store_true",
                        help="List available interfaces")
    args = parser.parse_args()

    if args.list_ifaces:
        print(info("Available interfaces:"))
        for iface in get_if_list():
            print(f"  {iface}")
        return

    sniffer = PacketSniffer(
        iface=args.iface,
        bpf_filter=args.filter,
        http_only=args.http_only,
        count=args.count,
        save=args.save,
    )
    sniffer.start()


if __name__ == "__main__":
    main()
