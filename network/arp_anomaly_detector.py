#!/usr/bin/env python3
"""
network/arp_anomaly_detector.py — Detect ARP spoofing & cache poisoning
NuRichter · CySec Arsenal

Monitors ARP traffic and flags:
  - IP→MAC mapping changes (potential ARP spoofing)
  - Gratuitous ARP storms
  - Duplicate IP assignments

Requires: scapy, root/admin

Usage:
    sudo python network/arp_anomaly_detector.py -i eth0
    sudo python network/arp_anomaly_detector.py -i eth0 --alert-only
"""
import argparse
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import ok, warn, err, info, found, get_logger

log = get_logger("arp_detector")

try:
    from scapy.all import sniff, ARP, Ether, get_if_hwaddr
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


class ARPAnomalyDetector:
    def __init__(self, iface: str, alert_only: bool = False):
        self.iface = iface
        self.alert_only = alert_only

        # ip → {mac: last_seen_ts}
        self.arp_table: dict[str, dict[str, float]] = defaultdict(dict)
        # ip → arp reply count per minute
        self.reply_count: dict[str, list[float]] = defaultdict(list)

        self.alerts: list[dict] = []
        self.total_packets = 0

    def _ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _check(self, pkt):
        if not pkt.haslayer(ARP):
            return
        self.total_packets += 1
        now = time.time()

        arp = pkt[ARP]
        src_ip  = arp.psrc
        src_mac = arp.hwsrc.lower()
        op = arp.op  # 1=who-has (request), 2=is-at (reply)

        if op == 2:  # ARP reply / gratuitous ARP
            self.reply_count[src_ip].append(now)
            # Clean old timestamps (> 60s)
            self.reply_count[src_ip] = [
                t for t in self.reply_count[src_ip] if now - t < 60
            ]

            # ─── Alert: ARP storm (>10 replies/min from same IP) ──────────
            count = len(self.reply_count[src_ip])
            if count > 10:
                msg = (f"ARP STORM: {src_ip} sent {count} replies in last 60s  "
                       f"(possible DoS/poisoning)")
                print(f"[{self._ts()}] {warn(msg)}")
                self.alerts.append({"type": "arp_storm", "ip": src_ip,
                                    "count": count, "mac": src_mac})
                log.warning(msg)

            # ─── Alert: IP→MAC mapping change ─────────────────────────────
            known_macs = self.arp_table.get(src_ip, {})
            if known_macs and src_mac not in known_macs:
                old_macs = list(known_macs.keys())
                msg = (f"ARP SPOOF DETECTED: {src_ip} changed MAC "
                       f"{old_macs[0]} → {src_mac}")
                print(f"[{self._ts()}] {found(msg)}")
                self.alerts.append({"type": "mac_change", "ip": src_ip,
                                    "old": old_macs, "new": src_mac})
                log.warning(msg)
            else:
                if not self.alert_only:
                    print(f"[{self._ts()}] {info('ARP reply')} {src_ip} is-at {src_mac}")

            # Update table
            self.arp_table[src_ip][src_mac] = now

        elif op == 1:  # ARP request
            if not self.alert_only:
                dst_ip = arp.pdst
                print(f"[{self._ts()}] {info('ARP query')} who-has {dst_ip} ? {src_ip}")

    def start(self):
        if not SCAPY_OK:
            print(err("scapy not installed. Run: pip install scapy"))
            return

        print(ok(f"Monitoring ARP on {self.iface}..."))
        print(info("Alert-only mode: " + ("ON" if self.alert_only else "OFF")))
        print(info("Press Ctrl+C to stop.\n"))

        try:
            sniff(iface=self.iface, filter="arp", prn=self._check, store=False)
        except KeyboardInterrupt:
            pass
        finally:
            self._summary()

    def _summary(self):
        print(f"\n{'='*55}")
        print(f"  ARP packets seen : {self.total_packets}")
        print(f"  Alerts raised    : {len(self.alerts)}")
        print(f"\n  Learned ARP table:")
        for ip, macs in sorted(self.arp_table.items()):
            mac_list = ", ".join(macs.keys())
            flag = " ⚠ MULTIPLE MACs" if len(macs) > 1 else ""
            print(f"    {ip:<18} {mac_list}{flag}")
        print(f"{'='*55}")


def main():
    if not SCAPY_OK:
        print(err("scapy not installed. Run: pip install scapy"))
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="ARP Anomaly Detector — NuRichter CySec Arsenal"
    )
    parser.add_argument("-i", "--iface", default="eth0")
    parser.add_argument("--alert-only", action="store_true",
                        help="Only print alerts, suppress normal ARP logs")
    args = parser.parse_args()

    detector = ARPAnomalyDetector(args.iface, args.alert_only)
    detector.start()


if __name__ == "__main__":
    main()
