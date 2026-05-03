#!/usr/bin/env python3
"""
ctf/template_web.py — CTF Web Challenge Solve Template
NuRichter · CySec Arsenal

A structured starting point for web CTF challenges.
"""
import json
import re
import sys
from pathlib import Path
import requests
requests.packages.urllib3.disable_warnings()

# ─── CONFIG ──────────────────────────────────────────────────────────────────
BASE_URL  = "http://challenge.ctf.io:5000"
HEADERS   = {"User-Agent": "Mozilla/5.0 (CTF Solver; NuRichter)"}
PROXIES   = {}  # {"http": "http://127.0.0.1:8080"}  # Burp proxy
SESSION   = requests.Session()
SESSION.headers.update(HEADERS)
SESSION.verify = False
if PROXIES:
    SESSION.proxies.update(PROXIES)

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def get(path: str, **kwargs) -> requests.Response:
    url = BASE_URL + path
    resp = SESSION.get(url, **kwargs)
    print(f"[GET {resp.status_code}] {url}")
    return resp


def post(path: str, data=None, json_=None, **kwargs) -> requests.Response:
    url = BASE_URL + path
    resp = SESSION.post(url, data=data, json=json_, **kwargs)
    print(f"[POST {resp.status_code}] {url}")
    return resp


def extract_flag(text: str, pattern: str = r"[A-Z0-9_]+\{[^}]+\}") -> list[str]:
    """Extract flag(s) matching common CTF formats."""
    flags = re.findall(pattern, text, re.IGNORECASE)
    for flag in flags:
        print(f"\n  🚩 FLAG FOUND: {flag}\n")
    return flags


def dump_cookies() -> dict:
    print("\n[COOKIES]")
    for k, v in SESSION.cookies.items():
        print(f"  {k}: {v}")
    return dict(SESSION.cookies)


def set_cookie(name: str, value: str):
    SESSION.cookies.set(name, value)
    print(f"[COOKIE SET] {name}={value}")


def jwt_decode_nocheck(token: str) -> tuple[dict, dict]:
    """Decode JWT without signature verification (for analysis)."""
    import base64
    parts = token.split(".")
    if len(parts) != 3:
        return {}, {}
    def decode_part(p):
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    return decode_part(parts[0]), decode_part(parts[1])


# ─── EXPLOIT STAGES ──────────────────────────────────────────────────────────

def stage_recon():
    """Initial recon: check robots.txt, sitemap, source hints."""
    print("\n[=== RECON ===]")
    for path in ["/robots.txt", "/sitemap.xml", "/.git/HEAD",
                 "/.env", "/debug", "/admin", "/api"]:
        resp = get(path)
        if resp.status_code == 200:
            print(f"  → {path} is accessible ({len(resp.text)} bytes)")


def stage_auth():
    """Authentication / session bypass."""
    print("\n[=== AUTH ===]")
    # Example: try common credentials
    for user, passwd in [("admin", "admin"), ("admin", "password"),
                         ("guest", "guest"), ("admin", "")]:
        resp = post("/login", data={"username": user, "password": passwd})
        if "invalid" not in resp.text.lower() and resp.status_code == 200:
            print(f"  → Login success: {user}:{passwd}")
            break


def stage_exploit():
    """Main exploit logic — fill this in."""
    print("\n[=== EXPLOIT ===]")
    # Example placeholders:
    # SQLi: post("/login", data={"username": "admin'--", "password": ""})
    # IDOR: get("/api/user/1")
    # SSTI: get("/render?template={{7*7}}")
    # XXE:  post("/upload", data=xml_payload)
    resp = get("/")
    extract_flag(resp.text)


def stage_flag():
    """Grab the flag after exploitation."""
    print("\n[=== FLAG ===]")
    resp = get("/flag")
    extract_flag(resp.text)
    resp2 = get("/secret")
    extract_flag(resp2.text)


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    print(f"Target: {BASE_URL}")
    print("="*60)

    stage_recon()
    # stage_auth()
    # stage_exploit()
    # stage_flag()


if __name__ == "__main__":
    main()
