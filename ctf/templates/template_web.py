#!/usr/bin/env python3
"""
ctf/templates/template_web.py — CTF Web Challenge Solve Template
NuRichter · CySec Arsenal
"""
import json, re, sys
import requests
requests.packages.urllib3.disable_warnings()

BASE_URL = "http://challenge.ctf.io:5000"
HEADERS  = {"User-Agent": "Mozilla/5.0 (CTF Solver; NuRichter)"}
PROXIES  = {}  # {"http": "http://127.0.0.1:8080"}
SESSION  = requests.Session()
SESSION.headers.update(HEADERS)
SESSION.verify  = False
SESSION.proxies = PROXIES

def get(path, **kw):  r = SESSION.get(BASE_URL+path, **kw);  print(f"[GET  {r.status_code}] {path}"); return r
def post(path, **kw): r = SESSION.post(BASE_URL+path, **kw); print(f"[POST {r.status_code}] {path}"); return r

def extract_flag(text):
    flags = re.findall(r"[A-Z0-9_]+\{[^}]+\}", text, re.I)
    for f in flags: print(f"\n  🚩 FLAG: {f}\n")
    return flags

def recon():
    for path in ["/robots.txt","/.git/HEAD","/.env","/admin","/api","/debug"]:
        r = SESSION.get(BASE_URL+path, verify=False, timeout=4)
        if r.status_code == 200: print(f"  [>] {path} accessible")

def main():
    print(f"Target: {BASE_URL}\n")
    recon()
    # stage_auth(); stage_exploit(); stage_flag()

if __name__ == "__main__": main()
