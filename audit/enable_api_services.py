#!/usr/bin/env python3
"""
enable_api_services.py — Enable ISE API services on the PAN via admin API.

Uses POST /admin/API/apiService/update (same toggle the GUI exposes under
Administration > System > Settings > API Settings). Read the current state
first; only updates when --enable is passed.

On some lab builds this turns on OpenAPI while ERS may still need the GUI
toggle (ERS returns HTTP 302 to /admin/ until fully enabled).

Usage:
  python enable_api_services.py --host ise-pan.example.com --insecure
  python enable_api_services.py --host ise-pan.example.com --insecure --enable
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings()


def main() -> int:
    ap = argparse.ArgumentParser(description="Show or enable ISE API services (admin API).")
    ap.add_argument("--host", default=os.environ.get("ISE_HOST"))
    ap.add_argument("--user", default=os.environ.get("ISE_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("ISE_PASS"))
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument(
        "--enable",
        action="store_true",
        help="Set papIsEnabled/psnsIsEnabled true (writes to ISE)",
    )
    args = ap.parse_args()
    if not args.host:
        sys.exit("Set --host or ISE_HOST")
    password = args.password or input("ISE password: ")

    host = args.host.strip().removeprefix("https://").removeprefix("http://").rstrip("/")
    s = requests.Session()
    s.auth = HTTPBasicAuth(args.user, password)
    s.verify = not args.insecure
    s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    get_url = f"https://{host}/admin/API/apiService/get"
    r = s.get(get_url, timeout=30)
    r.raise_for_status()
    state = r.json()
    print("Current:", json.dumps(state, indent=2))

    if not args.enable:
        print("Dry run only. Pass --enable to set papIsEnabled/psnsIsEnabled true.")
        return 0

    body = {
        "id": state.get("id"),
        "papIsEnabled": True,
        "psnsIsEnabled": True,
    }
    u = s.post(f"https://{host}/admin/API/apiService/update", data=json.dumps(body), timeout=60)
    print("Update:", u.status_code, u.text[:500])
    after = s.get(get_url, timeout=30)
    print("After:", after.text)
    return 0 if after.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
