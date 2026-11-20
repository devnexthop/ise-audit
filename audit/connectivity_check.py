#!/usr/bin/env python3
"""
connectivity_check.py — Preflight checklist before an ISE audit pull.

Prompts for (or accepts) hostname, username, password and verifies everything
the toolkit needs. Read-only (HTTP GET only) — does not enable APIs or change ISE.

Checks:
  [ ] HTTPS reachability (TCP/TLS to :443)
  [ ] Credentials accepted (not bounced to login HTML on a known API)
  [ ] API Gateway enabled (admin API)
  [ ] OpenAPI serving (/api/v1/...)
  [ ] ERS serving (/ers/config/...) — required for devices/dACLs/profile bodies
  [ ] RADIUS policy API readable
  [ ] TACACS (device-admin) policy API readable

Usage (PowerShell):
  python audit\\connectivity_check.py --insecure
  python audit\\connectivity_check.py --host ise-pan.example.com --user apiadmin --insecure
  # password from prompt, or: $env:ISE_PASS=...

Exit code 0 = all required boxes green; 1 = one or more required failed.
"""
from __future__ import annotations

import argparse
import getpass
import json
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ise_common import env_cred, get_json, is_login_html, make_session  # noqa: E402


@dataclass
class Check:
    name: str
    required: bool
    ok: bool = False
    detail: str = ""


@dataclass
class Report:
    host: str
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str, required: bool = True) -> None:
        self.checks.append(Check(name=name, required=required, ok=ok, detail=detail))

    @property
    def required_ok(self) -> bool:
        return all(c.ok for c in self.checks if c.required)


def _prompt(host: str | None, user: str | None, password: str | None):
    host, user, password = env_cred(host, user, password)
    if not host:
        host = input("ISE PAN hostname or IP: ").strip()
    host = host.removeprefix("https://").removeprefix("http://").rstrip("/").split("/")[0]
    if not user:
        user = input("API username: ").strip()
    if not password:
        password = getpass.getpass("API password: ")
    return host, user, password


def check_tcp(host: str, port: int = 443, timeout: float = 5.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"TCP {host}:{port} open"
    except OSError as e:
        return False, f"TCP {host}:{port} failed: {e}"


def run_checks(host: str, user: str, password: str, insecure: bool) -> Report:
    report = Report(host=host)
    base = f"https://{host}"

    ok, detail = check_tcp(host, 443)
    report.add("HTTPS port 443 reachable", ok, detail)

    if not ok:
        report.add("Credentials / APIs", False, "Skipped — host not reachable")
        return report

    session = make_session(user, password, insecure)

    # API Gateway
    status, data, raw = get_json(
        session, f"{base}/admin/API/apiGateway/get", allow_redirects=False, timeout=25
    )
    if status == 200 and isinstance(data, list):
        enabled = [n for n in data if isinstance(n, dict) and n.get("isEnabled")]
        names = ", ".join(n.get("hostname", "?") for n in enabled) or "(none)"
        report.add(
            "API Gateway enabled",
            bool(enabled),
            f"enabled on: {names}" if enabled else "no nodes have API Gateway on",
        )
    elif is_login_html(raw) or raw == "HTML_LOGIN":
        report.add("API Gateway enabled", False, "got login HTML — bad creds or no API access")
    else:
        report.add(
            "API Gateway enabled",
            False,
            f"status={status} (could not read /admin/API/apiGateway/get)",
        )

    # apiService flags (informational — OpenAPI vs ERS naming varies by build)
    status, data, raw = get_json(
        session, f"{base}/admin/API/apiService/get", allow_redirects=False, timeout=25
    )
    if status == 200 and isinstance(data, dict):
        report.add(
            "API Service flags (admin)",
            True,
            json.dumps(data, ensure_ascii=False),
            required=False,
        )
    else:
        report.add(
            "API Service flags (admin)",
            False,
            f"status={status}",
            required=False,
        )

    # OpenAPI — deployment nodes
    status, data, raw = get_json(
        session, f"{base}/api/v1/deployment/node", allow_redirects=False, timeout=25
    )
    openapi_ok = status == 200 and data is not None and raw != "HTML_LOGIN"
    if openapi_ok:
        from ise_common import unwrap

        nodes = unwrap(data)
        report.add(
            "OpenAPI serving (/api/v1/)",
            True,
            f"deployment/node OK — {len(nodes)} node(s)",
        )
    else:
        hint = "Enable OpenAPI under Administration > System > Settings > API Settings"
        if status in (301, 302) or raw == "HTML_LOGIN":
            hint = "login redirect/HTML — OpenAPI off or bad creds. " + hint
        report.add("OpenAPI serving (/api/v1/)", False, f"status={status}. {hint}")

    # RADIUS policy
    status, data, raw = get_json(
        session,
        f"{base}/api/v1/policy/network-access/policy-set",
        allow_redirects=False,
        timeout=25,
    )
    rad_ok = status == 200 and data is not None and raw != "HTML_LOGIN"
    if rad_ok:
        from ise_common import unwrap

        report.add(
            "RADIUS policy API (network-access)",
            True,
            f"{len(unwrap(data))} policy set(s)",
        )
    else:
        report.add(
            "RADIUS policy API (network-access)",
            False,
            f"status={status}",
        )

    # TACACS policy
    status, data, raw = get_json(
        session,
        f"{base}/api/v1/policy/device-admin/policy-set",
        allow_redirects=False,
        timeout=25,
    )
    tac_ok = status == 200 and data is not None and raw != "HTML_LOGIN"
    if tac_ok:
        from ise_common import unwrap

        report.add(
            "TACACS policy API (device-admin)",
            True,
            f"{len(unwrap(data))} policy set(s)",
        )
    else:
        report.add(
            "TACACS policy API (device-admin)",
            False,
            f"status={status}",
        )

    # ERS — must not 302 to /admin/
    status, data, raw = get_json(
        session,
        f"{base}/ers/config/networkdevice",
        allow_redirects=False,
        timeout=25,
    )
    ers_ok = status == 200 and isinstance(data, dict) and "SearchResult" in data
    if ers_ok:
        total = (data.get("SearchResult") or {}).get("total")
        report.add(
            "ERS serving (/ers/config/)",
            True,
            f"networkdevice list OK (total={total})",
        )
    elif status in (301, 302, 303, 307, 308):
        report.add(
            "ERS serving (/ers/config/)",
            False,
            "HTTP redirect to GUI — enable ERS under API Settings",
        )
    elif raw == "HTML_LOGIN" or (isinstance(raw, str) and is_login_html(raw)):
        report.add(
            "ERS serving (/ers/config/)",
            False,
            "login HTML — ERS off or account lacks ERS role",
        )
    else:
        report.add("ERS serving (/ers/config/)", False, f"status={status}")

    # AuthZ profiles via ERS (body pull path)
    status, data, raw = get_json(
        session,
        f"{base}/ers/config/authorizationprofile",
        allow_redirects=False,
        timeout=25,
    )
    if status == 200 and isinstance(data, dict) and "SearchResult" in data:
        total = (data.get("SearchResult") or {}).get("total")
        report.add(
            "ERS authorization profiles",
            True,
            f"listed total={total}",
            required=False,
        )
    else:
        report.add(
            "ERS authorization profiles",
            False,
            f"status={status} (needed for profile→dACL cross-ref)",
            required=False,
        )

    return report


def print_report(report: Report) -> None:
    print()
    print("=" * 64)
    print(f" ISE connectivity checklist — {report.host}")
    print(f" {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("=" * 64)
    for c in report.checks:
        box = "[OK] " if c.ok else "[FAIL]"
        req = "" if c.required else " (optional)"
        print(f" {box} {c.name}{req}")
        if c.detail:
            print(f"        {c.detail}")
    print("-" * 64)
    if report.required_ok:
        print(" RESULT: READY — you can run pull_ise_inventory.py")
    else:
        print(" RESULT: NOT READY — fix FAIL items in ISE GUI:")
        print("   Administration > System > Settings > API Settings")
        print("   Enable: API Gateway, OpenAPI, ERS (and correct API account role)")
    print("=" * 64)
    print()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="ISE preflight checklist (hostname + user + password)."
    )
    ap.add_argument("--host", default=None, help="PAN FQDN or IP")
    ap.add_argument("--user", default=None, help="API username")
    ap.add_argument("--password", default=None, help="API password (or prompt / ISE_PASS)")
    ap.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS verify (lab self-signed certs)",
    )
    ap.add_argument(
        "--outdir",
        default=None,
        help="Optional folder to write connectivity_check.json",
    )
    args = ap.parse_args()

    host, user, password = _prompt(args.host, args.user, args.password)
    if not host or not user or not password:
        sys.exit("Hostname, username, and password are required.")

    print(f"Checking {host} as {user} ...")
    report = run_checks(host, user, password, args.insecure)
    print_report(report)

    if args.outdir:
        out = Path(args.outdir)
        out.mkdir(parents=True, exist_ok=True)
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": host,
            "user": user,
            "ready": report.required_ok,
            "checks": [
                {
                    "name": c.name,
                    "required": c.required,
                    "ok": c.ok,
                    "detail": c.detail,
                }
                for c in report.checks
            ],
        }
        path = out / "connectivity_check.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Wrote {path}")

    return 0 if report.required_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
