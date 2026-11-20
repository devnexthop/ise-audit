#!/usr/bin/env python3
"""
sdk_smoke.py — Read-only ciscoisesdk connectivity check against an ISE PAN.

Uses the official IdentityServicesEngineAPI client (API Gateway on TCP 443).
Writes a JSON summary to --outdir. Does not modify ISE.

Prereqs on ISE:
  - API Gateway enabled
  - OpenAPI and/or ERS enabled (Administration > System > Settings > API Settings)
  - Account with ERS Admin / Super Admin

Usage:
  set ISE_HOST=ise-pan.example.com
  set ISE_USER=apiadmin
  set ISE_PASS=...
  python sdk_smoke.py --outdir ./outdir --insecure

Environment (also accepted by ciscoisesdk):
  IDENTITY_SERVICES_ENGINE_BASE_URL, _USERNAME, _PASSWORD, _VERIFY, ...
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path


def _env(*names: str, default: str | None = None) -> str | None:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return default


def main() -> int:
    ap = argparse.ArgumentParser(description="ciscoisesdk read-only smoke test.")
    ap.add_argument("--outdir", default="./outdir", help="Directory for sdk_smoke.json")
    ap.add_argument("--host", default=_env("ISE_HOST"))
    ap.add_argument("--user", default=_env("ISE_USER", "IDENTITY_SERVICES_ENGINE_USERNAME"))
    ap.add_argument("--password", default=_env("ISE_PASS", "IDENTITY_SERVICES_ENGINE_PASSWORD"))
    ap.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS verify (lab / self-signed PAN cert)",
    )
    ap.add_argument(
        "--version",
        default=_env("IDENTITY_SERVICES_ENGINE_VERSION", default="3.3_patch_1"),
        help="ciscoisesdk API version string",
    )
    args = ap.parse_args()

    host = (args.host or "").strip().removeprefix("https://").removeprefix("http://").rstrip("/")
    if not host:
        sys.exit("Set ISE_HOST / --host (PAN FQDN or IP).")
    if not args.user or not args.password:
        sys.exit("Set ISE_USER/ISE_PASS (or IDENTITY_SERVICES_ENGINE_USERNAME/PASSWORD).")

    try:
        from ciscoisesdk import IdentityServicesEngineAPI
    except ImportError:
        sys.exit("ciscoisesdk not installed. pip install -r requirements.txt")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    api = IdentityServicesEngineAPI(
        username=args.user,
        password=args.password,
        base_url=f"https://{host}",
        version=args.version,
        uses_api_gateway=True,
        verify=not args.insecure,
        uses_csrf_token=False,
    )

    results: dict = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "checks": {},
    }

    def _is_html(payload) -> bool:
        if isinstance(payload, str):
            t = payload.lstrip().lower()
            return t.startswith("<!doctype") or t.startswith("<html")
        return False

    def check(name: str, fn) -> None:
        try:
            resp = fn()
            payload = getattr(resp, "response", resp)
            status = getattr(resp, "status_code", None)
            html = _is_html(payload)
            ok = status == 200 and not html and payload is not None
            entry = {
                "ok": ok,
                "status_code": status,
                "html_login_page": html,
                "summary": _summarize(payload) if ok else None,
            }
            if not ok and html:
                entry["hint"] = (
                    "Got ISE login HTML — enable ERS/OpenAPI under "
                    "Administration > System > Settings > API Settings, "
                    "and confirm API Gateway is on."
                )
            if not ok and not html:
                entry["response_preview"] = str(payload)[:400]
            results["checks"][name] = entry
            flag = "OK" if ok else "FAIL"
            print(f"[{flag}] {name} status={status} html={html}")
        except Exception as e:
            results["checks"][name] = {
                "ok": False,
                "error": str(e),
                "trace": traceback.format_exc(),
            }
            print(f"[FAIL] {name}: {e}")

    def _summarize(payload):
        if isinstance(payload, dict):
            if "response" in payload and isinstance(payload["response"], list):
                return {"count": len(payload["response"])}
            if "SearchResult" in payload:
                sr = payload["SearchResult"]
                return {"total": sr.get("total"), "resources": len(sr.get("resources") or [])}
            return {"keys": sorted(payload.keys())[:20]}
        if isinstance(payload, list):
            return {"count": len(payload)}
        return {"type": type(payload).__name__}

    check(
        "network_access_policy_set",
        lambda: api.network_access_policy_set.get_network_access_policy_sets(),
    )
    check(
        "authorization_profile",
        lambda: api.authorization_profile.get_authorization_profiles(),
    )
    check(
        "network_device",
        lambda: api.network_device.get_network_device(),
    )
    check(
        "version_and_patch",
        lambda: api.version_and_patch.get_ise_version_and_patch(),
    )

    out_path = outdir / "sdk_smoke.json"
    out_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {out_path}")

    openapi_ok = results["checks"].get("network_access_policy_set", {}).get("ok")
    return 0 if openapi_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
