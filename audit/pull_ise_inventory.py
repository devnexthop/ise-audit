#!/usr/bin/env python3
"""
pull_ise_inventory.py — Full read-only ISE inventory via OpenAPI + ERS.

HTTP GET only. Never enables APIs, never creates/updates/deletes objects.
(Do not use enable_api_services.py --enable if the engagement forbids changes.)

Collects:
  - ISE deployment nodes (servers)
  - RADIUS policy sets with full AuthN + AuthZ (+ exception) rule/condition detail
  - TACACS policy sets with full AuthN + AuthZ rule/condition detail
  - Condition libraries, dictionaries, SGTs, identity stores, command sets
  - Endpoints list (OpenAPI)
  - ERS *if already enabled*: network devices, NDGs, identity groups, internal
    users, endpoint groups, id-store sequences, dACLs, authz-profile bodies

If ERS returns 302 → /admin/, those objects are listed MISSING in the Excel
Coverage sheet — turn ERS on in the customer GUI under change control, then
re-run this script (still GET-only).

Usage:
  set ISE_HOST=... ISE_USER=... ISE_PASS=...
  python pull_ise_inventory.py --outdir D:\\ise-engagements\\job\\raw --insecure
"""
from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running as script from audit/ or repo root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ise_common import (  # noqa: E402
    env_cred,
    flatten_condition,
    get_json,
    make_session,
    unwrap,
    write_json,
)


def _save_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def _openapi_get(session, base: str, path: str, manifest: dict):
    status, data, raw = get_json(session, f"{base}{path}", allow_redirects=False)
    ok = status == 200 and data is not None
    manifest["openapi"][path] = {
        "status": status,
        "ok": ok,
        "count": len(unwrap(data)) if ok else 0,
        "note": raw if raw == "HTML_LOGIN" else None,
    }
    return data if ok else None


def _ers_list(
    session,
    base_ers: str,
    resource: str,
    manifest: dict,
    *,
    max_pages: int | None = None,
) -> list[dict]:
    """Page through ERS collection without size= (matches pull_ise_objects.ps1)."""
    all_rows: list[dict] = []
    page = 1
    reported_total = None
    while True:
        url = f"{base_ers}/{resource}" if page == 1 else f"{base_ers}/{resource}?page={page}"
        status, data, raw = get_json(session, url, allow_redirects=False)
        if status in (301, 302, 303, 307, 308) or raw == "HTML_LOGIN":
            manifest["ers"][resource] = {
                "ok": False,
                "status": status,
                "note": "ERS not serving (enable ERS under API Settings)",
            }
            return []
        if status != 200 or not isinstance(data, dict):
            manifest["ers"][resource] = {"ok": False, "status": status, "note": str(raw)[:200]}
            return all_rows
        sr = data.get("SearchResult") or {}
        if page == 1:
            reported_total = sr.get("total")
        resources = sr.get("resources") or []
        all_rows.extend(resources)
        if max_pages and page >= max_pages:
            break
        if sr.get("nextPage") and sr["nextPage"].get("href"):
            page += 1
        else:
            break
    manifest["ers"][resource] = {
        "ok": True,
        "status": 200,
        "count": len(all_rows),
        "reported_total": reported_total,
        "capped": bool(max_pages and reported_total and len(all_rows) < int(reported_total)),
    }
    return all_rows


def _ers_get(session, url: str):
    status, data, raw = get_json(session, url, allow_redirects=False)
    if status != 200 or data is None or raw == "HTML_LOGIN":
        return None
    return data


def export_policy_domain(session, base: str, domain: str, out_dir: Path, manifest: dict) -> None:
    root = f"/api/v1/policy/{domain}"
    sets = unwrap(_openapi_get(session, base, f"{root}/policy-set", manifest))
    full = []
    authn_rows = []
    authz_rows = []

    for ps in sets:
        if not isinstance(ps, dict):
            continue
        psid = ps.get("id")
        psname = ps.get("name", psid)
        authn = unwrap(
            _openapi_get(session, base, f"{root}/policy-set/{psid}/authentication", manifest)
        )
        authz = unwrap(
            _openapi_get(session, base, f"{root}/policy-set/{psid}/authorization", manifest)
        )
        exc = unwrap(
            _openapi_get(session, base, f"{root}/policy-set/{psid}/exception", manifest)
        )
        full.append(
            {
                "policySet": ps,
                "authentication": authn,
                "authorization": authz,
                "exception": exc,
            }
        )

        for r in authn:
            rule = r.get("rule", r) if isinstance(r, dict) else {}
            identity = r.get("identitySourceName", "") if isinstance(r, dict) else ""
            if not isinstance(identity, str):
                identity = ", ".join(filter(None, identity or []))
            authn_rows.append(
                {
                    "policy_set": psname,
                    "policy_set_id": psid,
                    "rule": rule.get("name", ""),
                    "rule_id": rule.get("id", ""),
                    "rank": rule.get("rank", ""),
                    "state": rule.get("state", ""),
                    "hit_counts": rule.get("hitCounts", ""),
                    "default": rule.get("default", ""),
                    "condition": flatten_condition(rule.get("condition")),
                    "condition_json": json_dumps(rule.get("condition")),
                    "identity_source": identity,
                }
            )

        for r in authz:
            rule = r.get("rule", r) if isinstance(r, dict) else {}
            profs = (r.get("profile") if isinstance(r, dict) else None) or []
            sgts = (r.get("securityGroup") if isinstance(r, dict) else None) or ""
            if isinstance(profs, str):
                profs = [profs]
            authz_rows.append(
                {
                    "policy_set": psname,
                    "policy_set_id": psid,
                    "rule": rule.get("name", ""),
                    "rule_id": rule.get("id", ""),
                    "rank": rule.get("rank", ""),
                    "state": rule.get("state", ""),
                    "hit_counts": rule.get("hitCounts", ""),
                    "default": rule.get("default", ""),
                    "condition": flatten_condition(rule.get("condition")),
                    "condition_json": json_dumps(rule.get("condition")),
                    "profiles": ", ".join(profs),
                    "security_group": sgts if isinstance(sgts, str) else json_dumps(sgts),
                }
            )

        for r in exc:
            rule = r.get("rule", r) if isinstance(r, dict) else {}
            authz_rows.append(
                {
                    "policy_set": psname,
                    "policy_set_id": psid,
                    "rule": f"[exception] {rule.get('name', '')}",
                    "rule_id": rule.get("id", ""),
                    "rank": rule.get("rank", ""),
                    "state": rule.get("state", ""),
                    "hit_counts": rule.get("hitCounts", ""),
                    "default": rule.get("default", ""),
                    "condition": flatten_condition(rule.get("condition")),
                    "condition_json": json_dumps(rule.get("condition")),
                    "profiles": ", ".join((r.get("profile") or []) if isinstance(r, dict) else []),
                    "security_group": (r.get("securityGroup") if isinstance(r, dict) else "") or "",
                }
            )

    label = "radius" if domain == "network-access" else "tacacs"
    write_json(out_dir / f"{label}_policysets_full.json", full)
    _save_csv(
        out_dir / f"{label}_authentication_rules.csv",
        [
            "policy_set",
            "policy_set_id",
            "rule",
            "rule_id",
            "rank",
            "state",
            "hit_counts",
            "default",
            "condition",
            "condition_json",
            "identity_source",
        ],
        authn_rows,
    )
    _save_csv(
        out_dir / f"{label}_authorization_rules.csv",
        [
            "policy_set",
            "policy_set_id",
            "rule",
            "rule_id",
            "rank",
            "state",
            "hit_counts",
            "default",
            "condition",
            "condition_json",
            "profiles",
            "security_group",
        ],
        authz_rows,
    )
    print(f"  {label}: {len(sets)} policy sets, {len(authn_rows)} authn, {len(authz_rows)} authz/exception")


def json_dumps(obj) -> str:
    import json

    if obj is None:
        return ""
    return json.dumps(obj, ensure_ascii=False)


def export_condition_sheets(session, base: str, out_dir: Path, manifest: dict) -> None:
    for domain, prefix in (
        ("network-access", "radius"),
        ("device-admin", "tacacs"),
    ):
        root = f"/api/v1/policy/{domain}"
        for suffix, name in (
            ("/condition", "conditions_all"),
            ("/condition/authentication", "conditions_authentication"),
            ("/condition/authorization", "conditions_authorization"),
            ("/condition/policyset", "conditions_policyset"),
        ):
            data = _openapi_get(session, base, f"{root}{suffix}", manifest)
            if data is not None:
                write_json(out_dir / f"{prefix}_{name}.json", data)
                rows = []
                for c in unwrap(data):
                    if not isinstance(c, dict):
                        continue
                    rows.append(
                        {
                            "name": c.get("name"),
                            "id": c.get("id"),
                            "conditionType": c.get("conditionType"),
                            "isNegate": c.get("isNegate"),
                            "description": c.get("description"),
                            "flattened": flatten_condition(c),
                            "raw_json": json_dumps(c),
                        }
                    )
                _save_csv(
                    out_dir / f"{prefix}_{name}.csv",
                    [
                        "name",
                        "id",
                        "conditionType",
                        "isNegate",
                        "description",
                        "flattened",
                        "raw_json",
                    ],
                    rows,
                )


def export_name_id_list(session, base: str, path: str, out_name: str, out_dir: Path, manifest: dict):
    data = _openapi_get(session, base, path, manifest)
    if data is None:
        return
    write_json(out_dir / f"{out_name}.json", data)
    rows = []
    for it in unwrap(data):
        if isinstance(it, dict):
            row = {k: it.get(k) for k in ("name", "id", "description", "value", "generationId")}
            # keep extra scalar fields
            for k, v in it.items():
                if k not in row and not isinstance(v, (dict, list)):
                    row[k] = v
            rows.append(row)
    if rows:
        cols = sorted({k for r in rows for k in r.keys()})
        prefer = ["name", "id", "description"]
        fieldnames = [c for c in prefer if c in cols] + [c for c in cols if c not in prefer]
        _save_csv(out_dir / f"{out_name}.csv", fieldnames, rows)


def export_ers_inventory(session, host: str, out_dir: Path, manifest: dict) -> None:
    base_ers = f"https://{host}/ers/config"
    ers_dir = out_dir / "ers"
    ers_dir.mkdir(parents=True, exist_ok=True)

    # Network devices (NAD / RADIUS/TACACS clients)
    devices = _ers_list(session, base_ers, "networkdevice", manifest)
    if devices:
        detailed = []
        for d in devices:
            body = _ers_get(session, f"{base_ers}/networkdevice/{d.get('id')}")
            detailed.append(body or d)
        write_json(ers_dir / "networkdevices.json", detailed)
        rows = []
        for body in detailed:
            nd = body.get("NetworkDevice") if isinstance(body, dict) else None
            src = nd or (body if isinstance(body, dict) else {})
            ips = src.get("ipaddress") or src.get("NetworkDeviceIPList") or []
            ip_str = ""
            if isinstance(ips, list):
                parts = []
                for x in ips:
                    if isinstance(x, dict):
                        parts.append(x.get("ipaddress") or x.get("ipAddress") or "")
                    else:
                        parts.append(str(x))
                ip_str = ", ".join(p for p in parts if p)
            rows.append(
                {
                    "name": src.get("name") or body.get("name"),
                    "id": src.get("id") or body.get("id"),
                    "description": src.get("description") or body.get("description"),
                    "ips": ip_str,
                    "profileName": src.get("profileName"),
                    "coaPort": src.get("coaPort"),
                    "dtlsRequired": src.get("dtlsRequired"),
                    "raw_json": json_dumps(body),
                }
            )
        _save_csv(
            ers_dir / "networkdevices.csv",
            ["name", "id", "description", "ips", "profileName", "coaPort", "dtlsRequired", "raw_json"],
            rows,
        )

    for res, fname in (
        ("networkdevicegroup", "networkdevicegroups"),
        ("identitygroup", "identitygroups"),
        ("endpointgroup", "endpointgroups"),
        ("idstoresequence", "idstoresequences"),
    ):
        items = _ers_list(session, base_ers, res, manifest)
        if not items:
            continue
        detailed = []
        for it in items:
            body = _ers_get(session, f"{base_ers}/{res}/{it.get('id')}")
            detailed.append(body or it)
        write_json(ers_dir / f"{fname}.json", detailed)
        rows = []
        for body in detailed:
            # unwrap ERS wrapper key if present
            inner = body
            if isinstance(body, dict):
                for k, v in body.items():
                    if isinstance(v, dict) and ("name" in v or "id" in v):
                        inner = v
                        break
            if isinstance(inner, dict):
                rows.append(
                    {
                        "name": inner.get("name"),
                        "id": inner.get("id"),
                        "description": inner.get("description"),
                        "parent": inner.get("parent") or inner.get("parentId"),
                        "raw_json": json_dumps(body),
                    }
                )
        _save_csv(
            ers_dir / f"{fname}.csv",
            ["name", "id", "description", "parent", "raw_json"],
            rows,
        )

    # Local internal users — first page sample only (labs can have 25k+)
    users = _ers_list(session, base_ers, "internaluser", manifest, max_pages=1)
    if users:
        meta = manifest["ers"].get("internaluser") or {}
        total = meta.get("reported_total")
        write_json(
            ers_dir / "internalusers_meta.json",
            {"reported_total": total, "sample": users},
        )
        rows = [
            {
                "name": f"(estate total={total})",
                "id": "",
                "note": f"sample {len(users)} of {total}; full index/bodies skipped by default",
            }
        ] + [
            {
                "name": u.get("name"),
                "id": u.get("id"),
                "note": "sample page 1",
            }
            for u in users
        ]
        _save_csv(ers_dir / "internalusers.csv", ["name", "id", "note"], rows)
        print(f"  Internal users: sample {len(users)} (reported total={total})")

    # AuthZ profile bodies
    profiles = _ers_list(session, base_ers, "authorizationprofile", manifest)
    if profiles:
        pdir = ers_dir / "authorizationprofiles"
        pdir.mkdir(exist_ok=True)
        index = []
        rows = []
        for p in profiles:
            body = _ers_get(session, f"{base_ers}/authorizationprofile/{p.get('id')}")
            name = p.get("name") or "profile"
            safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)[:80]
            if body:
                write_json(pdir / f"{safe}.json", body)
            index.append({"name": p.get("name"), "id": p.get("id")})
            ap = (body or {}).get("AuthorizationProfile") if isinstance(body, dict) else None
            src = ap or body or p
            if isinstance(src, dict):
                rows.append(
                    {
                        "name": src.get("name") or p.get("name"),
                        "id": src.get("id") or p.get("id"),
                        "description": src.get("description"),
                        "accessType": src.get("accessType"),
                        "authzProfileType": src.get("authzProfileType"),
                        "vlan": json_dumps(src.get("vlan")),
                        "daclName": src.get("daclName"),
                        "airespaceACL": src.get("airespaceACL") or src.get("webRedirection"),
                        "raw_json": json_dumps(body or p),
                    }
                )
        write_json(ers_dir / "authorizationprofiles_index.json", index)
        _save_csv(
            ers_dir / "authorizationprofiles.csv",
            [
                "name",
                "id",
                "description",
                "accessType",
                "authzProfileType",
                "vlan",
                "daclName",
                "airespaceACL",
                "raw_json",
            ],
            rows,
        )

    # dACLs
    dacls = _ers_list(session, base_ers, "downloadableacl", manifest)
    if dacls:
        ddir = ers_dir / "dacls"
        ddir.mkdir(exist_ok=True)
        rows = []
        for d in dacls:
            body = _ers_get(session, f"{base_ers}/downloadableacl/{d.get('id')}")
            name = d.get("name") or "dacl"
            safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)[:80]
            if body:
                write_json(ddir / f"{safe}.json", body)
            da = (body or {}).get("DownloadableAcl") if isinstance(body, dict) else None
            src = da or body or d
            rows.append(
                {
                    "name": src.get("name") if isinstance(src, dict) else name,
                    "id": src.get("id") if isinstance(src, dict) else d.get("id"),
                    "dacl": src.get("dacl") if isinstance(src, dict) else "",
                    "raw_json": json_dumps(body or d),
                }
            )
        _save_csv(ers_dir / "dacls.csv", ["name", "id", "dacl", "raw_json"], rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Full ISE inventory pull (OpenAPI + ERS).")
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--host", default=None)
    ap.add_argument("--user", default=None)
    ap.add_argument("--password", default=None)
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()

    host, user, password = env_cred(args.host, args.user, args.password)
    if not host or not user or not password:
        sys.exit("Set ISE_HOST, ISE_USER, ISE_PASS (or pass --host/--user/--password).")

    out_dir = Path(args.outdir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = f"https://{host}"
    session = make_session(user, password, args.insecure)

    manifest = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "openapi": {},
        "ers": {},
    }

    print(f"Inventory pull from {base} → {out_dir}")

    # ISE servers (deployment)
    nodes = _openapi_get(session, base, "/api/v1/deployment/node", manifest)
    if nodes is not None:
        write_json(out_dir / "ise_nodes.json", nodes)
        rows = []
        for n in unwrap(nodes):
            if not isinstance(n, dict):
                continue
            rows.append(
                {
                    "hostname": n.get("hostname"),
                    "fqdn": n.get("fqdn"),
                    "ipAddress": n.get("ipAddress"),
                    "roles": ", ".join(n.get("roles") or []),
                    "services": ", ".join(n.get("services") or []),
                    "nodeStatus": n.get("nodeStatus"),
                }
            )
        _save_csv(
            out_dir / "ise_nodes.csv",
            ["hostname", "fqdn", "ipAddress", "roles", "services", "nodeStatus"],
            rows,
        )
        print(f"  ISE nodes: {len(rows)}")

    ng = _openapi_get(session, base, "/api/v1/deployment/node-group", manifest)
    if ng is not None:
        write_json(out_dir / "ise_node_groups.json", ng)

    # RADIUS + TACACS policy (full)
    print("  RADIUS (network-access) policy...")
    export_policy_domain(session, base, "network-access", out_dir, manifest)
    print("  TACACS (device-admin) policy...")
    export_policy_domain(session, base, "device-admin", out_dir, manifest)

    # Conditions + supporting objects
    print("  Conditions / dictionaries / stores...")
    export_condition_sheets(session, base, out_dir, manifest)
    export_name_id_list(
        session,
        base,
        "/api/v1/policy/network-access/dictionaries",
        "radius_dictionaries",
        out_dir,
        manifest,
    )
    export_name_id_list(
        session,
        base,
        "/api/v1/policy/network-access/authorization-profiles",
        "radius_authorization_profiles",
        out_dir,
        manifest,
    )
    export_name_id_list(
        session,
        base,
        "/api/v1/policy/network-access/security-groups",
        "security_groups",
        out_dir,
        manifest,
    )
    export_name_id_list(
        session,
        base,
        "/api/v1/policy/network-access/identity-stores",
        "identity_stores",
        out_dir,
        manifest,
    )
    export_name_id_list(
        session,
        base,
        "/api/v1/policy/device-admin/command-sets",
        "tacacs_command_sets",
        out_dir,
        manifest,
    )
    # tacacs profiles path varies by build
    export_name_id_list(
        session,
        base,
        "/api/v1/policy/device-admin/tacacs-profiles",
        "tacacs_profiles",
        out_dir,
        manifest,
    )
    export_name_id_list(
        session,
        base,
        "/api/v1/policy/network-access/network-condition",
        "radius_network_conditions",
        out_dir,
        manifest,
    )
    export_name_id_list(
        session,
        base,
        "/api/v1/policy/network-access/time-condition",
        "radius_time_conditions",
        out_dir,
        manifest,
    )

    # Endpoints (OpenAPI)
    eps = _openapi_get(session, base, "/api/v1/endpoint", manifest)
    if eps is not None:
        write_json(out_dir / "endpoints.json", eps)
        rows = []
        for e in unwrap(eps):
            if isinstance(e, dict):
                rows.append(
                    {
                        "name": e.get("name"),
                        "mac": e.get("mac"),
                        "id": e.get("id"),
                        "groupId": e.get("groupId"),
                        "profileId": e.get("profileId"),
                        "identityStore": e.get("identityStore"),
                        "staticGroupAssignment": e.get("staticGroupAssignment"),
                        "raw_json": json_dumps(e),
                    }
                )
        _save_csv(
            out_dir / "endpoints.csv",
            [
                "name",
                "mac",
                "id",
                "groupId",
                "profileId",
                "identityStore",
                "staticGroupAssignment",
                "raw_json",
            ],
            rows,
        )
        print(f"  Endpoints (OpenAPI list): {len(rows)}")

    # ERS-heavy objects
    print("  ERS inventory (devices, groups, local users, profiles, dACLs)...")
    export_ers_inventory(session, host, out_dir, manifest)

    write_json(out_dir / "manifest.json", manifest)
    ers_ok = any(v.get("ok") for v in manifest["ers"].values())
    if not ers_ok:
        print(
            "  NOTE: ERS returned redirects/HTML — network devices, identity groups, "
            "internal users, dACLs, full authz-profile bodies need ERS enabled in GUI."
        )
    print(f"Done. Manifest: {out_dir / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
