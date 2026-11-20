#!/usr/bin/env python3
"""
report_policy_xlsx.py — ISE policy cross-reference workbook (RADIUS + TACACS).

Produces BOTH:
  RADIUS (network-access) — Authentication, Authorization, Profiles, dACLs, …
  TACACS (device-admin)  — Authentication, Authorization, Command Sets, …

Sheet layout matches NextHop engagement policy workbooks, extended with a
TACACS section and inventory tabs.

Usage:
  python report_policy_xlsx.py --indir D:\\job\\raw\\inventory \\
      --outfile D:\\job\\reports\\ISE_Policies.xlsx --customer "Acme"
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
except ImportError:
    sys.exit("openpyxl required: pip install openpyxl")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ise_common import flatten_condition  # noqa: E402

HEADER_FILL = PatternFill("solid", fgColor="1F4E79")
HEADER_FONT = Font(bold=True, color="FFFFFF")
TITLE_FONT = Font(bold=True, size=16)
SECTION_FILL = PatternFill("solid", fgColor="D6E3F0")


def _load_json(path: Path):
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _read_csv_dicts(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _style_header(ws) -> None:
    for cell in ws[1]:
        cell.font = HEADER_FONT
        cell.fill = HEADER_FILL
        cell.alignment = Alignment(wrap_text=True, vertical="center")


def _autosize(ws, max_width: int = 55) -> None:
    for col in ws.columns:
        letter = get_column_letter(col[0].column)
        width = 12
        for cell in col[:300]:
            if cell.value is not None:
                width = max(width, min(max_width, len(str(cell.value)) + 2))
        ws.column_dimensions[letter].width = width


def _add_sheet(wb: Workbook, title: str, headers: list[str], rows: list[list]) -> None:
    ws = wb.create_sheet(title[:31])
    ws.append(headers)
    _style_header(ws)
    for row in rows:
        ws.append(row)
    _autosize(ws)
    ws.freeze_panes = "A2"
    if rows:
        ws.auto_filter.ref = ws.dimensions


def infer_medium(condition_text: str) -> str:
    t = condition_text or ""
    hits = []
    checks = [
        ("wireless-dot1x", r"Wireless_802\.1X|Wireless_Dot1X"),
        ("wired-dot1x", r"Wired_802\.1X|Wired_Dot1X"),
        ("wireless-MAB", r"Wireless_MAB"),
        ("wired-MAB", r"Wired_MAB"),
        ("wireless", r"Wireless_Access|Wireless_"),
        ("wired", r"Wired_Access|Wired_"),
    ]
    for label, pat in checks:
        if re.search(pat, t, re.I):
            hits.append(label)
    if not hits:
        return ""
    # prefer more specific
    for pref in ("wireless-dot1x", "wired-dot1x", "wireless-MAB", "wired-MAB", "wireless", "wired"):
        if pref in hits:
            return pref
    return hits[0]


def classify_dacl(ace: str, access_type: str = "") -> str:
    at = (access_type or "").upper()
    if at in ("REJECT", "DENY"):
        return "DENY"
    body = (ace or "").lower()
    if not body.strip():
        return "OPEN (no dACL/VLAN)" if at in ("", "ACCEPT", "ACCESS_ACCEPT") else at or "UNKNOWN"
    if "deny ip any any" in body and "permit ip any any" not in body:
        return "DENY"
    if "permit ip any any" in body or "permit ipv6 any any" in body:
        return "OPEN (permit ip any any)"
    return "SCOPED"


def load_profile_index(indir: Path) -> dict[str, dict]:
    """name -> {accessType, daclName, vlan, reauth, advanced, raw}"""
    out: dict[str, dict] = {}
    # OpenAPI name/id list
    for row in _read_csv_dicts(indir / "radius_authorization_profiles.csv"):
        name = row.get("name") or ""
        if name:
            out.setdefault(name, {"name": name, "id": row.get("id")})
    # ERS bodies
    ers_csv = indir / "ers" / "authorizationprofiles.csv"
    for row in _read_csv_dicts(ers_csv):
        name = row.get("name") or ""
        if not name:
            continue
        out[name] = {
            "name": name,
            "id": row.get("id"),
            "accessType": row.get("accessType") or "",
            "daclName": row.get("daclName") or "",
            "vlan": row.get("vlan") or "",
            "authzProfileType": row.get("authzProfileType") or "",
            "airespaceACL": row.get("airespaceACL") or "",
            "raw_json": row.get("raw_json") or "",
        }
    # Also parse JSON bodies folder for richer fields
    pdir = indir / "ers" / "authorizationprofiles"
    if pdir.is_dir():
        for fp in pdir.glob("*.json"):
            body = _load_json(fp)
            if not isinstance(body, dict):
                continue
            ap = body.get("AuthorizationProfile") or body
            name = ap.get("name") or ""
            if not name:
                continue
            advanced = []
            for attr in ap.get("advancedAttributes") or []:
                if isinstance(attr, dict):
                    left = attr.get("leftHandSideDictionaryAttribue") or attr.get(
                        "leftHandSideDictionaryAttribute"
                    )
                    # ERS schema varies; keep raw dump short
                    advanced.append(json.dumps(attr, ensure_ascii=False)[:120])
            # common ERS fields
            dacl = ap.get("daclName") or ""
            vlan = ""
            if isinstance(ap.get("vlan"), dict):
                vlan = str(ap["vlan"].get("tagID") or ap["vlan"].get("name") or "")
            elif ap.get("vlan"):
                vlan = str(ap.get("vlan"))
            reauth = ""
            if isinstance(ap.get("reauth"), dict):
                reauth = str(ap["reauth"].get("timer") or "")
            out[name] = {
                "name": name,
                "id": ap.get("id"),
                "accessType": ap.get("accessType") or "",
                "daclName": dacl,
                "vlan": vlan,
                "reauth": reauth,
                "autoSmartPort": ap.get("autoSmartPort") or "",
                "advanced": "; ".join(advanced),
                "raw_json": json.dumps(body, ensure_ascii=False),
            }
    return out


def load_dacls(indir: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for row in _read_csv_dicts(indir / "ers" / "dacls.csv"):
        name = row.get("name") or ""
        if name:
            out[name] = {
                "name": name,
                "dacl": row.get("dacl") or "",
                "id": row.get("id"),
            }
    ddir = indir / "ers" / "dacls"
    if ddir.is_dir():
        for fp in ddir.glob("*.json"):
            body = _load_json(fp)
            if not isinstance(body, dict):
                continue
            da = body.get("DownloadableAcl") or body
            name = da.get("name") or ""
            if name:
                out[name] = {
                    "name": name,
                    "dacl": da.get("dacl") or "",
                    "id": da.get("id"),
                    "daclType": da.get("daclType") or "",
                }
    return out


def build_radius_authn_rows(policysets: list) -> list[list]:
    rows = []
    for block in policysets or []:
        ps = (block.get("policySet") or {}).get("name") or ""
        for r in block.get("authentication") or []:
            rule = r.get("rule") or {}
            rows.append(
                [
                    rule.get("rank", ""),
                    rule.get("name", ""),
                    flatten_condition(rule.get("condition")) or (
                        "ANY (default)" if rule.get("default") else ""
                    ),
                    r.get("identitySourceName") or "",
                    r.get("ifUserNotFound") or "",
                    r.get("ifAuthFail") or "",
                    rule.get("hitCounts", ""),
                    rule.get("state", ""),
                    ps,
                ]
            )
    rows.sort(key=lambda x: (str(x[8]), int(x[0]) if str(x[0]).isdigit() else 9999))
    return rows


def build_radius_authz_rows(policysets: list, profiles: dict, dacls: dict) -> list[list]:
    rows = []
    for block in policysets or []:
        ps = (block.get("policySet") or {}).get("name") or ""
        for r in (block.get("authorization") or []) + (block.get("exception") or []):
            rule = r.get("rule") or {}
            cond = flatten_condition(rule.get("condition"))
            profs = r.get("profile") or []
            if isinstance(profs, str):
                profs = [profs]
            profile_name = ", ".join(profs)
            primary = profs[0] if profs else ""
            pinfo = profiles.get(primary) or {}
            dacl_name = pinfo.get("daclName") or ""
            ace = (dacls.get(dacl_name) or {}).get("dacl") or ""
            effective = classify_dacl(ace, pinfo.get("accessType") or "")
            sgt = r.get("securityGroup") or ""
            rows.append(
                [
                    rule.get("rank", ""),
                    rule.get("name", ""),
                    rule.get("state", ""),
                    infer_medium(cond),
                    cond,
                    profile_name,
                    dacl_name,
                    effective,
                    rule.get("hitCounts", ""),
                    sgt if isinstance(sgt, str) else json.dumps(sgt),
                    ps,
                ]
            )
    rows.sort(key=lambda x: (str(x[10]), int(x[0]) if str(x[0]).isdigit() else 9999))
    return rows


def build_tacacs_authn_rows(policysets: list) -> list[list]:
    rows = []
    for block in policysets or []:
        ps = (block.get("policySet") or {}).get("name") or ""
        for r in block.get("authentication") or []:
            rule = r.get("rule") or {}
            rows.append(
                [
                    rule.get("rank", ""),
                    rule.get("name", ""),
                    flatten_condition(rule.get("condition"))
                    or ("ANY (default)" if rule.get("default") else ""),
                    r.get("identitySourceName") or "",
                    r.get("ifUserNotFound") or "",
                    r.get("ifAuthFail") or "",
                    rule.get("hitCounts", ""),
                    rule.get("state", ""),
                    ps,
                ]
            )
    return rows


def build_tacacs_authz_rows(policysets: list) -> list[list]:
    """TACACS AuthZ: profiles often are command-sets / shell profiles."""
    rows = []
    for block in policysets or []:
        ps = (block.get("policySet") or {}).get("name") or ""
        for r in (block.get("authorization") or []) + (block.get("exception") or []):
            rule = r.get("rule") or {}
            cond = flatten_condition(rule.get("condition"))
            # device-admin uses commands / profile fields depending on build
            commands = r.get("commands") or r.get("commandSets") or []
            profile = r.get("profile") or r.get("shellProfile") or []
            if isinstance(commands, str):
                commands = [commands]
            if isinstance(profile, str):
                profile = [profile]
            rows.append(
                [
                    rule.get("rank", ""),
                    rule.get("name", ""),
                    rule.get("state", ""),
                    cond or ("ANY (default)" if rule.get("default") else ""),
                    ", ".join(commands) if commands else "",
                    ", ".join(profile) if profile else "",
                    rule.get("hitCounts", ""),
                    ps,
                    json.dumps(r, ensure_ascii=False)[:500],
                ]
            )
    return rows


def build_workbook(indir: Path, customer: str) -> Workbook:
    wb = Workbook()
    wb.remove(wb.active)

    radius_ps = _load_json(indir / "radius_policysets_full.json") or []
    tacacs_ps = _load_json(indir / "tacacs_policysets_full.json") or []
    profiles = load_profile_index(indir)
    dacls = load_dacls(indir)
    manifest = _load_json(indir / "manifest.json") or {}

    radius_authn = build_radius_authn_rows(radius_ps)
    radius_authz = build_radius_authz_rows(radius_ps, profiles, dacls)
    tacacs_authn = build_tacacs_authn_rows(tacacs_ps)
    tacacs_authz = build_tacacs_authz_rows(tacacs_ps)

    # --- Overview ---
    ws = wb.create_sheet("Overview", 0)
    ws["A1"] = f"{customer} — Cisco ISE Policy Cross-Reference"
    ws["A1"].font = TITLE_FONT
    ws["A2"] = (
        f"RADIUS + TACACS · Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC · "
        f"Source: {manifest.get('host') or indir}"
    )
    ws["A4"] = "Workbook contents"
    ws["A4"].font = Font(bold=True)
    overview_rows = [
        ("RADIUS Authentication", f"{len(radius_authn)} authentication rules"),
        ("RADIUS Authorization", f"{len(radius_authz)} authorization rules (condition→profile→dACL)"),
        ("RADIUS Profiles", f"{len(profiles)} authorization profiles"),
        ("RADIUS dACLs", f"{len(dacls)} downloadable ACLs"),
        ("TACACS Authentication", f"{len(tacacs_authn)} authentication rules"),
        ("TACACS Authorization", f"{len(tacacs_authz)} authorization rules"),
        ("ISE Servers", "Deployment nodes"),
        ("Inventory", "Network devices, groups, identity stores, local users (when ERS available)"),
        ("Findings", "Auto hygiene notes (not a substitute for engineer review)"),
    ]
    ws.append([])
    ws["A5"] = "Sheet"
    ws["B5"] = "Summary"
    _style_header(ws)
    # fix: we already have header style on row 1 from mistake - rebuild simply
    for i, (a, b) in enumerate(overview_rows, start=6):
        ws.cell(i, 1, a)
        ws.cell(i, 2, b)
    ws.column_dimensions["A"].width = 28
    ws.column_dimensions["B"].width = 70

    # RADIUS AuthN
    _add_sheet(
        wb,
        "RADIUS Authentication",
        [
            "Rank",
            "Rule",
            "Match",
            "Identity store",
            "If user-not-found",
            "If auth-fail",
            "Hits",
            "State",
            "Policy set",
        ],
        radius_authn,
    )

    # RADIUS AuthZ
    _add_sheet(
        wb,
        "RADIUS Authorization",
        [
            "Rank",
            "Rule",
            "State",
            "Medium",
            "Condition (resolved)",
            "Profile",
            "dACL",
            "Effective access",
            "Hits",
            "SGT",
            "Policy set",
        ],
        radius_authz,
    )

    # Profiles
    profile_rows = []
    used_profiles = Counter()
    for r in radius_authz:
        for name in str(r[5]).split(", "):
            if name:
                used_profiles[name] += 1
    for name, p in sorted(profiles.items()):
        profile_rows.append(
            [
                name,
                p.get("accessType") or "",
                p.get("daclName") or "",
                p.get("vlan") or "",
                p.get("reauth") or "",
                p.get("autoSmartPort") or "",
                p.get("advanced") or "",
                used_profiles.get(name, 0),
            ]
        )
    _add_sheet(
        wb,
        "RADIUS Profiles",
        [
            "Profile",
            "Access type",
            "dACL",
            "VLAN",
            "Reauth timer",
            "autoSmartPort",
            "Advanced attributes",
            "# authZ rules",
        ],
        profile_rows,
    )

    # dACLs in use + all
    dacl_use = Counter()
    for p in profiles.values():
        dn = p.get("daclName") or ""
        if dn:
            dacl_use[dn] += 1
    dacl_rows = []
    for name, d in sorted(dacls.items()):
        ace = d.get("dacl") or ""
        dacl_rows.append(
            [
                name,
                dacl_use.get(name, 0),
                classify_dacl(ace),
                ace,
                d.get("daclType") or "",
                "YES" if dacl_use.get(name) else "",
            ]
        )
    _add_sheet(
        wb,
        "RADIUS dACLs",
        ["dACL name", "# profiles using", "Classification", "ACE body", "Type", "Used by policy?"],
        dacl_rows,
    )

    # Effective access rollup (enabled RADIUS authZ)
    eff = Counter()
    enabled = 0
    for r in radius_authz:
        if str(r[2]).lower() == "enabled":
            enabled += 1
            eff[str(r[7])] += 1
    _add_sheet(
        wb,
        "RADIUS Effective Access",
        ["Effective access (enabled rules)", "Count"],
        [[k, v] for k, v in eff.most_common()] + [["Total enabled", enabled]],
    )

    # TACACS
    _add_sheet(
        wb,
        "TACACS Authentication",
        [
            "Rank",
            "Rule",
            "Match",
            "Identity store",
            "If user-not-found",
            "If auth-fail",
            "Hits",
            "State",
            "Policy set",
        ],
        tacacs_authn,
    )
    _add_sheet(
        wb,
        "TACACS Authorization",
        [
            "Rank",
            "Rule",
            "State",
            "Condition (resolved)",
            "Command sets",
            "Shell / profile",
            "Hits",
            "Policy set",
            "Raw (preview)",
        ],
        tacacs_authz,
    )
    cmd_rows = [[r.get("name"), r.get("id"), r.get("description")] for r in _read_csv_dicts(indir / "tacacs_command_sets.csv")]
    _add_sheet(wb, "TACACS Command Sets", ["Name", "Id", "Description"], cmd_rows)

    # Custom conditions (RADIUS library)
    cond_rows = []
    for row in _read_csv_dicts(indir / "radius_conditions_all.csv"):
        cond_rows.append([row.get("name"), row.get("conditionType") or row.get("flattened")])
    _add_sheet(wb, "RADIUS Conditions", ["Custom / library condition", "Type / flattened"], cond_rows)

    tac_cond = []
    for row in _read_csv_dicts(indir / "tacacs_conditions_all.csv"):
        tac_cond.append([row.get("name"), row.get("conditionType") or row.get("flattened")])
    _add_sheet(wb, "TACACS Conditions", ["Custom / library condition", "Type / flattened"], tac_cond)

    # Inventory
    for title, path, cols in [
        ("ISE Servers", "ise_nodes.csv", None),
        ("Network Devices", "ers/networkdevices.csv", None),
        ("Device Groups", "ers/networkdevicegroups.csv", None),
        ("Identity Groups", "ers/identitygroups.csv", None),
        ("Internal Users", "ers/internalusers.csv", None),
        ("Endpoint Groups", "ers/endpointgroups.csv", None),
        ("ID Sequences", "ers/idstoresequences.csv", None),
        ("Identity Stores", "identity_stores.csv", None),
        ("Security Groups", "security_groups.csv", None),
    ]:
        rows_d = _read_csv_dicts(indir / path)
        if not rows_d:
            _add_sheet(wb, title, ["status"], [["MISSING — enable ERS and re-pull" if path.startswith("ers/") else "MISSING"]])
            continue
        headers = list(rows_d[0].keys())
        # drop huge raw_json from identity groups for readability in main view
        if "raw_json" in headers and title in ("Identity Groups", "Internal Users"):
            headers = [h for h in headers if h != "raw_json"]
        _add_sheet(wb, title, headers, [[r.get(h, "") for h in headers] for r in rows_d])

    # Findings (lightweight auto)
    findings = []
    open_count = sum(1 for r in radius_authz if str(r[2]).lower() == "enabled" and "OPEN (permit" in str(r[7]))
    if open_count:
        findings.append(
            [
                "F1",
                "INFO",
                "Broad OPEN effective access",
                f"{open_count} enabled RADIUS authZ rules resolve to permit ip any any / OPEN",
            ]
        )
    zero_hit = sum(1 for r in radius_authz if str(r[2]).lower() == "enabled" and str(r[8]) in ("0", "0.0"))
    if zero_hit:
        findings.append(
            [
                "F2",
                "LOW",
                "Enabled rules with zero hits",
                f"{zero_hit} enabled RADIUS authZ rules show hitCounts=0",
            ]
        )
    if not dacls:
        findings.append(
            [
                "F3",
                "MED",
                "No dACL bodies pulled",
                "ERS dACLs missing — profile→dACL→effective access incomplete until ERS dACL pull succeeds",
            ]
        )
    if not tacacs_authz:
        findings.append(["F4", "INFO", "No TACACS authZ rules", "Device-admin policy set empty or unavailable"])
    _add_sheet(wb, "Findings", ["ID", "Severity", "Finding", "Detail"], findings)

    return wb


def main() -> int:
    ap = argparse.ArgumentParser(description="RADIUS+TACACS ISE policy cross-reference workbook.")
    ap.add_argument("--indir", required=True)
    ap.add_argument("--outfile", default="./outdir/ISE_Policies.xlsx")
    ap.add_argument("--customer", default="ISE engagement")
    args = ap.parse_args()

    indir = Path(args.indir)
    if not indir.is_dir():
        sys.exit(f"Not a directory: {indir}")
    outfile = Path(args.outfile)
    outfile.parent.mkdir(parents=True, exist_ok=True)
    wb = build_workbook(indir, args.customer)
    wb.save(outfile)
    print(f"Wrote {outfile} ({len(wb.sheetnames)} sheets): {', '.join(wb.sheetnames)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
