#!/usr/bin/env python3
"""
report_excel.py — Detailed Excel workbook from pull_ise_inventory.py output.

Sheets (when source files exist):
  Coverage, ISE_Servers, RADIUS_AuthN, RADIUS_AuthZ, TACACS_AuthN, TACACS_AuthZ,
  RADIUS_Conditions, TACACS_Conditions, Identity_Stores, Security_Groups,
  AuthZ_Profiles, Endpoints, Network_Devices, Device_Groups, Identity_Groups,
  Internal_Users, Endpoint_Groups, ID_Sequences, dACLs, Dictionaries, Command_Sets

Usage:
  python report_excel.py --indir D:\\job\\raw --outfile D:\\job\\reports\\ise_audit.xlsx
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

try:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
except ImportError:
    sys.exit("openpyxl required: pip install openpyxl")

HEADER_FILL = PatternFill("solid", fgColor="1F4E79")
HEADER_FONT = Font(bold=True, color="FFFFFF")
WARN_FILL = PatternFill("solid", fgColor="FFF2CC")


def _load_json(path: Path):
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _read_csv(path: Path) -> tuple[list[str], list[list]]:
    if not path.is_file():
        return [], []
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if not rows:
        return [], []
    return rows[0], rows[1:]


def _style_header(ws) -> None:
    for cell in ws[1]:
        cell.font = HEADER_FONT
        cell.fill = HEADER_FILL
        cell.alignment = Alignment(wrap_text=True, vertical="center")


def _autosize(ws, max_width: int = 60) -> None:
    for col in ws.columns:
        letter = get_column_letter(col[0].column)
        width = 10
        for cell in col[:200]:
            if cell.value is not None:
                width = max(width, min(max_width, len(str(cell.value)) + 2))
        ws.column_dimensions[letter].width = width


def _add_csv_sheet(wb: Workbook, title: str, path: Path, missing_note: str | None = None) -> int:
    headers, data = _read_csv(path)
    ws = wb.create_sheet(title[:31])
    if not headers:
        ws.append(["status", "detail"])
        _style_header(ws)
        ws.append(["MISSING", missing_note or f"No file: {path.name}"])
        ws["A2"].fill = WARN_FILL
        return 0
    ws.append(headers)
    _style_header(ws)
    for row in data:
        ws.append(row)
    _autosize(ws)
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    return len(data)


def _add_rows_sheet(wb: Workbook, title: str, headers: list[str], rows: list[list]) -> None:
    ws = wb.create_sheet(title[:31])
    ws.append(headers)
    _style_header(ws)
    for row in rows:
        ws.append(row)
    _autosize(ws)
    ws.freeze_panes = "A2"


def build_workbook(indir: Path) -> Workbook:
    wb = Workbook()
    wb.remove(wb.active)

    manifest = _load_json(indir / "manifest.json") or {}
    coverage_rows = [
        ["Field", "Value"],
        ["source_dir", str(indir.resolve())],
        ["host", manifest.get("host", "")],
        ["pulled_at_utc", manifest.get("timestamp", "")],
        ["generator", "nexthop-ise-devops audit/report_excel.py"],
    ]

    openapi = manifest.get("openapi") or {}
    ers = manifest.get("ers") or {}
    for path, info in sorted(openapi.items()):
        coverage_rows.append(
            [
                f"openapi:{path}",
                f"ok={info.get('ok')} status={info.get('status')} count={info.get('count')}",
            ]
        )
    if not ers:
        coverage_rows.append(
            [
                "ers",
                "NOT COLLECTED / DISABLED — enable ERS in API Settings for devices, "
                "identity groups, internal users, dACLs, full authz profile bodies",
            ]
        )
    for res, info in sorted(ers.items()):
        coverage_rows.append(
            [
                f"ers:{res}",
                f"ok={info.get('ok')} status={info.get('status')} "
                f"count={info.get('count')} note={info.get('note') or ''}",
            ]
        )

    _add_rows_sheet(wb, "Coverage", coverage_rows[0], coverage_rows[1:])
    for cell in wb["Coverage"]["B"]:
        if cell.row > 1 and "DISABLED" in str(cell.value or ""):
            cell.fill = WARN_FILL

    # Core sheets from inventory CSVs
    mapping = [
        ("ISE_Servers", "ise_nodes.csv", "ISE deployment nodes (OpenAPI)"),
        ("RADIUS_AuthN", "radius_authentication_rules.csv", "RADIUS AuthN rules"),
        ("RADIUS_AuthZ", "radius_authorization_rules.csv", "RADIUS AuthZ + exceptions"),
        ("TACACS_AuthN", "tacacs_authentication_rules.csv", "TACACS AuthN rules"),
        ("TACACS_AuthZ", "tacacs_authorization_rules.csv", "TACACS AuthZ + exceptions"),
        ("RADIUS_Conditions", "radius_conditions_all.csv", "RADIUS condition library"),
        ("RADIUS_Cond_AuthN", "radius_conditions_authentication.csv", "RADIUS AuthN conditions"),
        ("RADIUS_Cond_AuthZ", "radius_conditions_authorization.csv", "RADIUS AuthZ conditions"),
        ("TACACS_Conditions", "tacacs_conditions_all.csv", "TACACS condition library"),
        ("TACACS_Cond_AuthN", "tacacs_conditions_authentication.csv", "TACACS AuthN conditions"),
        ("TACACS_Cond_AuthZ", "tacacs_conditions_authorization.csv", "TACACS AuthZ conditions"),
        ("Network_Conditions", "radius_network_conditions.csv", "Network conditions"),
        ("Time_Conditions", "radius_time_conditions.csv", "Time/date conditions"),
        ("Identity_Stores", "identity_stores.csv", "Identity stores (OpenAPI)"),
        ("Security_Groups", "security_groups.csv", "TrustSec SGTs (OpenAPI)"),
        ("AuthZ_Profiles", "radius_authorization_profiles.csv", "AuthZ profile name/id (OpenAPI)"),
        ("Command_Sets", "tacacs_command_sets.csv", "TACACS command sets"),
        ("Dictionaries", "radius_dictionaries.csv", "RADIUS dictionaries"),
        ("Endpoints", "endpoints.csv", "Endpoints (OpenAPI list)"),
        ("Network_Devices", "ers/networkdevices.csv", "NADs — requires ERS already enabled"),
        ("Device_Groups", "ers/networkdevicegroups.csv", "Network device groups — requires ERS"),
        ("Identity_Groups", "ers/identitygroups.csv", "Identity groups — requires ERS"),
        ("Internal_Users", "ers/internalusers.csv", "Local internal users — requires ERS"),
        ("Endpoint_Groups", "ers/endpointgroups.csv", "Endpoint identity groups — requires ERS"),
        ("ID_Sequences", "ers/idstoresequences.csv", "Identity source sequences — requires ERS"),
        ("dACLs", "ers/dacls.csv", "Downloadable ACLs — requires ERS"),
        ("AuthZ_Profile_Bodies", "ers/authorizationprofiles.csv", "Full AuthZ profiles — requires ERS"),
    ]

    counts = {}
    for title, rel, note in mapping:
        counts[title] = _add_csv_sheet(wb, title, indir / rel, missing_note=note)

    # Summary counts on Coverage
    cov = wb["Coverage"]
    cov.append(["", ""])
    cov.append(["Sheet", "Row count"])
    for title, n in counts.items():
        cov.append([title, n])

    return wb


def main() -> int:
    ap = argparse.ArgumentParser(description="Build detailed Excel from inventory pull.")
    ap.add_argument("--indir", required=True, help="Folder from pull_ise_inventory.py")
    ap.add_argument("--outfile", default="./outdir/ise_audit.xlsx")
    args = ap.parse_args()

    indir = Path(args.indir)
    if not indir.is_dir():
        sys.exit(f"Not a directory: {indir}")

    outfile = Path(args.outfile)
    outfile.parent.mkdir(parents=True, exist_ok=True)
    wb = build_workbook(indir)
    wb.save(outfile)
    print(f"Wrote {outfile} ({len(wb.sheetnames)} sheets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
