# Cisco ISE DevOps + Audit Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Public **read-only** Cisco ISE assessment toolkit from [NextHop](https://nexthopllc.com).

Pull **RADIUS + TACACS** policy (full AuthN/AuthZ + conditions), inventory (nodes,
devices, groups, stores), then build an engagement-style **Excel policy
cross-reference** — including on an **air-gapped** laptop (no internet / no AI on site).

| Area | What |
|---|---|
| [`audit/connectivity_check.py`](audit/connectivity_check.py) | Preflight: host/user/pass → checklist (Gateway/OpenAPI/ERS) |
| [`audit/pull_ise_inventory.py`](audit/pull_ise_inventory.py) | **Primary** GET-only OpenAPI + ERS inventory |
| [`audit/report_policy_xlsx.py`](audit/report_policy_xlsx.py) | RADIUS + TACACS policy cross-reference Excel |
| [`audit/*.ps1`](audit/) | Classic PowerShell ERS collectors |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Operator steps |
| [`docs/AIRGAP.md`](docs/AIRGAP.md) | USB / offline wheelhouse |

**License:** MIT — see [LICENSE](LICENSE) and [NOTICE](NOTICE).  
**Customer exports** (JSON/CSV/XLSX/PDF) are engagement data — **not** open source.

## Security rules

1. Do **not** commit exports (policy names, dACLs, groups, hostnames).
2. `customer_config.py` is gitignored — copy from `customer_config_example.py`.
3. No real customer hostnames/passwords in examples or docs.
4. Always set `--outdir` / `--outfile` **outside** this git tree.

## Prerequisites

| Requirement | Notes |
|---|---|
| Python **3.12+** | 3.13 tested |
| ISE API Gateway | On (TCP 443) |
| OpenAPI | On — needed for RADIUS/TACACS policy |
| ERS | On — needed for devices, groups, dACL/profile bodies |
| API account | Super Admin or ERS Admin / Operator |
| PowerShell 5.1+ | Optional; for `audit/*.ps1` |

### Enable APIs on ISE (GUI — change control)

**Administration → System → Settings → API Settings**

1. Enable **API Gateway** on the PAN  
2. Enable **OpenAPI** (Read/Write on PAN)  
3. Enable **ERS** (Read/Write on PAN)  
4. Prefer CSRF disabled for read-only audit clients unless you know the token flow  

## Install (online laptop)

```powershell
git clone https://github.com/devnexthop/ise-audit.git
cd ise-audit
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Air-gap / USB pack: [`docs/AIRGAP.md`](docs/AIRGAP.md).

## How to run (PowerShell) — recommended

Reads only (HTTP **GET**). Does **not** change ISE.

```powershell
cd C:\path\to\ise-audit
.\.venv\Scripts\Activate.ps1

# Engagement folder OUTSIDE git (USB or local scratch)
$out = "D:\ise-engagements\customer-YYYYMMDD"
New-Item -ItemType Directory -Force -Path "$out\raw\inventory","$out\reports" | Out-Null

$env:ISE_HOST = "ise-pan.example.com"   # FQDN or IP, no https://
$env:ISE_USER = "apiadmin"
$env:ISE_PASS = "********"              # or prompt — do not commit

# Preflight checklist (prompts for host/user/pass if not set)
python audit\connectivity_check.py --insecure
# or non-interactive:
# python audit\connectivity_check.py --host $env:ISE_HOST --user $env:ISE_USER --insecure

# Full inventory: OpenAPI policy + ERS devices/groups/profiles/dACLs
python audit\pull_ise_inventory.py --outdir "$out\raw\inventory" --insecure

# Policy cross-reference Excel: RADIUS + TACACS + inventory sheets
python audit\report_policy_xlsx.py `
  --indir  "$out\raw\inventory" `
  --outfile "$out\reports\ISE_Policies_RADIUS_TACACS.xlsx" `
  --customer "Customer Name"

# Optional PDF summary
python audit\report_pdf.py `
  --indir "$out\raw\inventory" `
  --outfile "$out\reports\ise_audit.pdf" `
  --customer "Customer Name"
```

Use `--insecure` only for lab / self-signed PAN certificates. Drop it when the
PAN presents a trusted cert.

### What the Excel contains

| Sheet group | Contents |
|---|---|
| **RADIUS** | Authentication, Authorization (condition→profile→dACL→effective access), Profiles, dACLs, Conditions |
| **TACACS** | Authentication, Authorization, Command Sets, Conditions |
| **Inventory** | ISE servers, network devices, device groups, identity groups, stores, SGTs, … |
| **Findings** | Lightweight hygiene notes (engineer still reviews) |

Internal users on huge estates (10k+) are sampled by default — not every user body.

## API surface (what we call)

Custom Python (`requests`) — **not** dependent on ciscoisesdk for the audit path.

| API | Examples | Used for |
|---|---|---|
| **OpenAPI** `/api/v1/...` | `policy/network-access/policy-set/.../authentication\|authorization`, `policy/device-admin/...`, `deployment/node`, conditions, dictionaries | RADIUS + TACACS policy detail |
| **ERS** `/ers/config/...` | `networkdevice`, `networkdevicegroup`, `identitygroup`, `authorizationprofile/{id}`, `downloadableacl/{id}`, … | Devices, groups, profile/dACL bodies |

Docs: [Cisco ISE API (DevNet)](https://developer.cisco.com/docs/identity-services-engine/latest/).

## PowerShell ERS collectors (optional)

Same ERS objects as the Python inventory, classic script style:

```powershell
cd audit
powershell -ExecutionPolicy Bypass -File .\ers_diag.ps1 -Pan ise-pan.example.com
powershell -ExecutionPolicy Bypass -File .\pull_ise_objects.ps1 -Pan ise-pan.example.com
powershell -ExecutionPolicy Bypass -File .\fetch_auth_profiles.ps1 -Pan ise-pan.example.com
```

Run these from an engagement working directory so JSON does not land in git.

## Optional: enable API services via script

**Writes to ISE** — only with change approval:

```powershell
python audit\enable_api_services.py --host $env:ISE_HOST --insecure          # show
python audit\enable_api_services.py --host $env:ISE_HOST --insecure --enable # change
```

## Config export / import (separate tools)

```powershell
copy customer_config_example.py customer_config.py
# edit locally — never commit
python ise_export.py
python ise_import.py C:\path\to\export.json
```

## Repository layout

```text
ise-audit/
├── audit/
│   ├── pull_ise_inventory.py    # primary GET inventory
│   ├── report_policy_xlsx.py    # RADIUS+TACACS Excel
│   ├── report_excel.py / report_pdf.py / sdk_smoke.py
│   ├── enable_api_services.py   # optional WRITE
│   ├── ise_common.py
│   ├── ise_policy_export.py     # legacy OpenAPI CSV export
│   └── *.ps1                    # ERS PowerShell collectors
├── docs/                        # RUNBOOK, AIRGAP, kickoff PPT
├── ise_export.py / ise_import.py
├── customer_config_example.py
├── requirements.txt
├── LICENSE / NOTICE / SECURITY.md / CONTRIBUTING.md
└── README.md
```

## References

- [Cisco ISE API docs](https://developer.cisco.com/docs/identity-services-engine/latest/)
- [ciscoisesdk (PyPI)](https://pypi.org/project/ciscoisesdk/) — optional smoke only
- [ISE DevNet hub](https://developer.cisco.com/identity-services-engine/)

## License

MIT — see [LICENSE](LICENSE). Third-party: [NOTICE](NOTICE).
