# ISE Audit Scripts

Read-only collection helpers for Cisco ISE assessments. Credentials are prompted
or taken from environment variables — nothing is hard-coded.

**Never commit script output.** Exports contain customer policy, dACLs, and
identity-group names.

## Prerequisites

| Requirement | Notes |
|---|---|
| PowerShell 5.1+ (Windows) or PowerShell 7+ | Native `Invoke-WebRequest` |
| Python 3.12+ + `requirements.txt` | `ciscoisesdk`, `requests`, Excel/PDF libs |
| ISE API Gateway + OpenAPI (ERS for `*.ps1`) | Admin → System → Settings → API Settings |
| Account with API RBAC | ERS Admin or Super Admin |

Scripts accept self-signed PAN certificates (lab-friendly). Prefer proper TLS
validation in production when you can.

## Recommended order

```text
1. connectivity_check.py     # enter host/user/pass — checklist all API boxes
2. pull_ise_inventory.py     # FULL GET inventory (OpenAPI + ERS)
3. report_policy_xlsx.py     # RADIUS + TACACS policy cross-reference Excel (primary)
4. report_pdf.py             # optional PDF summary
5. ers_diag.ps1 + pull_*.ps1 # optional classic PowerShell ERS collectors
```

### One-shot (PowerShell)

```powershell
$out = "D:\ise-engagements\job"
$env:ISE_HOST = "ise-pan.example.com"
$env:ISE_USER = "apiadmin"
$env:ISE_PASS = "********"

python connectivity_check.py --insecure
python pull_ise_inventory.py --outdir "$out\raw\inventory" --insecure
python report_policy_xlsx.py --indir "$out\raw\inventory" `
  --outfile "$out\reports\ISE_Policies_RADIUS_TACACS.xlsx" --customer "Acme"
```

### `connectivity_check.py`

Interactive (or `--host` / `--user` / `--password` / env) preflight. Prints `[OK]` /
`[FAIL]` for: TCP 443, API Gateway, OpenAPI, RADIUS policy API, TACACS policy API,
ERS. Exit code `0` only when required boxes pass.

```powershell
python connectivity_check.py --insecure
python connectivity_check.py --host ise-pan.example.com --user apiadmin --insecure
```

**OpenAPI** → ISE servers, RADIUS/TACACS policy (full AuthN/AuthZ + conditions),
identity stores, SGTs, dictionaries.  
**ERS** → network devices, device/identity/endpoint groups, dACL bodies, AuthZ
profile bodies. Internal users are **sampled** on large estates (not 25k by-id GETs).

Always use `--outdir` / `--outfile` outside this repo. See [`docs/AIRGAP.md`](../docs/AIRGAP.md)
and the root [`README.md`](../README.md).

## Scripts

### `pull_ise_inventory.py`

Primary **GET-only** collector (custom `requests`, not SDK-driven). Writes OpenAPI
+ ERS artifacts under `--outdir` plus `manifest.json`.

### `report_policy_xlsx.py`

Primary customer Excel: RADIUS + TACACS sheets
(Authentication, Authorization with condition→profile→dACL→effective access,
Profiles, dACLs, inventory tabs).

### `sdk_smoke.py`

Optional `ciscoisesdk` checks. Treats HTTP 200 + login HTML as failure.

```powershell
python sdk_smoke.py --outdir D:\ise-engagements\job\raw --insecure
```

### `enable_api_services.py`

Shows `/admin/API/apiService/get`. With `--enable`, **writes** to ISE (change control).

### `report_excel.py` / `report_pdf.py`

Alternate/legacy inventory Excel and PDF summary from `--indir`.

```powershell
python report_excel.py --indir D:\job\raw\inventory --outfile D:\job\reports\ise_audit.xlsx
python report_pdf.py --indir D:\job\raw\inventory --outfile D:\job\reports\ise_audit.pdf --customer "Acme"
```

### `ers_diag.ps1`

Connectivity smoke test. Hits ERS on 443 and 9060, with and without `size=`
paging. Use this when collections mysteriously 404 — some ISE builds reject
`?size=` on certain resources.

```powershell
powershell -ExecutionPolicy Bypass -File .\ers_diag.ps1 -Pan ise-pan.example.com
```

### `pull_ise_objects.ps1`

Bulk ERS pull for objects needed in a policy cross-reference:

- `dacls/*.json` — downloadable ACL bodies
- `endpointgroups.json`
- `idstoresequences.json`
- `networkdevicegroups.json`

Uses `?page=N` without `size=` (the pattern that survived real ISE 3.x audits).

```powershell
powershell -ExecutionPolicy Bypass -File .\pull_ise_objects.ps1 -Pan ise-pan.example.com
```

### `fetch_auth_profiles.ps1`

Lists every authorization profile, then downloads each body to `profiles/`.
Profile **content** is ERS-only (`/ers/config/authorizationprofile/{id}`), not
OpenAPI.

```powershell
powershell -ExecutionPolicy Bypass -File .\fetch_auth_profiles.ps1 -Pan ise-pan.example.com
```

### `pull_policy_meta.ps1`

OpenAPI condition libraries + dictionaries, then probes profiling endpoints and
prints HTTP status only (so you know what this build supports).

```powershell
powershell -ExecutionPolicy Bypass -File .\pull_policy_meta.ps1 -Pan ise-pan.example.com
```

### `pull_profiling.ps1`

Profiler policy name↔id index (`profilerprofiles_index.json`) and logical
profiles when ERS exposes them.

```powershell
powershell -ExecutionPolicy Bypass -File .\pull_profiling.ps1 -Pan ise-pan.example.com
```

### `resolve_profiling_guids.ps1`

AuthZ rules often store `EndPointPolicy` as GUIDs. Feed a CSV of IDs (column
`id`) and get `profiling_guid_names.json`.

```powershell
# copy examples/profiling_guids_sample.csv → profiling_guids.csv and fill real IDs
powershell -ExecutionPolicy Bypass -File .\resolve_profiling_guids.ps1 `
  -Pan ise-pan.example.com -GuidCsv .\profiling_guids.csv
```

### `ise_policy_export.py`

OpenAPI export of network-access and device-admin policy sets, flattened to CSV
with resolved profile/condition names.

```bash
export ISE_HOST=ise-pan.example.com
export ISE_USER=apiadmin
export ISE_PASS='...'
python3 ise_policy_export.py --outdir ./ise_export --insecure
```

## What is intentionally not here

Customer-specific report builders, branded HTML/XLSX templates, switch running
configs, and live JSON exports stay in the engagement folder (OneDrive), not in
this repository.
