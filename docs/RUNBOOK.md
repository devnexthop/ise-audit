# ISE audit runbook (customer-facing)

Read-only assessment of Cisco ISE. No internet or AI required on site after the
USB pack is prepared ([AIRGAP.md](AIRGAP.md)).

## 1. Prerequisites checklist

- [ ] Laptop with Python 3.12+ and PowerShell 5.1+
- [ ] Toolkit installed (`pip install -r requirements.txt` or air-gap wheelhouse)
- [ ] Reach PAN on TCP **443**
- [ ] **API Gateway** enabled
- [ ] **OpenAPI** enabled (RADIUS + TACACS policy)
- [ ] **ERS** enabled (devices, groups, dACL/profile bodies)
- [ ] API account: Super Admin or ERS Admin / Operator
- [ ] Output folder **outside** git (USB or `D:\ise-engagements\...`)

## 2. PowerShell — full run

```powershell
cd <path>\nexthop-ise-devops
.\.venv\Scripts\Activate.ps1

$out = "D:\ise-engagements\customer-YYYYMMDD"
New-Item -ItemType Directory -Force -Path "$out\raw\inventory","$out\reports" | Out-Null

$env:ISE_HOST = "ise-pan.example.com"
$env:ISE_USER = "apiadmin"
$env:ISE_PASS = "********"

python audit\sdk_smoke.py --outdir "$out\raw" --insecure
python audit\pull_ise_inventory.py --outdir "$out\raw\inventory" --insecure
python audit\report_policy_xlsx.py `
  --indir "$out\raw\inventory" `
  --outfile "$out\reports\ISE_Policies_RADIUS_TACACS.xlsx" `
  --customer "Customer Name"
```

`pull_ise_inventory.py` = **HTTP GET only** (no ISE changes).

## 3. What you get

| Deliverable | Tool |
|---|---|
| RADIUS + TACACS policy cross-reference Excel | `report_policy_xlsx.py` |
| Raw JSON/CSV inventory | `pull_ise_inventory.py` → `raw\inventory\` |
| Optional PDF summary | `report_pdf.py` |
| Optional PS1 ERS dumps | `audit\*.ps1` |

Excel sheets include: RADIUS AuthN/AuthZ/Profiles/dACLs, TACACS AuthN/AuthZ/Command Sets,
ISE servers, network devices, device/identity/endpoint groups, identity stores, SGTs,
Findings.

## 4. If something is empty

| Symptom | Likely cause |
|---|---|
| Policy sheets empty / login HTML in smoke | OpenAPI or API Gateway off |
| Network Devices / dACLs / Profiles bodies empty | **ERS** off (302 → `/admin/`) |
| Internal Users only a sample | By design on large estates (10k+) |
| TACACS sheets nearly empty | Lab/customer has little device-admin policy |

## 5. Safety

- Do not commit exports, hostnames, or passwords.
- Do not run `enable_api_services.py --enable` or `ise_import.py` without change approval.
- Report content belongs to the customer; tools are MIT.

## 6. Hand-off

Leave `ISE_Policies_RADIUS_TACACS.xlsx` (+ optional PDF) with the customer.
Keep `raw\inventory` for your working papers on USB.
