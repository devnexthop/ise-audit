# Air-gapped / USB laptop workflow

Use when the customer site has **no internet** and you bring tools on USB.

## Split: tools vs reports

| Location | Contents |
|---|---|
| This GitHub repo (or zip + `wheelhouse\`) | Scripts, docs, `requirements.txt` |
| Engagement folder on laptop / USB | Live JSON/CSV/XLSX/PDF, local creds |

Never copy live exports into the git tree you will push publicly.

```text
D:\ise-engagements\<customer>-<YYYYMMDD>\
  raw\inventory\     # pull_ise_inventory.py output
  reports\           # ISE_Policies_RADIUS_TACACS.xlsx, PDF
  config.env         # host/user/pass — local only
  NOTES.md
```

## Online box (before you leave)

```powershell
git clone https://github.com/devnexthop/nexthop-ise-devops.git
cd nexthop-ise-devops
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
New-Item -ItemType Directory -Force -Path wheelhouse | Out-Null
pip download -r requirements.txt -d wheelhouse
# Copy entire repo folder + wheelhouse\ to USB
```

## Air-gapped laptop (on site)

```powershell
cd <usb>\nexthop-ise-devops
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --no-index --find-links=wheelhouse -r requirements.txt
```

ISE GUI (if not already on): API Gateway + OpenAPI + ERS.

## Run (same as online)

```powershell
$out = "D:\ise-engagements\customer-YYYYMMDD"
$env:ISE_HOST = "..."
$env:ISE_USER = "..."
$env:ISE_PASS = "..."

python audit\pull_ise_inventory.py --outdir "$out\raw\inventory" --insecure
python audit\report_policy_xlsx.py --indir "$out\raw\inventory" `
  --outfile "$out\reports\ISE_Policies_RADIUS_TACACS.xlsx" --customer "Customer Name"
```

## USB out

Copy only the engagement folder back. Wipe credentials per customer policy.
