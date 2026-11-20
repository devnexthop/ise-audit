# nexthop-ise-devops — canonical agent rules

**This file is canonical.** `CLAUDE.md` is only a pointer.

Public-facing Cisco **ISE** toolkit: read-only audit pulls under `audit/`,
Excel/PDF report builders, air-gap docs under `docs/`, plus `ise_export.py` /
`ise_import.py` for config management.

## Configuration and credentials

`customer_config.py` is **gitignored** — it holds real ISE hostnames and credentials.
Start from `customer_config_example.py`.

Never commit real hostnames, passwords, or export JSON/CSV/XLSX/PDF. `.gitignore`
blocks common audit output filenames; still run pulls with `--outdir` outside the
repo when practical.

Before making the repo public (or opening a PR), search the tree for customer
names, FQDNs, and GUIDs from live deployments.

## Estate rules

Working tree is `~/gitsync/nexthop-ise-devops`, never a cloud-synced folder.

**Tools** live in this git repo (public GitHub).  
**Engagement artifacts** (live exports, Excel, PDF, local `config.env`) live on the
assessment laptop under a non-git folder such as `C:\DevWork-Local\ise-engagements\`
(or USB). Do not commit them here.

Cross-project skills:
`git -C ~/gitsync/devwork-kit pull --ff-only && ~/gitsync/devwork-kit/sync-kit.sh`.
