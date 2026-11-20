# Contributing

Thanks for improving the ISE audit toolkit.

## Ground rules

1. **No live customer data** in PRs (hostnames, passwords, GUIDs from real pulls, exports).  
2. Config examples only via `customer_config_example.py`.  
3. New writers should take an explicit `--outdir` / `--outfile` (never hardcode a personal path).  
4. Keep audit scripts read-only unless the change is clearly documented as a write tool.  
5. Match existing style; update `docs/RUNBOOK.md` / `docs/AIRGAP.md` when operator steps change.

## Dev setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python audit\sdk_smoke.py --help
```

## License

By contributing, you agree your changes are included under the MIT License (see LICENSE).
