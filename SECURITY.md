# Security Policy

## Supported use

This toolkit is intended for **authorized**, primarily **read-only** assessment of Cisco ISE deployments you own or are contracted to assess.

## Reporting a vulnerability

Email **security@nexthopllc.com** (or open a private security advisory on GitHub if available). Do **not** file a public issue that includes:

- Credentials, tokens, or API keys  
- Customer hostnames, exports, policy JSON/CSV, Excel, or PDF reports  
- Screenshots of live customer policy  

## Safe contribution rules

- Never commit `customer_config.py`, `config.env`, or export artifacts  
- Use `customer_config_example.py` and placeholder FQDNs only  
- Prefer `--outdir` paths outside the git tree  

## Known operational risks

- `--insecure` disables TLS verification (lab only)  
- `audit/enable_api_services.py --enable` and root `ise_import.py` **write** to ISE — use only with change approval  
- Enabling ERS/OpenAPI changes the attack surface of the PAN; follow the customer’s change process  
