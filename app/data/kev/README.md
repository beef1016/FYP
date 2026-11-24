# CISA KEV catalog (local mirror)

This directory holds the offline mirror of the **CISA Known Exploited
Vulnerabilities (KEV)** catalog used to enrich exploit correlation.

- Expected file: `known_exploited_vulnerabilities.json`
- Source feed: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>

The running app **never downloads** this file — it only reads it. Populate and
refresh it out-of-band so scans stay fully offline:

```bash
bash scripts/update_kev.sh          # Linux / Kali
```

```powershell
powershell -File scripts\update_kev.ps1   # Windows
```

Override the location with the `EXPLOITLINK_KEV_PATH` environment variable to
point at a shared/managed copy.

> The `.json` data file itself is intentionally **not committed** — it is
> refreshed data, not source. If the file is absent, KEV enrichment is simply
> skipped (scans and correlation still work).
