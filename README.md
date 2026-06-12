# Orchestration Engine

A web-based automated workflow orchestration engine that chains industry-standard
open-source security tools — Nmap, WhatWeb, Gobuster, Nuclei — against a target,
parses their disparate outputs into a unified database, then correlates discovered
CVEs and service banners against Exploit-DB via Searchsploit.

Final Year Project for the Bachelor of Computer Science (Hons)(Cybersecurity)
at Multimedia University.

---

## What it does

- **Single web form** — point it at an IPv4, a domain, or an `http(s)://host:port/path` URL and select which scanners to run.
- **Three-phase orchestration pipeline**:
  1. Nmap discovery scan with service-version detection (`-sV`) runs first.
  2. WhatWeb, Nuclei, and Gobuster fan out concurrently across the HTTP/HTTPS ports Nmap discovered.
  3. Searchsploit correlates discovered CVEs *and* product/version banners against the local Exploit-DB.
- **Unified results database** — every finding lands in a single `scan_results` schema regardless of which tool produced it. Severities are normalised (Critical / High / Medium / Low / Info).
- **Exploit correlation** in two passes: by CVE ID (from Nuclei findings) and by product+version (from Nmap `-sV` banners and WhatWeb fingerprints), so misconfigured ancient services like `Apache 2.2.8` or `vsftpd 2.3.4` light up with public exploits even when no CVE was explicitly named.
- **Tool Management UI** — checks whether each scanner is installed and shows the suggested install/update command. The Flask process never runs `apt-get` itself; you copy the command and run it in your own shell, keeping the web app unprivileged.
- **Dashboard + History** — severity donut chart per scan, sortable severity column, per-scan PDF + JSON downloads, full scan history with mini severity badges.
- **Read-only correlator, never an auto-exploiter** — the system tells you *what* exploits exist and *where* the PoC files live on disk. It never runs them.

## Demo

<!-- TODO: replace with real screenshots taken on Kali against Metasploitable 2 -->

| Scan configuration | Per-scan dashboard | Severity sort |
|---|---|---|
| _add `docs/img/scan-config.png`_ | _add `docs/img/dashboard.png`_ | _add `docs/img/sort.png`_ |

## Architecture

The codebase follows the **Factory Pattern** (FYP spec section 18). The app is
constructed by `app/__init__.py:create_app()`, which wires the SQLAlchemy +
Flask-Migrate extensions, four service objects (DatabaseManager, ExploitCorrelator,
ReportGenerator, OrchestrationEngine), and four Blueprint controllers.

```
ScanController        → starts scans, exposes /api/scan/<id>/{status,results}
PagesController       → renders /, /dashboard, /history
ToolController        → /api/tools (read-only tool inventory)
ReportController      → /api/scan/<id>/report/{pdf,json}
        |
        v
OrchestrationEngine   → 3-phase pipeline, ThreadPoolExecutor for phase 2
        |
        v
BaseScanner(ABC)      → NmapScanner, WhatWebScanner, NucleiScanner, GobusterScanner
        |
        v
PARSERS dispatch      → one parser per tool, all write ScanResult rows
        |
        v
ExploitCorrelator     → CVE pass + product/version pass via SearchsploitAdapter
```

Adding a new scanner is a ~10-minute drop-in: subclass `BaseScanner`, implement
`get_command()`, register it in `SCANNER_REGISTRY`, add a parser to the `PARSERS`
dispatch map. No controller, template, or status-string changes required.

For the deep design write-up, see [ARCHITECTURE.md](ARCHITECTURE.md). For the FYP spec it
implements, see [FYP_PROJECT_SPEC.md](FYP_PROJECT_SPEC.md).

## Requirements

- **OS**: Kali Linux (other Debian-family distros may work; the wordlist path
  and pre-installed tool set assume Kali).
- **Python**: 3.10 or newer (uses `list[int]` style type hints).
- **External CLI tools** on `$PATH`:
  - `nmap` (for the `-sV` service detection)
  - `whatweb`
  - `nuclei`
  - `gobuster` (depends on the wordlist `/usr/share/wordlists/dirb/common.txt` — `apt install dirb` provides it)
  - `searchsploit` (provided by `exploitdb`)

## Installation

```bash
# Clone
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>

# Set up the Python environment
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Install the external scanners (Kali pre-installs most of these; this is a safety net)
sudo apt update
sudo apt install -y nmap nuclei whatweb gobuster exploitdb dirb

# Create the database schema via Alembic — never call db.create_all() directly
FLASK_APP=run.py .venv/bin/flask db upgrade

# Run
.venv/bin/python run.py
```

The dev server comes up on `http://127.0.0.1:5000`. No root needed.

## Usage

1. Open `http://127.0.0.1:5000`.
2. **Tool Management** card shows which scanners are installed. For any that
   aren't, click "Copy" next to the suggested install command and run it in
   your terminal.
3. **New Scan Configuration**:
   - Enter a target (`192.168.1.50`, `scanme.nmap.org`, or `https://example.com:8443/admin`).
   - Tick which scanners to run.
   - Click "Initiate Scan Job".
4. The page polls the live status. When the scan reaches `COMPLETED` it redirects to the dashboard.
5. **Dashboard** shows per-scan cards with the severity donut, findings table (severity column is sortable — click the header), and per-scan PDF / JSON download links.
6. **History** (`/history`) shows a condensed list of past scans.

## Project structure

```
.
├── app/                            # Flask application package (Factory pattern)
│   ├── __init__.py                 # create_app()
│   ├── config.py                   # Dev / Test / Prod configs
│   ├── extensions.py               # db, migrate
│   ├── models/                     # ScanJob, ScanResult, ExploitCorrelation
│   ├── controllers/                # Pages / Scan / Tool / Report (Blueprints)
│   ├── engine/                     # ManagedTool, BaseScanner, registry, orchestration
│   ├── parsers/                    # One parser per tool + PARSERS dispatch map
│   ├── services/                   # DatabaseManager, ExploitCorrelator, ReportGenerator
│   └── templates/                  # Jinja2: index.html, dashboard.html, history.html
├── migrations/                     # Alembic schema history (do not skip)
├── run.py                          # Entry point: from app import create_app
├── requirements.txt
├── ARCHITECTURE.md                       # Detailed architecture documentation
├── FYP_PROJECT_SPEC.md             # FYP project specification
└── README.md
```

## Responsible-use disclaimer

This tool runs active scans (Nmap port scans, Nuclei vulnerability probes,
Gobuster directory brute-forcing, WhatWeb fingerprinting) against the target you
provide. Use it only against systems you own or have explicit written permission
to assess. Unauthorised scanning may be illegal in your jurisdiction.

The orchestration engine is a **scanner + correlator, not an auto-exploiter**
(FYP spec NFR-02). It identifies vulnerabilities and points to where public
exploit code lives in the local Exploit-DB; it never executes exploit payloads.

## Project context

- **Project ID**: FYP01-CS-T2530-0788
- **Author**: Ng Jia Huang (1211309530)
- **Programme**: Bachelor of Computer Science (Hons)(Cybersecurity), Multimedia University
- **Supervisor**: Ms. Siti Husna Binti Abdul Rahman@Suliman
- **Timeline**: FYP2 development — March 2026 to July 2026

## License

<!-- Add your chosen license. MIT is the safe default for academic projects; pick whatever your university allows. -->

MIT.
