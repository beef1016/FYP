# ExploitLink Orchestration Engine

A web-based automated workflow orchestration engine that chains industry-standard
open-source security tools — Nmap, WhatWeb, Gobuster, Nuclei, and OWASP ZAP —
against a target, parses their disparate outputs into a unified database, then
correlates discovered CVEs and service banners against Exploit-DB (via Searchsploit)
and the CISA **Known Exploited Vulnerabilities** catalog. Overlapping findings from
different tools are de-duplicated and linked rather than double-counted, and results
are ranked by real-world exploitability — actively-exploited-and-confirmed first —
not by a severity label alone.

Final Year Project for the Bachelor of Computer Science (Hons)(Cybersecurity)
at Multimedia University.

---

## What it does

- **Single web form** — point it at an IPv4, a domain, or an `http(s)://host:port/path` URL and select which scanners to run.
- **Three-phase orchestration pipeline**:
  1. Nmap discovery scan with service-version detection (`-sV`) runs first.
  2. WhatWeb, Nuclei, Gobuster, and OWASP ZAP fan out concurrently across the HTTP/HTTPS ports Nmap discovered.
  3. Findings are enriched in passes: cross-tool de-duplication → Exploit-DB lookup by CVE → Exploit-DB lookup by product/version → CISA KEV.
- **Unified results database** — every finding lands in a single `scan_results` schema regardless of which tool produced it. Severities are normalised (Critical / High / Medium / Low / Info).
- **Exploit correlation** — by CVE ID (from Nuclei/ZAP) and by product+version (from Nmap `-sV` banners and WhatWeb fingerprints), so misconfigured ancient services like `Apache 2.2.8` or `vsftpd 2.3.4` light up with public exploits even when no CVE was explicitly named. The product query is normalised identically for every tool and unioned across a dup-group, so two tools describing one service never show contradictory exploit lists.
- **CISA KEV enrichment (offline)** — CVE-tagged findings are flagged when they appear in a local mirror of CISA's **Known Exploited Vulnerabilities** catalog (i.e. exploited in the wild right now), independent of whether a PoC exists. The running app only ever *reads* the local mirror; refresh it on the host with `scripts/update_kev.sh` (or `scripts/update_kev.ps1`). Nothing is fetched at scan time.
- **Cross-tool de-duplication (keep-both-and-link)** — overlapping findings are linked, never deleted, and the two *kinds* of overlap are kept separate: **identity** (a shared CVE or service banner → "also detected by …", genuine corroboration) vs **co-location** (different tools touched the same URL path → "same path also mapped by …", *not* the same issue). A shared path can therefore never masquerade as corroboration.
- **Evidence-aware, tiered prioritisation** — findings are ordered by real-world exploitability, in three tiers: **(1)** listed in CISA KEV *and* confirmed on the target, **(2)** a public exploit targets the finding's specific CVE, then **(3)** severity. Within a tier, **confirmed** findings outrank **presumed** (version-inferred) ones, then CVSS, then EPSS. A banner-only exploit match (same software, possibly a different flaw) does *not* elevate a finding, and a KEV listing that is only presumed keeps its flag but drops out of the top tier — because KEV means "exploited somewhere", not "this host is vulnerable". Severity itself stays a qualitative, tool-reported label (not CVSS-derived).
- **Honest finding counts** — the dashboard and reports show three numbers instead of one: *reported* (raw tool hits), *collapsed* (after merging repeated template hits within a tool, e.g. `http-missing-security-headers` ×10 → 1), and *unique* (after also merging cross-tool identity duplicates).
- **Actionable exploit intelligence (offline)** — each correlated exploit carries a one-line **synopsis** read from the exploit file: its language, what it does, and the exact command to run it (`searchsploit -m <id>`). Findings with *no* public exploit aren't dead ends either — an **exploitation-context** line classifies them (reconnaissance, exposure, fingerprint, versioned, misconfiguration, …) and explains how they contribute to the attack surface, instead of a bare "N/A". All computed locally; no external lookups.
- **Tool Management UI** — checks whether each scanner (and the Searchsploit / CISA-KEV data sources) is installed/present and shows the suggested install/update command. The Flask process never runs `apt-get` itself; you copy the command and run it in your own shell, keeping the web app unprivileged.
- **Dashboard + History** — severity donut chart per scan, sortable severity column, confirmed/presumed and corroboration badges, per-scan PDF + JSON downloads, full scan history with mini severity badges. Guessed credentials captured by weak-/default-login templates are **masked** (`admin:****`) in the shareable PDF/JSON exports; the raw value stays only in the local database.
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
BaseScanner(ABC)      → NmapScanner, WhatWebScanner, NucleiScanner,
                        GobusterScanner, ZapScanner
        |
        v
PARSERS dispatch      → one parser per tool, all write ScanResult rows
        |
        v
ExploitCorrelator     → (1) de-dup via finding_dedup  (2) CVE pass
                        (3) product/version pass via SearchsploitAdapter
                        (4) CISA KEV pass via KevCatalog
        |
        v
priority_key          → evidence-aware 3-tier ranking on each ScanResult
```

Adding a new scanner is a ~10-minute drop-in: subclass `BaseScanner`, implement
`get_command()`, register it in `SCANNER_REGISTRY`, add a parser to the `PARSERS`
dispatch map. No controller, template, or status-string changes required.

For the deep design write-up, see [ARCHITECTURE.md](ARCHITECTURE.md). For the FYP spec it
implements, see [FYP_PROJECT_SPEC.md](FYP_PROJECT_SPEC.md).

## Run with Docker (recommended)

The repo ships a `Dockerfile` + `docker-compose.yml` so the core stack — Python
runtime, the Nmap / WhatWeb / Gobuster / Nuclei CLIs, Searchsploit + the Exploit-DB
mirror, and the Nuclei templates — is reproducible from a clean machine. No need to
install anything on the host beyond Docker itself.

Two things are **not** baked into the image, by design:

- **OWASP ZAP** — it is large (a full Java app), so it is left out of the image to
  keep builds lean. On the Dockerized stack the ZAP scanner simply reports as "not
  installed" and is skipped; run ZAP on a native Kali host (below) to use it.
- **The CISA KEV mirror** — it is runtime data, not image content. `docker-compose.yml`
  mounts `./app/data/kev` into the container, and you populate/refresh it on the host
  with `scripts/update_kev.sh` (or `.ps1`); the container reads it live, so a KEV
  refresh needs no rebuild. Without it, scans still run — findings just aren't
  KEV-flagged.

### Prerequisites

- Docker Engine 20.10+ and Docker Compose v2.

### One-command start

```bash
git clone https://github.com/beef1016/FYP.git
cd FYP
docker compose up --build
```

First build takes ~5–10 minutes (Kali base image, apt installs, Nuclei template
download). Subsequent runs use the cached layers and start in seconds.

Once running, open **<https://localhost/>** (HTTPS via Caddy; plain HTTP
redirects). Use the hostname `localhost`, **not** `https://127.0.0.1/` —
connecting by raw IP sends no TLS SNI, so Caddy can't select its certificate
and the handshake fails with `TLSV1_ALERT_INTERNAL_ERROR`.

### Accessing the dashboard over HTTPS

The compose stack runs **two containers**: ExploitLink (Flask) on loopback,
and a **Caddy reverse proxy** that terminates TLS on the host's :443 and
proxies to Flask. The Flask process is never directly reachable from outside
the host.

**First-time browser warning**: Caddy issues the cert from its own local
certificate authority (the `tls internal` directive in `Caddyfile`). Your
browser will warn "This connection is not private" the first time you visit.
Two ways to handle it:

- **Click through**: Advanced → Proceed to localhost (unsafe). Repeat once
  per browser session. Fine for the FYP demo.

- **Trust Caddy's root CA** (one-time setup, then no warnings forever):

  ```bash
  # Extract Caddy's root CA cert from the running container
  docker compose exec caddy cat /data/caddy/pki/authorities/local/root.crt > caddy-root.crt
  # Linux:  sudo cp caddy-root.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
  # Firefox: about:preferences#privacy → Certificates → View Certificates →
  #          Authorities → Import → select caddy-root.crt → tick "Trust for websites"
  # Chrome/Edge: Settings → Privacy → Manage certificates → Trusted Root
  #              Certification Authorities → Import → select caddy-root.crt
  ```

**Plain HTTP works (sort of)**: <http://localhost> 301-redirects to the
HTTPS URL automatically.

### Production deployment (real domain)

Replace the `:443 { ... }` block in `Caddyfile` with:

```
scanner.your-company.com {
    reverse_proxy 127.0.0.1:5000 {
        header_up X-Forwarded-Proto https
    }
}
```

Caddy obtains and rotates a Let's Encrypt certificate automatically via the
ACME HTTP-01 challenge (requires port 80 open + DNS pointing at the server).
No browser warnings, no manual cert trust step.

### Networking profiles

`docker-compose.yml` ships **two profiles**; pick by host OS.

**Default — bridge + published ports (as shipped; works everywhere, incl.
Docker Desktop on Windows/macOS).** Caddy publishes `:80`/`:443`, Flask binds
`0.0.0.0:5000` inside its container, and Caddy reaches it by service name
(`EXPLOITLINK_UPSTREAM: exploitlink:5000`). Open <https://localhost/>. This is
the reliable choice on Docker Desktop, whose `network_mode: host` does not
publish container ports to the Windows/macOS host.

**Kali / native-Linux — host networking (better for LAN scanning).** Uncomment
`network_mode: host` on **both** services, set `FLASK_HOST: 127.0.0.1`, and the
Caddyfile upstream falls back to `127.0.0.1:5000`. The container then shares the
host's stack, so:

1. **LAN targets** — a Metasploitable 2 VM, DVWA box, or any same-subnet device
   is reachable exactly as from the host, with no bridge NAT to degrade Nmap's
   service-version probes or Nuclei's UDP/raw-socket templates.
2. **Internet targets** — `testfire.net`, `scanme.nmap.org`, etc. work with no
   extra config.

> **Note (Docker Desktop on Windows):** host networking runs inside a WSL2 VM,
> so it neither publishes ports to Windows nor reaches LAN targets cleanly — use
> the default bridge profile there. Host networking is for native Linux/Kali.

### Image refresh

Nuclei templates and the Exploit-DB mirror are **baked into the image at build
time** for reproducibility. To pick up newer templates / exploits, rebuild:

```bash
docker compose build --no-cache
docker compose up
```

The **CISA KEV** mirror is the exception — it is host-side mounted data, so refresh
it without any rebuild:

```bash
./scripts/update_kev.sh        # or scripts\update_kev.ps1 on Windows
```

### Stopping

```bash
docker compose down
```

Your scan history lives in `./instance/scans.db` on the host (mounted as a
volume) and survives `down` + `up`.

---

## Run without Docker (Kali host install)

If you'd rather run directly on a Kali host without Docker:

### Requirements

- **OS**: Kali Linux (other Debian-family distros may work; the wordlist path
  and pre-installed tool set assume Kali).
- **Python**: 3.10 or newer (uses `list[int]` style type hints).
- **External CLI tools** on `$PATH`:
  - `nmap` (for the `-sV` service detection)
  - `whatweb`
  - `nuclei`
  - `gobuster` (depends on the wordlist `/usr/share/dirb/wordlists/common.txt` — `apt install dirb` provides it)
  - `zaproxy` (OWASP ZAP; provides the ZAP DAST scanner — optional, the scan skips it if absent)
  - `searchsploit` (provided by `exploitdb`)
- **Local CISA KEV mirror** (optional, enables KEV enrichment) — populate it once with
  `scripts/update_kev.sh`; see `app/data/kev/README.md`.

### Installation

**One-time setup:**

```bash
# 1. Clone
git clone https://github.com/beef1016/FYP.git
cd FYP

# 2. Python environment (name it `venv` or `.venv` — start.sh auto-detects either)
python3 -m venv venv
venv/bin/pip install -r requirements.txt

# 3. Scanners (Kali pre-installs most) + Caddy for the HTTPS option
sudo apt update
sudo apt install -y nmap nuclei whatweb gobuster zaproxy exploitdb dirb caddy libnss3-tools

# 4. (optional) populate the local CISA KEV mirror for exploited-in-the-wild flags
./scripts/update_kev.sh
```

Then pick how to run it:

**Option A — plain HTTP (simplest):**

```bash
source venv/bin/activate
export FLASK_APP=run.py
export EXPLOITLINK_AUTH_PASSWORD='your-strong-password'   # REQUIRED — app won't start without it
export EXPLOITLINK_ALLOW_PRIVATE_TARGETS=true             # allow LAN / Metasploitable targets
flask db upgrade                                          # create / upgrade the DB schema
python run.py                                             # http://127.0.0.1:5000
```

**Option B — HTTPS in one command (Caddy + Flask together):**

```bash
chmod +x start.sh
EXPLOITLINK_AUTH_PASSWORD='your-strong-password' ./start.sh   # https://localhost/
```

`start.sh` runs `flask db upgrade`, then launches **Caddy** (TLS on :443) and
**Flask** (loopback :5000) together — Ctrl+C stops both. So you do **not** run
`flask db upgrade` or `run.py` separately with this option. First run installs
Caddy's local CA; accept the one-time browser cert warning, or import the CA to
trust it (see *Accessing the dashboard over HTTPS* above).

> `EXPLOITLINK_AUTH_PASSWORD` is mandatory (`run.py` exits without it).
> `EXPLOITLINK_ALLOW_PRIVATE_TARGETS=true` enables lab mode for Metasploitable /
> LAN targets — omit it for production-safe mode (RFC1918 targets blocked).

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
│   ├── engine/                     # BaseScanner + Nmap/WhatWeb/Nuclei/Gobuster/ZAP, registry, orchestration
│   ├── parsers/                    # One parser per tool (incl. zap_parser) + PARSERS dispatch
│   ├── services/                   # DatabaseManager, ExploitCorrelator, ReportGenerator,
│   │                               #   finding_dedup, kev_catalog, redaction
│   ├── data/kev/                   # Local CISA KEV mirror (JSON is gitignored; see README)
│   ├── static/                     # theme.css
│   └── templates/                  # Jinja2: base, index, dashboard, history
├── migrations/                     # Alembic schema history (head d1e6f4a8b2c5 — do not skip)
├── scripts/                        # update_kev.sh / update_kev.ps1 (refresh the KEV mirror)
├── tests/                          # ranking fixture test (test_ranking_order.py)
├── run.py                          # Entry point: from app import create_app
├── requirements.txt
├── ARCHITECTURE.md                 # Detailed architecture documentation
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

Released under the [MIT License](LICENSE). You're free to use, modify, and
redistribute the code — subject to keeping the copyright notice intact and
acknowledging that the software is provided as-is.
