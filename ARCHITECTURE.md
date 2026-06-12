# ARCHITECTURE.md

Detailed architectural reference for the VulnFlow Orchestration Engine.

## Project

Orchestration Engine — a Flask app that chains Kali Linux pentest tools (nmap, whatweb, nuclei, gobuster) against a target, parses their output into a SQLite database, then correlates discovered CVEs against Exploit-DB via `searchsploit`. FYP spec lives in `FYP_PROJECT_SPEC.md`.

## Commands

```bash
pip install -r requirements.txt
flask db upgrade         # apply Alembic migrations (auto-creates instance/scans.db)
python run.py            # Flask debug server on 127.0.0.1:5000
```

For DB schema changes:
```bash
FLASK_APP=run.py flask db migrate -m "describe change"
FLASK_APP=run.py flask db upgrade
```

There is no test suite yet (FYP2 step #5 — `tests/` folder planned). `requirements.txt` pins Flask, Flask-SQLAlchemy, Flask-Migrate, and ReportLab — the scanner CLIs (`nmap`, `nuclei`, `whatweb`, `gobuster`, `searchsploit`) must be installed on the host. Gobuster also depends on the wordlist at `/usr/share/wordlists/dirb/common.txt`. **The runtime target is Kali Linux**, even though development may happen on Windows; `subprocess`-launched scanners will fail elsewhere.

**The Tool Management UI never shells out to `apt-get` itself.** It only displays the suggested install/update command and copies it to the clipboard — the user runs it in their own terminal. This is intentional: keeping `sudo apt-get` out of the Flask process means the web app never needs root and can't be used as a privilege-escalation vector if `_is_valid_target` is ever bypassed. If you're tempted to "just add a button that runs it," resist — that's exactly the foot-gun this design avoids.

## Architecture

The codebase follows the **Factory Pattern** the FYP spec calls out (sections 5.2, 18). The app is constructed by `app/__init__.py:create_app()`, which wires the SQLAlchemy + Migrate extensions, the four service objects, and the four Blueprint controllers. `run.py` is the entry point.

### Layered structure

```
run.py                          # entry point
migrations/                     # Alembic migration history
app/
├── __init__.py                 # create_app() factory
├── config.py                   # Dev/Test/Prod configs (CONFIG_BY_NAME)
├── extensions.py               # db = SQLAlchemy(), migrate = Migrate()
├── models/                     # spec section 11 schema
│   ├── scan_job.py             # ScanJob (UUID PK) + ScanStatus constants
│   ├── scan_result.py          # ScanResult (FK → scan_jobs)
│   └── exploit_correlation.py  # ExploitCorrelation (FK → scan_results)
├── controllers/                # Flask Blueprints, wrapped in classes
│   ├── pages_controller.py     # /, /dashboard
│   ├── scan_controller.py      # /api/scan/start, /api/scan/<id>/{status,results}
│   ├── tool_controller.py      # /api/tools
│   └── report_controller.py    # /api/scan/<id>/report/{pdf,json}
├── engine/                     # scanner wrappers + orchestrator + adapter
│   ├── scanner_base.py         # ManagedTool, BaseScanner
│   ├── nmap_scanner.py         # NmapScanner (-F -sV)
│   ├── whatweb_scanner.py
│   ├── nuclei_scanner.py
│   ├── gobuster_scanner.py
│   ├── searchsploit_adapter.py # SearchsploitTool + SearchsploitAdapter
│   ├── registry.py             # SCANNER_REGISTRY, TOOL_REGISTRY
│   └── orchestration.py        # OrchestrationEngine
├── parsers/                    # one parser per tool; PARSERS dispatch map
│   ├── nmap_parser.py          # also owns NMAP_SERVICE_SEVERITY heuristic
│   ├── whatweb_parser.py
│   ├── nuclei_parser.py
│   └── gobuster_parser.py
├── services/                   # spec-named service classes
│   ├── db_manager.py           # DatabaseManager (thin SQLAlchemy façade)
│   ├── exploit_correlator.py   # ExploitCorrelator (uses adapter)
│   └── report_generator.py     # ReportGenerator.generate_pdf / .generate_json
└── templates/                  # Jinja templates
    ├── index.html
    └── dashboard.html
```

### Database schema (spec section 11)

Three tables, managed entirely via Alembic — never call `db.create_all()` directly:

- `scan_jobs` — `scan_id` (UUID PK), `target`, `status` (PENDING / RUNNING / COMPLETED / FAILED), `start_time`, `end_time`, `selected_modules` (JSON), `target_port` + `target_scheme` (optional URL hint).
- `scan_results` — `id` (int PK), `scan_id` (FK), `tool_name`, `host`, `port` (int), `service`, `finding`, `severity`, `raw_output`, plus deviations `cve_id`, `product`, `version` (see below).
- `exploit_correlations` — `id`, `result_id` (FK), `exploit_title`, `exploit_id` (Exploit-DB EDB-ID), `exploit_path`.

`ScanResult.has_public_exploit` is a Python `@property` derived from `len(correlations) > 0`, not a stored column.

**Deviations from spec section 11:**
- `scan_results.cve_id` — added nullable indexed column. Without it `ExploitCorrelator` would need to text-match the `finding` column to find CVE-tagged rows.
- `scan_results.product` + `scan_results.version` — added nullable columns populated by the Nmap (`-sV`) and WhatWeb parsers. These power the correlator's second pass (`searchsploit <product> <version>`) so findings without an explicit CVE — e.g. WhatWeb's `Apache 2.2.8` fingerprint — still get exploits attached. The WhatWeb parser guards version extraction with the `_VERSION_LIKE` regex so the `Title` plugin's "version" field (which holds the page title) never reaches the correlator.

All three deviations are intentional and worth listing in the FYP2 report's "Design changes from FYP1" section.

### Request flow

1. `POST /api/scan/start` (form fields: `target` or `ip`, repeated `modules` or `tools`) is handled by `ScanController`. `_parse_target_input` accepts either a bare host (`example.com`, `192.168.1.50`) or an `http(s)://host[:port][/path]` URL — when a URL is provided the path is dropped, the scheme + port are remembered as the optional URL hint, and the bare host is re-validated through `_is_valid_target` (strict IPv4 or domain regex). `_is_valid_target` remains the **only** guard against shell injection into `subprocess.run`. A 409 is returned if a non-terminal `ScanJob` already exists for the target. On success, `OrchestrationEngine.create_scan_job` is called with the host + selected tools + URL hint, and the response carries the new `scan_id` (UUID).
2. `OrchestrationEngine.create_scan_job` persists a `ScanJob` row with `selected_modules`, seeds `_progress[scan_id]`, and spawns a daemon thread running `execute_scan`.
3. `OrchestrationEngine.execute_scan` runs the pipeline in **three phases**:
   - **Phase 1 (sequential)** — Nmap. Its results drive HTTP-port detection for the next phase, so it has to finish first.
   - **Phase 2 (concurrent)** — WhatWeb, Nuclei, Gobuster. Each tool's subprocess runs in a worker thread via `ThreadPoolExecutor` (capped at 4 workers). WhatWeb and Gobuster fan out into one work unit per `(port, scheme)` returned by `_resolve_http_targets` (which combines the user's URL hint with Nmap discoveries) — every unit runs in parallel. They skip cleanly if neither source yielded an HTTP port (and Nmap was selected — without Nmap they fall back to port 80).
   - **Phase 3 (sequential)** — `ExploitCorrelator.correlate(scan_id)` runs two passes: a CVE pass (Nuclei findings) and a product/version pass (Nmap banners + WhatWeb fingerprints), both writing `ExploitCorrelation` rows.

   **Concurrency model:** workers ONLY run scanner subprocesses (the slow, I/O-bound part). Parsing and DB writes happen back on the orchestrator thread via `as_completed`, so SQLAlchemy sessions stay single-threaded and SQLite never gets concurrent writers. Updates to `_progress[scan_id]` (step / total / current_tool) likewise happen only on the orchestrator thread.
4. The frontend polls `GET /api/scan/<scan_id>/status` every 2 s. The payload includes `current_status` (uppercase enum), `current_tool`, `step`, and `total`; the JS computes a percentage from step/total so adding a new scanner does **not** require touching hardcoded percentages. Only `"COMPLETED"` and `"FAILED"` are special-cased in JS.
5. On `"COMPLETED"` the page redirects to `/dashboard`, which lists every `ScanJob` (most recent first), each card showing its findings + per-scan `⬇ PDF` and `⬇ JSON` download links served by `ReportController`.

Because the worker thread runs outside the request, every DB access inside `OrchestrationEngine.execute_scan` is wrapped in `with self.app.app_context():`.

### Adding a new scanner

1. New `app/engine/<name>_scanner.py` subclassing `BaseScanner` with `name`, `cli_name`, `apt_package`, and `get_command()`.
2. Register it in `app/engine/registry.py:SCANNER_REGISTRY` (order = pipeline order).
3. New `app/parsers/<name>_parser.py` with `parse_<name>(output, scan_id, target)`; register in `app/parsers/__init__.py:PARSERS`. The parser MUST write to `ScanResult`, not the legacy models.

That's all — no controller, template, or status-string changes needed.

## Things to watch when editing

- `_is_valid_target` is the security boundary. Don't bypass it, and don't pass unvalidated user input to any new `subprocess` call.
- All parsers now take `(output, scan_id, target)` — `scan_id` is the UUID string, `target` is the host string. They write `ScanResult` rows directly; never reach for the old `Target`/`Vulnerability` classes (they no longer exist).
- The orchestrator catches all exceptions and marks the scan `"FAILED"`, so silently-broken parsers won't surface in the UI; check the Flask console for `[PARSER ...]` / `[SYSTEM ...]` logs when debugging.
- Severity strings (`Critical`/`High`/`Medium`/`Low`/`Info`) are used as CSS class suffixes (`severity-Critical` etc.) in `dashboard.html` and as keys in `app/services/report_generator.py:SEVERITY_COLORS`; the Nuclei parser `.capitalize()`s them to match.
- Status strings are now spec-aligned uppercase (`PENDING`/`RUNNING`/`COMPLETED`/`FAILED`) defined in `app.models.ScanStatus`. The granular per-tool detail lives in `_progress[scan_id]["current_tool"]`, not the DB.
- `OrchestrationEngine._progress` is in-memory and per-process. The Flask debug reloader spawns two processes, which can make polling look inconsistent during dev — run with `use_reloader=False` if you need deterministic progress for a demo.
- The `install_command` / `update_command` strings in `GET /api/tools` are rendered into a `<code>` block on the page; if you add new tools, make sure their commands don't contain user input — these strings are static, but the assumption is load-bearing.
- Any schema change MUST go through `flask db migrate` + `flask db upgrade`. Do not call `db.create_all()` from app code — the factory no longer does, and adding it back will mask drift between models and migrations.
