# FYP Project Specification — Automated Workflow Orchestration Engine for Vulnerability Assessment and Exploit Correlation

> **Project ID:** FYP01-CS-T2530-0788
> **Author:** Ng Jia Huang (1211309530)
> **Programme:** Bachelor of Computer Science (Hons)(Cybersecurity), Multimedia University
> **Supervisor:** Ms. Siti Husna Binti Abdul Rahman@Suliman
> **Timeline:** FYP2 Development — March 2026 to July 2026

---

## 1. Project Overview

This project is a **web-based automated workflow orchestration engine** that streamlines vulnerability assessment by programmatically orchestrating a multi-stage pipeline of reconnaissance, scanning, and exploit correlation. It wraps industry-standard open-source CLI security tools within a unified Python/Flask application, replacing the fragmented manual process where analysts run tools individually, manually parse outputs, and correlate findings by hand.

The system is a **scanner orchestrator and correlator**, NOT an auto-exploiter. It provides intelligence about what vulnerabilities exist and whether public exploits are available, but never executes attack payloads.

---

## 2. Problem Being Solved

- Manual vulnerability assessment takes 80–120 person-hours for a medium-complexity environment and produces inconsistent results (detection rates vary 62–100% across experts).
- Analysts waste ~23.7 minutes per vulnerability researching context because automated scanners give generic severity scores without exploit context.
- Tools produce disparate output formats (XML, JSON, unstructured text) requiring analysts to act as "human middleware" copying data between tools.
- No existing lightweight, open-source framework bridges vulnerability scanning and exploit correlation without active intrusion risk or enterprise-level cost/complexity.

---

## 3. Project Objectives

1. Orchestrate external scanning tools (Nmap, WhatWeb, Gobuster, Nuclei) via a web-based interface built with Python/Flask.
2. Parse, aggregate, and store machine-readable output (XML/JSON) from all integrated tools into a centralized database.
3. Implement a correlation module using Searchsploit that automatically maps identified services/vulnerabilities to known public exploits.
4. Validate the complete workflow against a controlled vulnerable environment (Metasploitable2 VM).

---

## 4. Tech Stack

| Layer | Technology |
|---|---|
| **Backend Framework** | Python 3 + Flask (factory pattern) |
| **ORM / Database** | SQLAlchemy + SQLite (or PostgreSQL) |
| **Frontend** | HTML5, CSS (Bootstrap), JavaScript (vanilla) |
| **Charts** | Chart.js |
| **Async Execution** | Python threading (background scan jobs) |
| **Status Polling** | AJAX (periodic GET requests from frontend) |
| **Deployment Target** | Kali Linux (single-machine, no Docker/Cloud required) |

### Integrated Security Tools (CLI wrappers)

| Tool | Purpose | Output Format |
|---|---|---|
| **Nmap** | Network/port scanning, service version detection, OS fingerprinting | XML |
| **WhatWeb** | Web technology fingerprinting (CMS, frameworks, server software) | JSON / line-based text |
| **Gobuster** | Directory and file brute-forcing (hidden paths, admin panels) | Text (status codes + paths) |
| **Nuclei** | Template-based vulnerability scanning (CVEs, misconfigs) | JSON lines |
| **Searchsploit** | Offline exploit correlation via local Exploit-DB | Text (exploit titles + IDs) |

---

## 5. System Architecture

### 5.1 High-Level Flow

```
User (Browser) → Web Dashboard → Flask ScanController → OrchestrationEngine
                                                              ↓
                                              ┌───────────────┼───────────────┐
                                              ↓               ↓               ↓
                                          NmapScanner   WhatWebScanner   GobusterScanner
                                              ↓               ↓               ↓
                                              └───────────────┼───────────────┘
                                                              ↓
                                                      NucleiScanner
                                                              ↓
                                                       ResultParser
                                                              ↓
                                                     DatabaseManager
                                                              ↓
                                                    ExploitCorrelator
                                                     (Searchsploit)
                                                              ↓
                                                     ReportGenerator
                                                              ↓
                                               Results Dashboard + PDF Download
```

### 5.2 Key Architectural Decisions

- **Asynchronous scan execution**: Scans run in background threads so the Flask web server stays responsive. The frontend polls `/status` via AJAX.
- **Scanner abstraction**: All tool wrappers inherit from an abstract `Scanner` base class with `run()` and `parseOutput()` methods — new tools can be added by creating a new subclass.
- **Adapter pattern for Searchsploit**: `SearchsploitAdapter` isolates the system from Searchsploit's CLI output format, allowing future replacement of the exploit data source.
- **Deterministic, rule-based logic**: No AI/LLM involved in the pipeline. Same input → same output.
- **Non-intrusive operation**: System never executes exploits, shells, or DoS attacks. Correlation only.

---

## 6. Class Structure

### Core Classes

- **`WebDashboard`** — Presentation layer. Methods: `displayScanForm()`, `showScanStatus()`, `viewResults()`, `downloadReport()`.
- **`ScanController`** — HTTP request handler (Flask routes). Methods: `startScan()`, `getScanStatus()`, `getResults()`.
- **`OrchestrationEngine`** — Central coordinator. Methods: `createScanJob()`, `executeScan()`, `collectResults()`, `correlateExploits()`.
- **`ScanJob`** — Data model. Attributes: `scanId`, `target`, `status`, `startTime`, `endTime`.
- **`ScanResult`** — Data model. Attributes: `toolName`, `finding`, `severity`.

### Scanner Wrappers (all extend abstract `Scanner`)

- **`NmapScanner`** — Builds Nmap CLI command, runs it, parses XML output.
- **`WhatWebScanner`** — Runs WhatWeb, parses JSON/text for technologies detected.
- **`GobusterScanner`** — Runs Gobuster, parses discovered directories + HTTP status codes.
- **`NucleiScanner`** — Runs Nuclei, parses JSON lines for CVEs, severity, description, URLs.

### Support Classes

- **`ResultParser`** — Converts raw tool outputs into unified `ScanResult` objects.
- **`DatabaseManager`** — Persistence via SQLAlchemy. Methods: `saveScan()`, `saveResults()`, `fetchResults()`.
- **`ExploitCorrelator`** — Receives vulnerabilities, queries `SearchsploitAdapter`, returns exploit matches.
- **`SearchsploitAdapter`** — Executes `searchsploit` CLI queries, parses text output for exploit titles/IDs.
- **`ReportGenerator`** — Builds PDF and/or JSON report from aggregated results. Methods: `generatePDF()`, `generateJSON()`.

---

## 7. Functional Requirements

| ID | Module | Description | Tool |
|---|---|---|---|
| FR-01 | Interface | Web-based GUI via Flask accessible in Chrome/Firefox | Flask |
| FR-02 | Validation | Validate target is a properly formatted IPv4 address or domain name | Python `ipaddress` lib |
| FR-03 | Network | Execute port scan to identify live hosts, open ports, service versions → XML | Nmap |
| FR-04 | Content | Auto-trigger directory brute-forcing on detected HTTP/HTTPS services | Gobuster |
| FR-05 | Fingerprint | Execute web fingerprinting to identify CMS versions and server technologies | WhatWeb |
| FR-06 | Scanning | Template-based vulnerability scanning for CVEs and misconfigurations | Nuclei |
| FR-07 | Parsing | Convert disparate tool outputs (Nmap XML, Nuclei JSON, WhatWeb text) into unified Python dict | Python |
| FR-08 | Correlation | Normalize service banners, query local Exploit-DB for matching exploit IDs (no active attacks) | Searchsploit |
| FR-09 | Reporting | Render HTML results page with tables + charts; include "Print to PDF" function | Chart.js / HTML5 |

---

## 8. Non-Functional Requirements

| ID | Category | Description |
|---|---|---|
| NFR-01 | Performance | Orchestration overhead must be negligible compared to manual CLI execution |
| NFR-02 | Safety | Strictly non-intrusive — no exploitation payloads, shells, or DoS. Passive correlation only |
| NFR-03 | Reliability | Deterministic output — same static target → identical results on repeat scans |
| NFR-04 | Portability | Runs on standard Kali Linux with Python standard libraries, no Cloud APIs or Docker required |

---

## 9. User Requirements

| ID | Need | Description |
|---|---|---|
| UR-01 | Simplicity | Initiate full-stack assessment (Recon → Scan → Correlate) from a single web form |
| UR-02 | Immediate visibility | View results in-browser upon completion, no external software needed |
| UR-03 | Intelligence | Report must flag vulnerabilities with matching public exploits from exploit database |
| UR-04 | Persistence | View and retrieve reports from previous scan sessions via dashboard |

---

## 10. Web Interface Pages

### 10.1 Scan Configuration Page (Entry Point)
- Module selection: checkboxes/toggles for Nmap, WhatWeb, Gobuster, Nuclei (each with short description)
- Target input: text field accepting IPv4 address or domain name
- Client-side + server-side validation
- "Start Scan" button → creates scan job → redirects to Status Page

### 10.2 Scan Status Page
- Displays Scan ID
- Overall progress indicator (percentage or phase name)
- Per-tool execution status (e.g., Nmap: Running, Gobuster: Waiting, WhatWeb: Completed)
- Auto-refreshes via AJAX polling without manual page reload

### 10.3 Results Dashboard
- **Scan Summary**: total vulnerabilities, severity distribution, scan duration
- **Vulnerability List**: table with columns — host, port, service, description, severity
- **Exploit Correlation**: which findings have known exploits, with exploit titles and reference links
- **Download Report**: export as PDF or JSON

---

## 11. Database Schema

### `scan_jobs` table
| Column | Type | Notes |
|---|---|---|
| `scan_id` | String (UUID) | Primary key |
| `target` | String | IPv4 or domain |
| `status` | String | PENDING / RUNNING / COMPLETED / FAILED |
| `start_time` | DateTime | |
| `end_time` | DateTime | Nullable |
| `selected_modules` | JSON/Text | List of enabled tools |

### `scan_results` table
| Column | Type | Notes |
|---|---|---|
| `id` | Integer | Primary key, auto-increment |
| `scan_id` | String (FK) | References `scan_jobs.scan_id` |
| `tool_name` | String | nmap / whatweb / gobuster / nuclei |
| `host` | String | Target host/IP |
| `port` | Integer | Nullable |
| `service` | String | Nullable |
| `finding` | Text | Description of the finding |
| `severity` | String | critical / high / medium / low / info |
| `raw_output` | Text | Original tool output snippet |

### `exploit_correlations` table
| Column | Type | Notes |
|---|---|---|
| `id` | Integer | Primary key |
| `result_id` | Integer (FK) | References `scan_results.id` |
| `exploit_title` | String | From Searchsploit |
| `exploit_id` | String | Exploit-DB ID |
| `exploit_path` | String | Local file path to exploit |

---

## 12. API Routes

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Home / Scan Configuration page |
| `POST` | `/api/scan/start` | Create and start a new scan job. Body: `{ target, modules[] }`. Returns: `{ scanId }` with HTTP 202 |
| `GET` | `/api/scan/<scanId>/status` | Get current scan status and per-tool progress |
| `GET` | `/api/scan/<scanId>/results` | Get aggregated results with exploit correlations |
| `GET` | `/api/scan/<scanId>/report/pdf` | Download PDF report |
| `GET` | `/api/scan/<scanId>/report/json` | Download JSON report |
| `GET` | `/dashboard` | Results Dashboard page |
| `GET` | `/history` | List of past scan sessions |

---

## 13. Scan Workflow (Sequence)

1. **User** fills target + selects modules on the web form and clicks "Start Scan".
2. **ScanController** receives POST, calls `OrchestrationEngine.createScanJob()`.
3. **OrchestrationEngine** stores the job via `DatabaseManager`, starts a background thread via `startAsync()`.
4. **ScanController** responds with HTTP 202 + `scanId`.
5. **Frontend** begins AJAX polling on `/api/scan/<scanId>/status`.
6. **Background thread** executes each selected scanner wrapper sequentially:
   - `NmapScanner.run()` → parse XML → save results
   - `WhatWebScanner.run()` → parse output → save results
   - `GobusterScanner.run()` → parse output → save results
   - `NucleiScanner.run()` → parse JSON lines → save results
7. **ExploitCorrelator** takes all results, queries `SearchsploitAdapter` for each relevant service/CVE.
8. **OrchestrationEngine** updates scan status to COMPLETED.
9. **Frontend** detects COMPLETED status, redirects to/renders Results Dashboard.
10. **User** views results, optionally downloads PDF/JSON report.

---

## 14. Development Phases (FYP2 Timeline)

### Phase 1: Infrastructure & Setup (Mar 2–17, 2026)
- Kali Linux VM environment setup, install all tools, verify CLI
- Flask skeleton with factory pattern, blueprints, templates
- SQLAlchemy database models for `ScanJob` and `ScanResult`

### Phase 2: Backend Core Logic (Mar 18 – Apr 3, 2026)
- `ScanController` API routes (start scan, get status, get results)
- `OrchestrationEngine` with async threading
- `ToolWrapper` abstract base class (common interface: build command, execute, parse)

### Phase 3: Scanner Modules (Apr 6–30, 2026)
- `NmapScanner` wrapper + XML parser
- `WhatWebScanner` + `GobusterScanner` wrappers
- `NucleiScanner` wrapper + JSON parser
- `SearchsploitAdapter` for exploit correlation

### Phase 4: Frontend Development (Mar 25 – May 7, 2026, runs partly parallel)
- Bootstrap layout + navbar
- Input forms with client/server validation
- AJAX status polling (JavaScript)
- Results Dashboard with Chart.js visualizations
- PDF report generation + download

---

## 15. Testing Plan

### Level 1: Unit Testing (May 18–22)
- IP/domain validation functions
- Nmap XML parser, Nuclei JSON parser (using fixture files)
- Database CRUD operations (in-memory SQLite)

### Level 2: Integration Testing (May 25 – Jun 8)
- API endpoint testing via Postman
- Async job handling (multiple concurrent scans, thread safety)
- Exploit correlation pipeline end-to-end

### Level 3: System Testing (Jun 9–24)
- Full-stack scan against Metasploitable2 VM (happy path)
- Error handling: host down, timeouts, unreachable targets
- Performance overhead measurement

### Level 4: UAT & Finalization (Jun 25 – Jul 13)
- Dashboard usability review with peers
- Report accuracy verification (compare system output vs manual tool output)
- Bug fixing, code refactoring
- Final documentation and packaging

---

## 16. Project Constraints & Limitations

- The engine does NOT execute exploits — it provides intelligence only (scanner + correlator, not auto-exploiter).
- It orchestrates existing tools, not write new vulnerability detection templates or zero-day exploit code.
- Accuracy depends on the underlying open-source tools installed on the host system.
- Designed for single-machine deployment on Kali Linux, not distributed/cloud architecture.
- Searchsploit provides offline exploit correlation — no external API calls needed.

---

## 17. Target Users

1. **Security analysts** — reduce manual effort by automating routine scanning and parsing.
2. **Penetration testers** — unified platform to rapidly map attack surfaces during initial engagement phases.
3. **Students and researchers** — modular platform to understand automated security workflow mechanics.

---

## 18. Key Design Patterns

- **Factory Pattern**: Flask app creation with different configs (dev/test/prod)
- **Abstract Base Class / Template Method**: `Scanner` base class with `run()` and `parseOutput()`
- **Adapter Pattern**: `SearchsploitAdapter` isolates Searchsploit CLI specifics
- **MVC-ish**: `WebDashboard` (View) → `ScanController` (Controller) → `OrchestrationEngine` + `DatabaseManager` (Model)

---

## 19. File/Folder Structure (Suggested)

```
vuln-orchestrator/
├── app/
│   ├── __init__.py              # Flask factory (create_app)
│   ├── config.py                # Dev/Test/Prod configs
│   ├── models/
│   │   ├── scan_job.py          # ScanJob model
│   │   ├── scan_result.py       # ScanResult model
│   │   └── exploit_correlation.py
│   ├── controllers/
│   │   └── scan_controller.py   # API routes (Blueprint)
│   ├── engine/
│   │   ├── orchestration.py     # OrchestrationEngine
│   │   ├── scanner_base.py      # Abstract Scanner class
│   │   ├── nmap_scanner.py
│   │   ├── whatweb_scanner.py
│   │   ├── gobuster_scanner.py
│   │   ├── nuclei_scanner.py
│   │   └── searchsploit_adapter.py
│   ├── parsers/
│   │   ├── nmap_parser.py       # XML parsing
│   │   ├── nuclei_parser.py     # JSON lines parsing
│   │   ├── whatweb_parser.py
│   │   └── gobuster_parser.py
│   ├── services/
│   │   ├── db_manager.py        # DatabaseManager
│   │   ├── exploit_correlator.py
│   │   └── report_generator.py
│   ├── templates/
│   │   ├── base.html            # Bootstrap layout + navbar
│   │   ├── scan_config.html     # Scan configuration form
│   │   ├── scan_status.html     # Status polling page
│   │   ├── dashboard.html       # Results dashboard
│   │   └── history.html         # Past scans list
│   └── static/
│       ├── css/
│       ├── js/
│       │   └── status_poll.js   # AJAX polling logic
│       └── img/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/                # Sample Nmap XML, Nuclei JSON, etc.
├── migrations/                  # Alembic DB migrations
├── requirements.txt
├── run.py                       # Entry point
└── README.md
```

---

## 20. Early Prototype (Completed in FYP1)

An input validation module prototype was implemented during FYP1 to prove technical feasibility. It uses Flask to serve a web form, Python's `ipaddress` library to validate IPv4 addresses vs domain names vs malformed inputs, and displays appropriate success/error states in the browser. This validates the foundational web interface approach before full tool integration begins.
