"""OrchestrationEngine (spec section 6) — the central coordinator.

Pipeline phases:
1. **Sequential prerequisites** — Nmap. Its findings drive HTTP-port detection
   for Gobuster and WhatWeb, so it has to finish before phase 2.
2. **Concurrent followers** — WhatWeb, Nuclei, Gobuster. Each tool's subprocess
   runs in a worker thread. WhatWeb / Gobuster expand into one work unit per
   HTTP port (`(port, scheme)`), all of which run in parallel.
3. **Correlation** — searchsploit. Sequential again, in the orchestrator thread.

Concurrency model: workers ONLY run scanner subprocesses (the slow, I/O-bound
part). Parsing + DB writes happen back on the orchestrator thread via
`as_completed`, which keeps SQLAlchemy session usage single-threaded and avoids
SQLite "database is locked" races.

Owns the in-memory progress map keyed by scan_id (NOT persisted; cleared when
the scan reaches a terminal state).
"""
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from app.models import ScanJob, ScanResult, ScanStatus
from app.engine.registry import SCANNER_REGISTRY
from app.parsers import PARSERS


# Service names Nmap commonly assigns to HTTP-bearing ports. Used to decide
# whether to run Gobuster / WhatWeb and which port(s) to point them at.
_HTTP_SERVICE_NAMES = {
    "http", "http-alt", "http-proxy", "https", "https-alt",
    "http-mgmt", "https-mgmt", "www", "www-http",
}
# Port-number fallback in case Nmap didn't get a service name
_HTTP_PORT_FALLBACK = {80, 443, 8000, 8008, 8080, 8443, 8888}

# Tools whose findings are prerequisites for other tools in the same scan.
# Runs sequentially in phase 1.
_SEQUENTIAL_FIRST = {"nmap"}
# Tools that need an HTTP/HTTPS port and iterate once per detected port.
_HTTP_AWARE = {"whatweb", "gobuster"}
# Cap on concurrent worker threads. I/O-bound, so we just need enough to
# overlap subprocess waits without spawning silly numbers of threads.
_MAX_CONCURRENT_WORKERS = 4


def _http_targets_from_scan(scan_id: str) -> list[tuple[int, str]]:
    """Return (port, scheme) pairs Nmap saw http on for this scan."""
    rows = (
        ScanResult.query
        .filter(ScanResult.scan_id == scan_id, ScanResult.tool_name == "Nmap")
        .all()
    )
    targets = []
    for r in rows:
        if r.port is None:
            continue
        service = (r.service or "").lower()
        is_http = service in _HTTP_SERVICE_NAMES or r.port in _HTTP_PORT_FALLBACK
        if not is_http:
            continue
        scheme = "https" if "https" in service or r.port in (443, 8443) else "http"
        targets.append((r.port, scheme))
    # De-dupe while preserving order
    seen, unique = set(), []
    for t in targets:
        if t in seen:
            continue
        seen.add(t)
        unique.append(t)
    return unique


class OrchestrationEngine:
    def __init__(self, flask_app, db_manager, exploit_correlator):
        self.app = flask_app
        self.db = db_manager
        self.correlator = exploit_correlator
        # scan_id -> {"step": int, "total": int, "current_tool": str|None}
        self._progress: dict[str, dict] = {}

    # --- Public API ------------------------------------------------------
    def create_scan_job(
        self,
        target: str,
        selected_tools: list[str],
        target_port: int | None = None,
        target_scheme: str | None = None,
    ) -> ScanJob:
        """Persist a ScanJob, spawn the worker thread, return the row.

        `target_port`/`target_scheme` are the optional URL hint from the user.
        They get merged into the HTTP-target list used by WhatWeb and Gobuster
        so a user-specified port is scanned even if Nmap missed it.
        """
        job = self.db.add(ScanJob(
            target=target,
            status=ScanStatus.PENDING,
            selected_modules=list(selected_tools),
            target_port=target_port,
            target_scheme=target_scheme,
        ))
        self.db.commit()

        self._progress[job.scan_id] = {
            "step": 0,
            "total": len(selected_tools) + 1,
            "current_tool": None,
        }

        threading.Thread(
            target=self.execute_scan,
            args=(job.scan_id,),
            daemon=True,
        ).start()
        return job

    def progress_for(self, scan_id: str) -> dict:
        return self._progress.get(scan_id, {})

    # --- HTTP-target resolution -----------------------------------------
    def _resolve_http_targets(self, job, scan_id, selected_tools):
        """Combine Nmap-discovered HTTP ports with the user's URL hint."""
        targets: list[tuple[int, str]] = []
        seen: set[tuple[int, str]] = set()

        def add(port, scheme):
            key = (port, scheme)
            if key in seen:
                return
            seen.add(key)
            targets.append(key)

        if job.target_port and job.target_scheme:
            add(job.target_port, job.target_scheme)
        if "nmap" in selected_tools:
            for port, scheme in _http_targets_from_scan(scan_id):
                add(port, scheme)
        return targets

    # --- Work-unit construction (main thread, DB-aware) ------------------
    def _build_work_units(self, tools, job, scan_id, selected_tools):
        """Expand a tool list into concrete (tool_name, port, scheme) units.

        HTTP-aware tools fan out one unit per (port, scheme); other tools
        produce a single (tool_name, None, None) unit. Returns a list of
        dicts ready for the ThreadPoolExecutor.
        """
        http_targets = self._resolve_http_targets(job, scan_id, selected_tools)
        units: list[dict] = []
        for tool_name in tools:
            if tool_name in _HTTP_AWARE:
                if http_targets:
                    targets = http_targets
                elif "nmap" not in selected_tools:
                    # Fall back to plain http://target:80 if Nmap wasn't asked
                    targets = [(80, "http")]
                else:
                    print(f"[SYSTEM] {tool_name} skipped — no HTTP/HTTPS detected.")
                    continue
                for port, scheme in targets:
                    units.append({"tool": tool_name, "port": port, "scheme": scheme})
            else:
                units.append({"tool": tool_name, "port": None, "scheme": None})
        return units

    # --- Single work unit (runs on a worker thread) ---------------------
    @staticmethod
    def _run_work_unit(target: str, unit: dict) -> dict:
        """Pure scanner invocation — NO DB access. Safe to run in a worker.

        Returns the dict that ``BaseScanner.execute_scan`` returns, with the
        original `unit` attached so the orchestrator thread can dispatch the
        right parser when it picks up the future.
        """
        tool_name = unit["tool"]
        scanner_cls = SCANNER_REGISTRY[tool_name]
        if unit["port"] is None:
            scanner = scanner_cls(target)
        else:
            scanner = scanner_cls(target, port=unit["port"], scheme=unit["scheme"])
        result = scanner.execute_scan()
        result["_unit"] = unit
        return result

    # --- Result persistence (runs on the orchestrator thread) ----------
    def _persist_result(self, result: dict, target: str, scan_id: str):
        """Dispatch a completed work unit's output to the right parser."""
        unit = result["_unit"]
        tool_name = unit["tool"]
        if result["status"] != "success":
            print(f"[SYSTEM] {tool_name} ({unit['port']}/{unit['scheme']}) "
                  f"failed: {result.get('error_message', '?')}")
            return
        parser = PARSERS[tool_name]
        if unit["port"] is None:
            parser(result["output"], scan_id, target)
        else:
            parser(result["output"], scan_id, target,
                   port=unit["port"], scheme=unit["scheme"])

    # --- Phase 1: sequential prerequisites -----------------------------
    def _run_sequential_phase(self, tools, job, scan_id, selected_tools, step_offset, total):
        """Run sequential tools one at a time. Currently just Nmap."""
        step = step_offset
        for tool_name in tools:
            step += 1
            self._progress[scan_id] = {
                "step": step, "total": total, "current_tool": tool_name,
            }
            units = self._build_work_units([tool_name], job, scan_id, selected_tools)
            for unit in units:
                result = self._run_work_unit(job.target, unit)
                self._persist_result(result, job.target, scan_id)
        return step

    # --- Phase 2: concurrent followers ---------------------------------
    def _run_concurrent_phase(self, tools, job, scan_id, selected_tools, step_offset, total):
        """Fan out the remaining tools across a thread pool.

        IMPORTANT: workers ONLY call scanner.execute_scan (a subprocess wait).
        All parsing and DB writes happen back on this orchestrator thread via
        the `as_completed` loop, so SQLAlchemy stays single-threaded.
        """
        units = self._build_work_units(tools, job, scan_id, selected_tools)
        if not units:
            return step_offset

        in_flight = {u["tool"] for u in units}
        self._progress[scan_id] = {
            "step": step_offset, "total": total,
            "current_tool": "+".join(sorted(in_flight)),
        }
        print(f"[SYSTEM] Phase 2 (concurrent): {len(units)} work units across "
              f"{len(in_flight)} tools — {sorted(in_flight)}")

        workers = min(_MAX_CONCURRENT_WORKERS, len(units))
        step = step_offset
        completed_tools: dict[str, int] = {t: 0 for t in in_flight}
        unit_counts = {t: sum(1 for u in units if u["tool"] == t) for t in in_flight}

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(self._run_work_unit, job.target, u): u for u in units
            }
            for future in as_completed(future_map):
                unit = future_map[future]
                tool_name = unit["tool"]
                try:
                    result = future.result()
                except Exception as e:
                    print(f"[SYSTEM ERROR] {tool_name} worker crashed: {e}")
                    completed_tools[tool_name] += 1
                    continue

                # Persist on THIS thread (orchestrator thread) — keeps DB writes serial
                self._persist_result(result, job.target, scan_id)

                completed_tools[tool_name] += 1
                # If every unit for this tool has come in, drop it from "in flight"
                if completed_tools[tool_name] == unit_counts[tool_name]:
                    in_flight.discard(tool_name)
                    step += 1
                    self._progress[scan_id] = {
                        "step": step, "total": total,
                        "current_tool": "+".join(sorted(in_flight)) if in_flight else None,
                    }
        return step

    # --- Worker ----------------------------------------------------------
    def execute_scan(self, scan_id: str):
        with self.app.app_context():
            job = self.db.get_scan(scan_id)
            if not job:
                print(f"[SYSTEM ERROR] Missing ScanJob {scan_id}")
                return

            selected_tools = list(job.selected_modules or [])
            seq_tools  = [t for t in selected_tools if t in _SEQUENTIAL_FIRST]
            conc_tools = [t for t in selected_tools if t not in _SEQUENTIAL_FIRST]
            total = len(selected_tools) + 1   # +1 for correlation phase

            try:
                job.status = ScanStatus.RUNNING
                self.db.commit()

                # Phase 1: sequential (Nmap)
                step = self._run_sequential_phase(
                    seq_tools, job, scan_id, selected_tools, 0, total
                )

                # Phase 2: concurrent (WhatWeb + Nuclei + Gobuster)
                if conc_tools:
                    step = self._run_concurrent_phase(
                        conc_tools, job, scan_id, selected_tools, step, total
                    )

                # Phase 3: exploit correlation
                self._progress[scan_id] = {
                    "step": total, "total": total, "current_tool": "searchsploit",
                }
                self.correlator.correlate(scan_id)

                job.status = ScanStatus.COMPLETED
                job.end_time = datetime.now(timezone.utc)
                self.db.commit()
                print(f"[SYSTEM] Orchestration completely finished for {job.target}.")

            except Exception as e:
                print(f"[SYSTEM ERROR] Background thread crashed: {e}")
                job.status = ScanStatus.FAILED
                job.end_time = datetime.now(timezone.utc)
                self.db.commit()
            finally:
                self._progress.pop(scan_id, None)
