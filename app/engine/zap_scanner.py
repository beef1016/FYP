"""OWASP ZAP scanner — DAST web-application scanning.

ZAP complements the existing toolkit: Nmap/WhatWeb fingerprint, Nuclei matches
templated CVEs, Gobuster enumerates paths — ZAP adds dynamic web-app testing
(XSS, SQLi, insecure headers, cookie flags, information disclosure).

HTTP-aware, like WhatWeb/Gobuster: the orchestrator passes the (port, scheme)
Nmap saw HTTP on, so ZAP scans each discovered web service.

Invocation: `zap.sh -cmd -quickurl <url> -quickout <report.json>` — a headless
one-shot quick scan (spider + passive + a light active scan). This is the most
portable headless mode: it runs from the single ZAP launcher without managing a
long-lived daemon, and works on a native Kali `zaproxy` install, the official
ZAP Docker image, and tarball installs. Its active component is consistent with
the toolkit's existing posture (Nuclei/Gobuster already send active probes).

The report is written to a file (not stdout), so `execute_scan` is overridden to
run ZAP, then hand the file's contents to the parser via the usual return shape.
"""
import os
import shutil
import subprocess
import tempfile

from .scanner_base import BaseScanner


# Resolution order for the ZAP launcher. Env override wins so an operator can
# pin a specific install; then PATH names; then common absolute locations.
# Mirrors the gobuster wordlist resolver — hard-coding one path breaks the
# other environments.
_ZAP_CANDIDATES = [
    "zap.sh",                       # ZAP tarball / Docker image (on PATH)
    "zaproxy",                      # Kali `zaproxy` apt package launcher
    "/usr/share/zaproxy/zap.sh",    # Kali package install dir
    "/opt/zaproxy/zap.sh",          # manual tarball install
    "/snap/bin/zaproxy",            # snap install
]


def _zap_binary() -> str | None:
    """Return the ZAP launcher path, or None if ZAP isn't installed."""
    env = os.environ.get("EXPLOITLINK_ZAP_CMD")
    if env:
        return env if (os.path.isfile(env) or shutil.which(env)) else None
    for cand in _ZAP_CANDIDATES:
        if os.path.isabs(cand):
            if os.path.isfile(cand):
                return cand
        else:
            found = shutil.which(cand)
            if found:
                return found
    return None


class ZapScanner(BaseScanner):
    name = "zap"
    cli_name = "zap.sh"
    apt_package = "zaproxy"
    # Booting the JVM just to print a version on every Tool-UI load is wasteful
    # (and slow); the apt package is the version. Skip the probe like Searchsploit.
    version_args = None
    # ZAP is the slowest tool in the kit (JVM start + spider + scan). Give it a
    # generous ceiling; a partial report written before a timeout is still used.
    timeout_seconds = 1200

    def __init__(self, target_ip, port: int = 80, scheme: str = "http"):
        super().__init__(target_ip)
        self.port = port
        self.scheme = scheme

    # --- presence detection (override: ZAP isn't a single PATH binary) ---
    @classmethod
    def is_installed(cls) -> bool:
        return _zap_binary() is not None

    def _url(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        if self.port and self.port != default_port:
            return f"{self.scheme}://{self.target_ip}:{self.port}"
        return f"{self.scheme}://{self.target_ip}"

    def _command(self, outfile: str) -> list[str]:
        binary = _zap_binary() or "zap.sh"
        # -silent: don't phone home / auto-update add-ons (keeps scans offline).
        # -quickurl/-quickout/-quickprogress: headless one-shot scan to JSON.
        return [
            binary, "-cmd", "-silent",
            "-quickurl", self._url(),
            "-quickout", outfile,
            "-quickprogress",
        ]

    def get_command(self):
        # Abstract-method contract + logging. The real run (execute_scan) uses a
        # per-run temp path; this representative form keeps the API consistent.
        return self._command("<report.json>")

    def execute_scan(self):
        binary = _zap_binary()
        if not binary:
            return {
                "status": "error",
                "error_message": "OWASP ZAP not installed (zap.sh / zaproxy not found). "
                                 "Install with: sudo apt-get install -y zaproxy",
            }

        with tempfile.TemporaryDirectory(prefix="exploitlink-zap-") as tmp:
            outfile = os.path.join(tmp, "zap-report.json")
            command = self._command(outfile)
            print(f"[SYSTEM] Executing: {' '.join(command)}")
            try:
                result = subprocess.run(
                    command, capture_output=True, text=True,
                    timeout=self.timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                # ZAP may have written a partial report before being killed.
                partial = _read_if_present(outfile)
                if partial:
                    print("[SYSTEM] ZAP timed out — using partial report.")
                    return {"status": "success", "output": partial}
                return {
                    "status": "error",
                    "error_message": f"zap exceeded {self.timeout_seconds}s timeout",
                }
            except FileNotFoundError:
                return {
                    "status": "error",
                    "error_message": f"Tool not installed on this system: {command[0]}",
                }

            report = _read_if_present(outfile)
            if report:
                return {"status": "success", "output": report}
            # No report file. A clean exit with no findings is still a success.
            if result.returncode == 0:
                return {"status": "success", "output": ""}
            return {
                "status": "error",
                "error_message": (result.stderr or result.stdout or "").strip()[:500]
                                 or f"zap exited with code {result.returncode}",
            }


def _read_if_present(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    except OSError:
        return None
    return data if data.strip() else None
