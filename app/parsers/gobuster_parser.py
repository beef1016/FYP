import re

from app.extensions import db
from app.models import ScanResult


# Gobuster -q output lines. Gobuster v3.x DROPPED the leading slash, so it now
# emits e.g.  "phpMyAdmin           (Status: 301) [Size: 328] [--> ...]"
# (older builds emitted "/phpMyAdmin  (Status: 301) ..."). The leading slash is
# therefore optional — match either form, then normalise the slash back on, or
# every discovered path is silently dropped and Gobuster shows 0 findings.
_PATH_LINE = re.compile(r"^/?(\S+)\s+\(Status:\s*(\d{3})\)")

# Path fragments that make a *reachable* (HTTP 200) resource notable: info
# disclosure, DB/admin consoles, backups, source/VCS, secrets. Deliberately
# CONSERVATIVE — broad words like "admin"/"upload"/"login" match ordinary pages
# and would over-flag, so only high-signal, specific fragments are listed.
_SENSITIVE = (
    "phpinfo", "phpmyadmin", "adminer", "backup", "dump",
    ".git", ".svn", ".env", ".sql", ".bak", "wp-admin",
)


def _severity_for(path: str, status: str) -> str:
    """Tie severity to the HTTP status and how sensitive the path is.

    A discovered path is attack surface, not a confirmed vulnerability, so
    Gobuster's ceiling is MEDIUM — it never rates a path High. (A sensitive 200
    like ``/phpinfo.php`` is Medium here, so it can't outrank a confirming tool
    such as Nuclei, which rates the same page Low/Info.)

      * 200 (reachable): sensitive -> Medium, otherwise Low.
      * 301/302 (exists, redirects): sensitive -> Low, otherwise Info.
      * 401/403 (protected, existence leak only): sensitive -> Low, else Info.
      * 500 (error, may leak a stack trace): Low.
      * anything else: Info.
    """
    low = path.lower()
    sensitive = any(frag in low for frag in _SENSITIVE)
    if status == "200":
        return "Medium" if sensitive else "Low"
    if status in ("301", "302"):
        return "Low" if sensitive else "Info"
    if status in ("401", "403"):
        return "Low" if sensitive else "Info"
    if status == "500":
        return "Low"
    return "Info"


def parse_gobuster_text(text_data: str, scan_id: str, target: str,
                        port: int | None = None, scheme: str = "http"):
    """Parser dispatch — `port` is filled in by the orchestrator so the row
    can record which HTTP service the path was found on."""
    # Note: don't bail on a literal "error" substring — wordlists contain words
    # like "error"/"error_log", and a discovered path such as "/error_log"
    # would otherwise discard the whole scan. Non-result lines are filtered by
    # the per-line regex below instead.
    if not text_data:
        print("[PARSER] Invalid Gobuster data received.")
        return

    try:
        for raw_line in text_data.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            m = _PATH_LINE.match(line)
            if not m:
                continue
            discovered_path = "/" + m.group(1).lstrip("/")  # normalise leading slash
            status_code = m.group(2)

            finding = (
                f"Hidden directory: {discovered_path} (HTTP {status_code})"
            )

            db.session.add(ScanResult(
                scan_id=scan_id,
                tool_name="Gobuster",
                host=target,
                port=port,
                service=scheme,
                finding=finding,
                severity=_severity_for(discovered_path, status_code),
                # A 200 means Gobuster actually retrieved the resource (confirmed
                # it is reachable); a redirect/forbidden only infers existence
                # (presumed). Label hidden on these recon rows (show_evidence).
                evidence="confirmed" if status_code == "200" else "presumed",
                raw_output=line,
            ))

        db.session.commit()
        print("[PARSER] Gobuster text parsing and database storage complete.")
    except Exception as e:
        db.session.rollback()
        print(f"[PARSER ERROR] Gobuster parser crashed: {e}")
