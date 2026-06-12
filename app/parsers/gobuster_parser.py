import re

from app.extensions import db
from app.models import ScanResult


# Gobuster -q output lines look like:  "/admin                (Status: 301) [Size: 178]"
_PATH_LINE = re.compile(r"^(/\S+)\s+\(Status:\s*(\d{3})\)")


def parse_gobuster_text(text_data: str, scan_id: str, target: str,
                        port: int | None = None, scheme: str = "http"):
    """Parser dispatch — `port` is filled in by the orchestrator so the row
    can record which HTTP service the path was found on."""
    if not text_data or "error" in text_data:
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
            discovered_path = m.group(1)
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
                severity="Medium",
                raw_output=line,
            ))

        db.session.commit()
        print("[PARSER] Gobuster text parsing and database storage complete.")
    except Exception as e:
        db.session.rollback()
        print(f"[PARSER ERROR] Gobuster parser crashed: {e}")
