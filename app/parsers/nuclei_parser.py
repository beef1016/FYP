import json

from app.extensions import db
from app.models import ScanResult


def parse_nuclei_json(json_data: str, scan_id: str, target: str):
    """Nuclei emits JSON Lines (one finding per line). Pull severity + CVE."""
    if not json_data:
        print("[PARSER] Invalid Nuclei data received.")
        return

    lines = json_data.strip().split("\n")

    try:
        for line in lines:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                finding = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[PARSER ERROR] Failed to parse a Nuclei JSON line: {e}")
                continue

            template_id = finding.get("template-id", "Unknown Vulnerability")
            info = finding.get("info", {}) or {}
            severity = (info.get("severity") or "info").capitalize()
            description = info.get("description") or "No description provided."

            classification = info.get("classification") or {}
            cve_list = classification.get("cve-id") or []
            extracted_cve = cve_list[0] if cve_list else None

            # Port can come from the matched-at URL if Nuclei includes one
            matched_at = finding.get("matched-at") or finding.get("host") or ""
            port_int = _port_from(matched_at)

            finding_text = f"{template_id}: {description}".strip()

            db.session.add(ScanResult(
                scan_id=scan_id,
                tool_name="Nuclei",
                host=target,
                port=port_int,
                service=None,
                finding=finding_text,
                severity=severity,
                cve_id=extracted_cve,
                raw_output=line,
            ))

        db.session.commit()
        print("[PARSER] Nuclei JSON parsing and database storage complete.")
    except Exception as e:
        db.session.rollback()
        print(f"[PARSER ERROR] Nuclei parser crashed: {e}")


def _port_from(url_or_host: str):
    """Cheap port extraction from URLs like https://example.com:8080/foo."""
    if not url_or_host or ":" not in url_or_host:
        return None
    # strip scheme
    s = url_or_host.split("//", 1)[-1]
    # take up to first '/' or end
    s = s.split("/", 1)[0]
    if ":" not in s:
        return None
    port_part = s.rsplit(":", 1)[-1]
    try:
        return int(port_part)
    except ValueError:
        return None
