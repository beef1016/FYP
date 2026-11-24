"""OWASP ZAP JSON-report parser.

ZAP's `-quickout report.json` produces the "traditional JSON report":

    {"site": [{"@name": "...", "@host": "...", "@port": "80", "@ssl": "false",
               "alerts": [{"name", "riskcode", "desc", "solution", "reference",
                           "cweid", "wascid", "count", "instances": [...]}, ...]}]}

We emit one ScanResult per *alert* (not per instance — a single alert can have
dozens of instances; one row per alert keeps the dashboard legible, with the
instance count noted in the finding text).

Any CVE referenced by an alert is extracted into `cve_id`, so ZAP findings feed
the existing Searchsploit + CISA-KEV correlation passes for free.
"""
import json
import re

from app.extensions import db
from app.models import ScanResult


# ZAP riskcode → our severity scale. ZAP has no "Critical"; its top risk is High.
_RISK_SEVERITY = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def parse_zap_json(json_data: str, scan_id: str, target: str,
                   port: int | None = None, scheme: str = "http"):
    """Parser dispatch — `port`/`scheme` come from the orchestrator so each ZAP
    row records which HTTP service was scanned."""
    if not json_data or not json_data.strip():
        return

    try:
        report = json.loads(json_data)
    except json.JSONDecodeError as e:
        print(f"[PARSER WARNING] Could not parse ZAP JSON: {e}")
        return

    try:
        for site in report.get("site", []) or []:
            for alert in site.get("alerts", []) or []:
                name = alert.get("name") or alert.get("alert") or "ZAP alert"
                riskcode = str(alert.get("riskcode", "0"))
                severity = _RISK_SEVERITY.get(riskcode, "Info")

                desc = _clean(alert.get("desc"))
                cweid = str(alert.get("cweid") or "").strip()
                instances = alert.get("instances") or []
                count = alert.get("count") or len(instances)

                finding = name
                if desc:
                    finding += f": {desc[:400]}"
                meta = []
                if cweid and cweid not in ("", "-1"):
                    meta.append(f"CWE-{cweid}")
                if count:
                    meta.append(f"{count} instance(s)")
                # Show the first affected URL so the finding is actionable.
                first_uri = (instances[0].get("uri") if instances else "") or ""
                if first_uri:
                    meta.append(first_uri)
                if meta:
                    finding += f" [{' | '.join(meta)}]"

                # Pull a CVE from the alert's reference/desc so it joins the
                # Searchsploit + KEV correlation passes.
                haystack = " ".join(str(alert.get(k, "")) for k in
                                    ("reference", "desc", "name", "otherinfo"))
                cve_match = _CVE_RE.search(haystack)
                cve_id = cve_match.group(0).upper() if cve_match else None

                db.session.add(ScanResult(
                    scan_id=scan_id,
                    tool_name="ZAP",
                    host=target,
                    port=port,
                    service=scheme,
                    finding=finding,
                    severity=severity,
                    cve_id=cve_id,
                    # ZAP is DAST: it sends payloads and matches the response, so
                    # an alert is a directly-observed (confirmed) web weakness.
                    evidence="confirmed",
                    raw_output=json.dumps(alert)[:4000],
                ))

        db.session.commit()
        print("[PARSER] ZAP JSON parsing complete.")

    except Exception as e:
        db.session.rollback()
        print(f"[PARSER WARNING] ZAP parser crashed: {e}")


def _clean(html_text) -> str:
    """Strip ZAP's HTML markup to a single-line plaintext snippet."""
    if not html_text:
        return ""
    return _WS_RE.sub(" ", _TAG_RE.sub(" ", str(html_text))).strip()
