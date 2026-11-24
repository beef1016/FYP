"""Nuclei JSONL parser.

Nuclei emits one JSON object per line. Beyond severity + CVE, we now extract
everything needed for cross-tool correlation and evidence-aware ranking, all of
which is present in Nuclei's own JSON:

  * port / scheme   — top-level fields (so HTTP findings stop being port=null and
                      can join Nmap/WhatWeb/Gobuster rows on the right port)
  * matched-at URL  — recorded so the de-dup path signature can link a Nuclei
                      web finding to a Gobuster path / ZAP alert on the same URL
  * product+version — for detection templates (e.g. `php-detect`,
                      `openssh-detect`), so they join Nmap/WhatWeb service rows
  * evidence        — "confirmed" vs "presumed": a `version-eol-branch`-style
                      matcher (or a pure detection template) is version-inferred,
                      so it is marked presumed and ranked below confirmed findings
  * cvss/epss       — captured from `info.classification` as ranking tie-breakers

Repeated hits of the SAME template on the SAME host:port (e.g.
`http-missing-security-headers` ×10, `ftp-weak-credentials` ×8) are collapsed
into ONE finding with an instance count, so the "unique findings" figure is
meaningful. Per-instance detail (matched URLs, extracted credentials/versions)
is preserved in the finding text.
"""
import json
import re

from app.extensions import db
from app.models import ScanResult


# Templates whose id ends in a detection/version suffix are fingerprints, not
# confirmed vulnerabilities — their product name is the stem of the id.
_DETECT_RE = re.compile(r"^(.*?)[-_](detect|detection|version|fingerprint)$", re.I)
# Matcher names that signal a *version-inferred* (presumed) match.
_PRESUMED_MATCHER_RE = re.compile(r"version|eol|branch|outdated|deprecat", re.I)
# A clean, comparable version token: 5.2.4, 4.7p1, 2.3.4, 1.2.3b …
_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[-_]?p\d+|[a-z])?)", re.I)
# Strip a leading banner protocol like "SSH-2.0-" so we don't read "2.0".
_BANNER_PREFIX_RE = re.compile(r"^[A-Za-z]+-\d+\.\d+-", re.I)

_RAW_CAP = 4000      # don't store megabytes of phpinfo etc. per row


def parse_nuclei_json(json_data: str, scan_id: str, target: str):
    if not json_data:
        print("[PARSER] Invalid Nuclei data received.")
        return

    try:
        groups = _group_lines(json_data)
        for (template_id, host, port), inst in groups.items():
            db.session.add(_build_result(scan_id, target, template_id,
                                         host, port, inst))
        db.session.commit()
        print(f"[PARSER] Nuclei: {len(groups)} unique finding(s) stored "
              "(repeated template hits collapsed).")
    except Exception as e:
        db.session.rollback()
        print(f"[PARSER ERROR] Nuclei parser crashed: {e}")


# --------------------------------------------------------------------------- #
def _group_lines(json_data: str) -> dict:
    """Parse each JSONL line and group by (template-id, host, port)."""
    groups: dict[tuple, list[dict]] = {}
    for line in json_data.strip().split("\n"):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"[PARSER ERROR] Bad Nuclei JSON line: {e}")
            continue
        template_id = obj.get("template-id", "unknown")
        host = obj.get("host") or ""
        port = _port_of(obj)
        groups.setdefault((template_id, host, port), []).append(obj)
    return groups


def _build_result(scan_id, target, template_id, host, port, instances) -> ScanResult:
    first = instances[0]
    info = first.get("info", {}) or {}
    classification = info.get("classification") or {}

    severity = (info.get("severity") or "info").capitalize()
    description = (info.get("description") or "").strip()
    cve_list = classification.get("cve-id") or []
    cve_id = cve_list[0] if cve_list else None

    scheme = first.get("scheme") or ("https" if port in (443, 8443) else "http")
    matcher_name = first.get("matcher-name") or first.get("matcher_name")
    evidence = _evidence(template_id, matcher_name)

    # Product/version for detection templates, so they join service rows.
    product = _product_from_template(template_id)
    version = None
    extracted = _all_extracted(instances)
    if product:
        version = _clean_version(extracted[0]) if extracted else None
        if not version:
            product = None     # a detection with no usable version can't join

    cvss = _as_float(classification.get("cvss-score"))
    epss = _as_float(classification.get("epss-score"))

    finding = _finding_text(template_id, description, instances, extracted)

    return ScanResult(
        scan_id=scan_id,
        tool_name="Nuclei",
        host=target,
        port=port,
        service=scheme if port else None,
        finding=finding,
        severity=severity,
        cve_id=cve_id,
        product=product,
        version=version,
        evidence=evidence,
        cvss_score=cvss,
        epss_score=epss,
        instance_count=len(instances),   # raw hits collapsed into this one row
        raw_output=json.dumps(first)[:_RAW_CAP],
    )


# --------------------------------------------------------------------------- #
def _port_of(obj):
    """Port from the top-level field, falling back to the matched-at URL."""
    p = _as_int(obj.get("port"))
    if p is not None:
        return p
    return _port_from(obj.get("matched-at") or obj.get("host") or "")


def _evidence(template_id, matcher_name) -> str:
    if matcher_name and _PRESUMED_MATCHER_RE.search(matcher_name):
        return "presumed"          # inferred from a version/EOL banner
    if _DETECT_RE.match(template_id or ""):
        return "presumed"          # a pure detection/fingerprint template
    return "confirmed"             # a matcher fired on actual response/behaviour


def _product_from_template(template_id):
    m = _DETECT_RE.match(template_id or "")
    if not m:
        return None
    stem = m.group(1).replace("-", " ").replace("_", " ").strip()
    return stem or None


def _clean_version(raw):
    if not raw:
        return None
    s = _BANNER_PREFIX_RE.sub("", str(raw).strip())
    m = _VERSION_RE.search(s)
    return m.group(1) if m else None


def _all_extracted(instances) -> list:
    out = []
    for obj in instances:
        for v in (obj.get("extracted-results") or []):
            v = str(v).strip()
            if v and v not in out:
                out.append(v)
    return out


def _finding_text(template_id, description, instances, extracted) -> str:
    base = f"{template_id}: {description}" if description else template_id
    base = base[:400]
    bits = []
    n = len(instances)
    if n > 1:
        bits.append(f"{n} instances")
    if extracted:
        bits.append("found: " + ", ".join(extracted[:6]))
    if bits:
        base += f" [{' | '.join(bits)}]"
    # Record a matched URL that carries a path, so the de-dup path signature can
    # link this finding to a Gobuster/ZAP hit on the same resource.
    url = _first_path_url(instances)
    if url:
        base += f" [matched: {url}]"
    return base


def _first_path_url(instances):
    """First matched-at URL that has a path component (not a bare host/root)."""
    for obj in instances:
        m = obj.get("matched-at") or ""
        if "://" not in m:
            continue
        after = m.split("//", 1)[-1]
        if "/" in after and after.split("/", 1)[1].strip():
            return m
    return None


def _as_int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _as_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _port_from(url_or_host: str):
    """Cheap port extraction from URLs like https://example.com:8080/foo."""
    if not url_or_host or ":" not in url_or_host:
        return None
    s = url_or_host.split("//", 1)[-1].split("/", 1)[0]
    if ":" not in s:
        return None
    try:
        return int(s.rsplit(":", 1)[-1])
    except ValueError:
        return None
