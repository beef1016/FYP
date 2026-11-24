"""Lock the prioritisation order against a real-scan fixture.

The scan review agreed a three-tier ranking (see ScanResult.priority_key):

    tier 0  CISA KEV *and* confirmed
    tier 1  a public exploit targets the finding's CVE
    tier 2  everything else, by severity
    within a tier: confirmed before presumed, then severity, then CVSS, EPSS

`tests/fixtures/ranking_metasploitable2.json` encodes the Metasploitable 2
findings that motivated the rule. This test rebuilds them and asserts the
prioritiser reproduces the agreed order, so a future change can't silently
reorder findings (e.g. let a presumed KEV outrank a confirmed finding, or let a
banner-only exploit elevate an Info row above a Critical).

No pytest in this project's venv, so it runs both as a pytest test and as a
plain script:  python tests/test_ranking_order.py
"""
import json
import os
from pathlib import Path

os.environ.setdefault("EXPLOITLINK_AUTH_PASSWORD", "test-pass")

from app import create_app
from app.config import TestConfig
from app.extensions import db
from app.models import ScanJob, ScanResult, ScanStatus, ExploitCorrelation

_FIXTURE = Path(__file__).with_name("fixtures") / "ranking_metasploitable2.json"


def _build(scan_id, entry):
    """Create one ScanResult (+ its exploit links) from a fixture entry."""
    row = ScanResult(
        scan_id=scan_id,
        tool_name=entry["tool_name"],
        host="192.168.114.130",
        port=entry.get("port"),
        finding=entry["id"],                 # id doubles as the finding text
        severity=entry["severity"],
        cve_id=entry.get("cve_id"),
        kev_listed=entry.get("kev_listed", False),
        evidence=entry.get("evidence"),
        cvss_score=entry.get("cvss_score"),
        epss_score=entry.get("epss_score"),
        product=entry.get("product"),
        version=entry.get("version"),
    )
    db.session.add(row)
    db.session.flush()
    for ex in entry.get("exploits", []):
        db.session.add(ExploitCorrelation(
            result_id=row.id, exploit_title="exploit", exploit_id="x",
            match_type=ex["match_type"]))
    db.session.flush()
    return row


def test_priority_order_matches_fixture():
    data = json.loads(_FIXTURE.read_text())
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        job = ScanJob(target="192.168.114.130", status=ScanStatus.COMPLETED,
                      selected_modules=["nmap", "nuclei", "whatweb"])
        db.session.add(job)
        db.session.commit()

        by_finding = {}
        for entry in data["findings"]:
            by_finding[entry["id"]] = _build(job.scan_id, entry)
        db.session.commit()

        ordered = sorted(ScanResult.query.filter_by(scan_id=job.scan_id).all(),
                         key=lambda r: r.priority_key)
        got = [r.finding for r in ordered]
        assert got == data["expected_order"], (
            f"\n got: {got}\n expected: {data['expected_order']}")

        # Spot-check the tier reasoning the order depends on.
        php_cgi = by_finding["php-cgi"]
        php_oom = by_finding["php-oom"]
        apache = by_finding["apache-banner"]
        samba = by_finding["samba-printing"]
        assert php_cgi.priority_tier_rank == 0            # KEV + confirmed
        assert php_oom.priority_tier_rank == 1 and php_oom.is_presumed  # presumed KEV
        assert apache.priority_tier_rank == 2 and not apache.has_cve_exploit
        assert apache.priority_key > samba.priority_key   # banner-only below Critical


if __name__ == "__main__":
    test_priority_order_matches_fixture()
    print("test_ranking_order: PASSED")
