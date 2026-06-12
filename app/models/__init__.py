"""Aggregated model exports.

Schema now follows FYP spec section 11:
- scan_jobs            (PK = scan_id UUID)
- scan_results         (FK → scan_jobs.scan_id)
- exploit_correlations (FK → scan_results.id)

Deviation from spec: `scan_results.cve_id` is an added nullable column so the
correlator can find CVE-tagged findings without text-matching `finding`. This
is documented in CLAUDE.md.
"""
from .scan_job import ScanJob, ScanStatus
from .scan_result import ScanResult
from .exploit_correlation import ExploitCorrelation

__all__ = ["ScanJob", "ScanStatus", "ScanResult", "ExploitCorrelation"]
