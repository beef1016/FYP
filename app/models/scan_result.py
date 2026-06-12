from app.extensions import db


class ScanResult(db.Model):
    """A unified scan finding from any tool (spec section 11: scan_results)."""
    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(
        db.String(36), db.ForeignKey("scan_jobs.scan_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    tool_name = db.Column(db.String(50), nullable=False)
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, nullable=True)
    service = db.Column(db.String(50), nullable=True)
    finding = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="Info")
    raw_output = db.Column(db.Text, nullable=True)

    # Deviation from spec: needed so the correlator can locate CVE-tagged rows
    # without text-matching `finding`. See CLAUDE.md.
    cve_id = db.Column(db.String(20), nullable=True, index=True)

    # Structured banner — populated by Nmap (-sV) and WhatWeb parsers.
    # Enables the correlator's second pass: `searchsploit <product> <version>`.
    product = db.Column(db.String(100), nullable=True, index=True)
    version = db.Column(db.String(50), nullable=True)

    correlations = db.relationship(
        "ExploitCorrelation",
        backref="result",
        lazy=True,
        cascade="all, delete-orphan",
    )

    @property
    def has_public_exploit(self) -> bool:
        return bool(self.correlations)
