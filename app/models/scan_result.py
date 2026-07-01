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

    @property
    def finding_class(self) -> str:
        """Classify a finding by its nature for exploitation framing.

        The exploit column only makes sense for vulnerabilities; recon rows
        (open ports, fingerprints, discovered paths) are attack-surface
        context, not exploitable in themselves. See `exploitation_context`.
        """
        if self.has_public_exploit:
            return "exploitable"
        if self.cve_id:
            return "vulnerability"          # CVE, but no public exploit indexed
        if self.product and self.version:
            return "versioned"              # software banner, no exploit hit
        tool = (self.tool_name or "").lower()
        if tool == "gobuster":
            return "resource"               # discovered path / file
        if tool == "whatweb":
            return "fingerprint"            # technology fingerprint
        if tool == "nmap":
            return "exposure"               # open port / reachable service
        return "informational"

    @property
    def exploitation_context(self):
        """Human-readable 'how this matters for exploitation' for findings with
        no directly-attached public exploit, so no row is a dead end. Returns
        None when an exploit is already attached (the exploit speaks for itself).
        """
        if self.has_public_exploit:
            return None
        cls = self.finding_class
        if cls == "vulnerability":
            return (f"{self.cve_id.upper()} has no public exploit indexed — "
                    "confirm via vendor advisory and manual testing.")
        if cls == "versioned":
            return (f"No public exploit for {self.product} {self.version} — "
                    "monitor for new disclosures or test manually.")
        if cls == "exposure":
            svc = self.service or "service"
            where = f" on port {self.port}" if self.port else ""
            return (f"Exposed {svc}{where}: attack surface — restrict access; "
                    "exploitable only if a vulnerable version is confirmed.")
        if cls == "resource":
            return ("Discovered resource — potential entry point; review for "
                    "sensitive content, default credentials, or auth bypass.")
        if cls == "fingerprint":
            return ("Technology fingerprint — guides targeted exploit "
                    "selection; not directly exploitable.")
        return ("Informational / misconfiguration — remediate via "
                "configuration; no exploit script applicable.")
