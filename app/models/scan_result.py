from app.extensions import db
from app.services.redaction import mask_credentials


# Canonical severity ordering (most → least severe). Single source of truth for
# sorting and for the priority key below. NOTE: these labels are qualitative and
# tool-reported (ZAP riskcode, Nuclei template severity) or app heuristics (Nmap
# service table, Gobuster/WhatWeb constants) — they are NOT derived from CVSS.
SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


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

    # CISA KEV enrichment — set by ExploitCorrelator's third pass when this
    # row's cve_id appears in the local Known-Exploited-Vulnerabilities mirror.
    # `kev_listed` is the queryable flag; `kev_data` holds the trimmed KEV
    # record (dateAdded / dueDate / ransomware / requiredAction) for display.
    kev_listed = db.Column(db.Boolean, nullable=False, default=False, index=True)
    kev_data = db.Column(db.JSON, nullable=True)

    # Cross-tool correlation (keep-both-and-link). Set by the correlator's final
    # pass. Two INDEPENDENT groupings, because tool overlaps are of two kinds:
    #
    #   identity  (dup_group/dup_tools) — the SAME finding seen twice: a shared
    #       CVE, or the same product+version banner. Genuine corroboration.
    #   location  (loc_group/loc_tools) — the SAME URL path touched by different
    #       tools (e.g. Gobuster found /admin, ZAP alerted on /admin). This is
    #       co-location, NOT "the same issue": Gobuster confirmed the path, it
    #       did not detect ZAP's vulnerability — so it must never read as "also
    #       detected by". Kept separate so a path match can't pollute identity.
    #
    # Each *_group is a per-scan cluster id; each *_tools is the sorted list of
    # distinct tools in that cluster (including this one). All stay NULL when the
    # finding has no cross-tool overlap of that kind.
    dup_group = db.Column(db.Integer, nullable=True, index=True)
    dup_tools = db.Column(db.JSON, nullable=True)
    loc_group = db.Column(db.Integer, nullable=True, index=True)
    loc_tools = db.Column(db.JSON, nullable=True)

    # Evidence strength — "confirmed" (a tool observed the issue directly: a
    # response matched, a login succeeded, a port is open) vs "presumed" (the
    # finding was inferred from a version/banner, e.g. a Nuclei
    # `version-eol-branch` match). Used to rank confirmed findings above
    # presumed ones within the same priority tier. NULL = treated as confirmed.
    evidence = db.Column(db.String(20), nullable=True)

    # Optional CVSS base score + EPSS probability, captured from Nuclei CVE
    # templates when present. Used ONLY as free tie-breakers in ranking (higher
    # first). EPSS is a snapshot from when the template/feed was published, not
    # a live value — treated as a hint, never authoritative.
    cvss_score = db.Column(db.Float, nullable=True)
    epss_score = db.Column(db.Float, nullable=True)

    # How many raw tool hits this row represents. Parsers that collapse repeated
    # hits of the same template/host/port into one row (Nuclei) set this to the
    # number collapsed; every other row is a single hit (default 1). Lets the
    # report show a *tool-reported* total alongside the post-collapse row count.
    instance_count = db.Column(db.Integer, nullable=False, default=1)

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
    def has_cve_exploit(self) -> bool:
        """True when a public exploit is linked to this finding's *CVE* (not just
        its product banner). A CVE-linked exploit targets exactly this flaw, so
        it is strong real-world-exploitability evidence; a banner-only match
        (same software, possibly a different flaw) is not and must not elevate a
        finding above severity. Legacy rows (match_type NULL) count as banner-only.
        """
        return any((c.match_type or "") == "cve" for c in self.correlations)

    @staticmethod
    def _others(tool_list, me):
        me = (me or "").strip().lower()
        return [t for t in (tool_list or []) if (t or "").strip().lower() != me]

    @property
    def corroborating_tools(self) -> list:
        """Other tools that reported this SAME finding (identity: CVE/banner).

        Excludes this row's own tool, so it reads naturally as 'also detected
        by …'. Empty when the finding is not cross-tool corroborated.
        """
        return self._others(self.dup_tools, self.tool_name)

    @property
    def is_corroborated(self) -> bool:
        """True when another tool corroborates this exact finding."""
        return bool(self.corroborating_tools)

    @property
    def colocated_tools(self) -> list:
        """Other tools that touched the SAME URL path (location, not identity).

        Reads as 'same path also mapped by …'. This is deliberately distinct
        from `corroborating_tools`: a shared path means the tools looked at the
        same resource, not that they found the same issue.
        """
        return self._others(self.loc_tools, self.tool_name)

    @property
    def is_colocated(self) -> bool:
        """True when another tool touched the same path as this finding."""
        return bool(self.colocated_tools)

    # --- Prioritisation --------------------------------------------------
    # Ordering rule (most urgent first), in THREE tiers:
    #
    #   Tier 0 — KEV-listed AND confirmed. CISA says it is exploited in the wild
    #            and a tool confirmed our target is actually affected. Only the
    #            combination earns the top tier: a *presumed* KEV match (inferred
    #            from a version banner) drops a tier but keeps its KEV label,
    #            because KEV means "exploited somewhere", not "your host is
    #            vulnerable".
    #   Tier 1 — a public exploit is linked to the finding's CVE (targets exactly
    #            this flaw). Strong, weaponisable evidence, so above bare severity.
    #            A banner-only exploit match (same software, maybe another flaw)
    #            does NOT qualify — it must not lift an Info fingerprint above a
    #            Critical.
    #   Tier 2 — everything else, ranked by severity.
    #
    # Within every tier: confirmed before presumed, then severity, then CVSS,
    # then EPSS, then a stable content key. Severity is a qualitative, tool-
    # reported label (see SEVERITY_RANK note), never CVSS-derived. The report
    # explains this ordering in prose for transparency.
    @property
    def is_presumed(self) -> bool:
        """True when this finding was inferred from a version/banner rather than
        confirmed by a direct response/behaviour (see `evidence`)."""
        return (self.evidence or "").strip().lower() == "presumed"

    @property
    def priority_tier_rank(self) -> int:
        """0/1/2 — the coarse tier (see the class-level ordering note)."""
        if self.kev_listed and not self.is_presumed:
            return 0
        if self.has_cve_exploit:
            return 1
        return 2

    @property
    def _content_key(self) -> tuple:
        """Deterministic tie-breaker derived from content, not the DB row id
        (row ids are unstable across repeat scans; NFR-03 wants stable order)."""
        return (
            (self.host or "").lower(),
            self.port if self.port is not None else -1,
            (self.tool_name or "").lower(),
            self.finding or "",
        )

    @property
    def priority_key(self) -> tuple:
        """Sort key — lower sorts first (higher priority):
        tier (0 KEV+confirmed / 1 CVE-linked exploit / 2 by severity) →
        confirmed-before-presumed → severity → CVSS (desc) → EPSS (desc) →
        stable content key. Evidence sits ABOVE severity inside a tier, so a
        confirmed finding never loses to a presumed one; and a banner-only
        exploit no longer elevates a finding (only a CVE-linked one does)."""
        return (
            self.priority_tier_rank,
            1 if self.is_presumed else 0,
            SEVERITY_RANK.get(self.severity, 5),
            -(self.cvss_score or 0.0),
            -(self.epss_score or 0.0),
            self._content_key,
        )

    @property
    def priority_tier(self) -> str:
        """Short label for *why* this finding sits where it does."""
        rank = self.priority_tier_rank
        if rank == 0:
            return "Actively exploited (CISA KEV), confirmed"
        if rank == 1:
            return "Public exploit targets this CVE"
        if self.kev_listed:            # presumed KEV that dropped out of tier 0
            return f"CISA KEV (presumed) — ranked by {self.severity} severity"
        return f"{self.severity} severity"

    @property
    def priority_reason(self) -> str:
        """One-line justification for the finding's priority tier."""
        presumed = (" It is *presumed* (inferred from a version banner, not "
                    "confirmed by a response), so it ranks below confirmed "
                    "findings in its tier.") if self.is_presumed else ""
        rank = self.priority_tier_rank
        if rank == 0:
            return ("Listed in CISA KEV and confirmed on this target — exploited "
                    "in the wild, so ranked above everything else.")
        if rank == 1:
            base = ("A public exploit targets this finding's CVE — elevated above "
                    "severity because it is readily weaponisable.")
            if self.kev_listed:
                base = ("Listed in CISA KEV with a public exploit for its CVE. "
                        + base)
            return base + presumed
        if self.kev_listed:
            return ("Listed in CISA KEV, but the match here is presumed (version-"
                    "inferred), so it is ranked by its severity rather than placed "
                    "in the top tier — still flagged as KEV." + presumed)
        if self.has_public_exploit:
            return ("A public exploit names this software, but only matched its "
                    "version banner (not a specific CVE), so it is ranked by "
                    f"{self.severity} severity, not elevated." + presumed)
        return (f"No KEV listing or CVE-linked exploit; ranked by its "
                f"{self.severity} severity rating." + presumed)

    @property
    def kev_ransomware(self) -> bool:
        """True when CISA flags this CVE as used in ransomware campaigns."""
        return (self.kev_data or {}).get(
            "knownRansomwareCampaignUse", ""
        ).strip().lower() == "known"

    @property
    def finding_redacted(self) -> str:
        """Finding text with guessed credentials masked (``admin:admin`` →
        ``admin:****``). Used by every *shareable* surface (PDF, JSON, dashboard,
        API) so a report that leaves the lab doesn't carry working logins. The
        raw `finding` is kept intact in the database for local analysis."""
        return mask_credentials(self.finding)

    @property
    def show_evidence(self) -> bool:
        """Whether to DISPLAY the confirmed/presumed label. Every tool now sets
        `evidence`, but on purely informational recon rows (an open port, a tech
        fingerprint, a discovered path) the label is noise — it only carries
        signal on a finding that makes an actual security claim. So show it only
        for vulnerability-class findings, and hide it elsewhere even though the
        value still participates in ranking tie-breaks.
        """
        return self.finding_class in (
            "exploitable", "actively-exploited", "vulnerability",
            "misconfiguration", "web-weakness",
        )

    @property
    def finding_class(self) -> str:
        """Classify a finding by its nature for exploitation framing.

        The exploit column only makes sense for vulnerabilities; recon rows
        (open ports, fingerprints, discovered paths) are attack-surface
        context, not exploitable in themselves. See `exploitation_context`.
        """
        if self.has_public_exploit:
            return "exploitable"
        if self.kev_listed:
            return "actively-exploited"     # in CISA KEV — exploited in the wild
        if self.cve_id:
            return "vulnerability"          # CVE, but no public exploit indexed
        if self.product and self.version:
            return "versioned"              # software banner, no exploit hit
        tool = (self.tool_name or "").lower()
        if tool == "gobuster":
            return "resource"               # discovered path / file
        if tool == "whatweb":
            return "fingerprint"            # technology fingerprint
        if tool == "zap":
            return "web-weakness"           # DAST web-app finding (XSS, headers, …)
        if tool == "nmap":
            return "exposure"               # open port / reachable service
        # Nuclei (and anything else) with no CVE/banner: a misconfiguration when
        # it is rated a real risk (weak/default credentials, default DBs, …),
        # otherwise purely informational. "informational" on a High/Critical
        # weak-credential finding reads wrong, so promote it.
        if (self.severity or "").lower() in ("critical", "high", "medium"):
            return "misconfiguration"
        return "informational"

    @property
    def exploitation_context(self):
        """Human-readable 'how this matters for exploitation' for findings with
        no directly-attached public exploit, so no row is a dead end. Returns
        None when an exploit is already attached (the exploit speaks for itself).
        """
        if self.has_public_exploit:
            return None
        if self.kev_listed:
            data = self.kev_data or {}
            added = data.get("dateAdded")
            since = f" (in CISA KEV since {added})" if added else " (listed in CISA KEV)"
            rw = " and is linked to ransomware campaigns" if self.kev_ransomware else ""
            cve = (self.cve_id or "This vulnerability").upper()
            return (f"{cve} is actively exploited in the wild{since}{rw}. "
                    "Treat as immediately exploitable and prioritise patching, "
                    "even though no local PoC is indexed.")
        cls = self.finding_class
        if cls == "vulnerability":
            return (f"{self.cve_id.upper()} has no public exploit indexed — "
                    "confirm via vendor advisory and manual testing.")
        if cls == "web-weakness":
            return ("Web-application weakness reported by ZAP (DAST). "
                    "Exploitability depends on the affected URL/parameter — "
                    "review the reported instance and validate manually.")
        if cls == "misconfiguration":
            return ("Security misconfiguration (e.g. weak or default "
                    "credentials, a default database, or an exposed service "
                    "setting) — directly abusable; remediate by changing the "
                    "configuration or credentials.")
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
