"""ReportGenerator (spec section 6) — per-scan PDF + JSON.

Inputs: a ScanJob row (with its ScanResults and their ExploitCorrelations).
Outputs: bytes for download.
"""
import io
import json
from datetime import datetime, timezone
from xml.sax.saxutils import escape as _esc

from app.services.finding_dedup import finding_totals, group_version_conflicts

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)


def _cap(text, limit):
    """Truncate long raw output (e.g. a full phpinfo dump) in exports so a
    single finding can't bloat the report by megabytes."""
    if not text:
        return text
    s = str(text)
    if len(s) <= limit:
        return s
    return s[:limit] + f"… [truncated, {len(s)} chars total]"


SEVERITY_COLORS = {
    "Critical": colors.HexColor("#dc3545"),
    "High":     colors.HexColor("#fd7e14"),
    "Medium":   colors.HexColor("#ffc107"),
    "Low":      colors.HexColor("#20c997"),
    "Info":     colors.HexColor("#0dcaf0"),
}


class ReportGenerator:
    def __init__(self, kev_catalog=None):
        # Optional — used only to print a data-freshness/provenance line so the
        # report is transparent about how current its KEV enrichment is.
        self.kev = kev_catalog

    # --- PDF -------------------------------------------------------------
    def generate_pdf(self, scan) -> bytes:
        styles = self._styles()
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=15*mm, rightMargin=15*mm,
            topMargin=15*mm, bottomMargin=15*mm,
            title=f"ExploitLink Report — {scan.target}",
        )

        story = [
            Paragraph("ExploitLink Vulnerability Report", styles["title"]),
            Paragraph(f"<b>Target:</b> {scan.target}", styles["body"]),
            Paragraph(f"<b>Scan ID:</b> {scan.scan_id}", styles["body"]),
            Paragraph(f"<b>Status:</b> {scan.status}", styles["body"]),
            Paragraph(
                f"<b>Modules:</b> {', '.join(scan.selected_modules or []) or '(none)'}",
                styles["body"],
            ),
            Paragraph(
                f"<b>Started:</b> {scan.start_time.strftime('%Y-%m-%d %H:%M UTC')}"
                if scan.start_time else "<b>Started:</b> —",
                styles["body"],
            ),
            Paragraph(
                f"<b>Ended:</b> {scan.end_time.strftime('%Y-%m-%d %H:%M UTC')}"
                if scan.end_time else "<b>Ended:</b> (in progress)",
                styles["body"],
            ),
            Paragraph(
                f"<b>Report generated:</b> "
                f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                styles["small"],
            ),
        ]
        # Data-provenance line: how current the KEV enrichment is (staleness
        # transparency). Shown only when a KEV catalog is wired in.
        if self.kev is not None:
            story.append(Paragraph(
                f"<b>Enrichment data:</b> {_esc(self.kev.freshness_label())}",
                styles["small"],
            ))
        story.append(Spacer(1, 6*mm))

        # Prioritised order: KEV → public exploit → severity (see the model's
        # priority_key). The table and the prose explanation below share it.
        results = sorted(scan.results, key=lambda r: r.priority_key)
        counts = {sev: 0 for sev in SEVERITY_COLORS}
        for r in results:
            counts[r.severity] = counts.get(r.severity, 0) + 1
        summary_bits = [f"<b>{sev}</b>: {n}" for sev, n in counts.items() if n]
        summary_text = " &nbsp;|&nbsp; ".join(summary_bits) if summary_bits else "No findings."

        # Three honest counts: tool-reported (raw hits), collapsed (after merging
        # repeated template hits within one tool), and unique (after also merging
        # cross-tool identity duplicates; co-located rows stay separate).
        reported, collapsed, unique = finding_totals(results)
        count_bits = [f"<b>{collapsed}</b> findings"]
        if reported != collapsed:
            count_bits.append(
                f"from <b>{reported}</b> raw tool hits "
                f"({reported - collapsed} repeat(s) collapsed)"
            )
        if unique != collapsed:
            count_bits.append(
                f"<b>{unique}</b> unique after merging "
                f"{collapsed - unique} cross-tool duplicate(s)"
            )
        story.append(Paragraph(
            f"<b>Findings:</b> {', '.join(count_bits)} &nbsp; ({summary_text})",
            styles["body"],
        ))
        story.append(Spacer(1, 2*mm))

        if results:
            story.append(self._priority_note(styles))
            story.append(Spacer(1, 3*mm))
            story.append(self._results_table(
                results, styles, group_version_conflicts(results)))
        else:
            story.append(Paragraph(
                "No findings were recorded for this scan.", styles["body"]
            ))

        doc.build(story)
        return buf.getvalue()

    # --- JSON ------------------------------------------------------------
    def generate_json(self, scan) -> bytes:
        # Prioritised order (tier: KEV+confirmed → CVE-linked exploit →
        # severity), same as the PDF.
        results = sorted(scan.results, key=lambda r: r.priority_key)
        reported, collapsed, unique = finding_totals(results)
        conflicts = group_version_conflicts(results)

        payload = {
            "scan_id": scan.scan_id,
            "target": scan.target,
            "status": scan.status,
            "selected_modules": scan.selected_modules or [],
            "start_time": scan.start_time.isoformat() if scan.start_time else None,
            "end_time": scan.end_time.isoformat() if scan.end_time else None,
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
            # Three honest counts (reported >= collapsed >= unique). "raw" is kept
            # as an alias of the post-collapse count for backward compatibility.
            "finding_counts": {
                "reported": reported, "collapsed": collapsed,
                "unique": unique, "raw": collapsed,
            },
            "ordering": "priority tiers: (1) CISA KEV and confirmed, "
                        "(2) a public exploit targets the CVE, (3) severity. "
                        "Within a tier: confirmed before presumed, then severity, "
                        "then CVSS, then EPSS. Severity is tool-reported/heuristic, "
                        "not CVSS-derived.",
            "results": [
                {
                    "id": r.id,
                    "tool_name": r.tool_name,
                    "host": r.host,
                    "port": r.port,
                    "service": r.service,
                    # Credentials masked for shareable output (see redaction.py).
                    "finding": r.finding_redacted,
                    "severity": r.severity,
                    "priority_tier": r.priority_tier,
                    "priority_tier_rank": r.priority_tier_rank,
                    "evidence": r.evidence or "confirmed",
                    "show_evidence": r.show_evidence,
                    "cvss_score": r.cvss_score,
                    "epss_score": r.epss_score,
                    "cve_id": r.cve_id,
                    "finding_class": r.finding_class,
                    "exploitation_context": r.exploitation_context,
                    "kev_listed": r.kev_listed,
                    "kev": r.kev_data,
                    "instance_count": r.instance_count,
                    "has_cve_exploit": r.has_cve_exploit,
                    "dup_group": r.dup_group,
                    "corroborated_by": r.corroborating_tools,
                    # Distinct software banners in this identity cluster, when the
                    # tools disagree on version (else omitted).
                    "version_conflict": conflicts.get(r.dup_group),
                    "loc_group": r.loc_group,
                    "colocated_with": r.colocated_tools,
                    "raw_output": _cap(r.raw_output, 2000),
                    "exploits": [
                        {
                            "title": c.exploit_title,
                            "edb_id": c.exploit_id,
                            "path": c.exploit_path,
                            "match_type": c.match_type or "product",
                            "synopsis": c.synopsis,
                        }
                        for c in r.correlations
                    ],
                }
                for r in results
            ],
        }
        return json.dumps(payload, indent=2).encode("utf-8")

    # --- Internals -------------------------------------------------------
    @staticmethod
    def _priority_note(styles):
        """Prose explaining the ordering rule + severity provenance, so a reader
        knows exactly why findings sit where they do and what 'severity' means.
        """
        text = (
            "<b>How findings are ordered.</b> In three tiers, most urgent first: "
            "<b>(1)</b> listed in CISA KEV <i>and</i> confirmed on this target "
            "(exploited in the wild, and a tool verified the target is affected); "
            "<b>(2)</b> a public exploit targets the finding's specific CVE "
            "(readily weaponisable); then <b>(3)</b> severity. A KEV listing that "
            "is only <i>presumed</i> here (inferred from a version banner) drops "
            "out of the top tier but keeps its KEV flag — KEV means 'exploited "
            "somewhere', not 'this host is vulnerable'. An exploit matched only by "
            "a software banner (not a CVE) does not elevate a finding. "
            "<b>Within each tier:</b> confirmed before presumed, then severity, "
            "then CVSS, then EPSS. Severity is a qualitative rating from each tool "
            "(ZAP risk, Nuclei template severity) or service heuristics (Nmap) — "
            "it is <b>not</b> calculated from CVSS scores."
        )
        return Paragraph(text, styles["small"])

    @staticmethod
    def _styles():
        base = getSampleStyleSheet()
        return {
            "title": ParagraphStyle("Title", parent=base["Title"], fontSize=20, spaceAfter=10),
            "h2":    ParagraphStyle("H2", parent=base["Heading2"], fontSize=14, spaceAfter=6),
            "body":  ParagraphStyle("Body", parent=base["BodyText"], fontSize=9, leading=11),
            "small": ParagraphStyle("Small", parent=base["BodyText"], fontSize=8, textColor=colors.grey),
            "cell":  ParagraphStyle("Cell", parent=base["BodyText"], fontSize=8, leading=10),
        }

    @staticmethod
    def _results_table(results, styles, version_conflicts=None):
        version_conflicts = version_conflicts or {}
        header = ["Tool", "Severity", "Host:Port", "Finding", "CVE / Exploit"]
        rows = [header]
        severity_cell_styles = []

        for idx, r in enumerate(results, start=1):
            host_port = r.host or ""
            if r.port:
                host_port = f"{host_port}:{r.port}"
            if r.service:
                host_port = f"{host_port}  ({r.service})"

            # Header line: CVE if known (linked to NVD), else the product/version banner if any.
            bits = []
            if r.cve_id:
                cve_upper = r.cve_id.upper()
                bits.append(
                    f'<b>CVE:</b> <link href="https://nvd.nist.gov/vuln/detail/{cve_upper}" '
                    f'color="#0d6efd">{cve_upper}</link>'
                )
            elif r.product and r.version:
                bits.append(f"<b>{_esc(r.product)} {_esc(r.version)}</b>")

            # CISA KEV flag — actively exploited in the wild (independent of
            # whether a local PoC exists). Rendered in red as a priority signal.
            if r.kev_listed:
                kd = r.kev_data or {}
                added = kd.get("dateAdded")
                when = f" since {_esc(added)}" if added else ""
                rw = " &middot; ransomware" if r.kev_ransomware else ""
                bits.append(
                    f'<b><font color="#dc3545">CISA KEV: actively '
                    f'exploited in the wild{when}{rw}</font></b>'
                )

            # Evidence strength + optional scores (ranking tie-breakers). Shown
            # only where it carries signal (a vulnerability-class finding), not on
            # recon rows (open ports, fingerprints, discovered paths).
            if r.show_evidence:
                if r.is_presumed:
                    bits.append(
                        '<font color="#b8860b" size="7">presumed — inferred from a '
                        'version/banner, not confirmed by response</font>'
                    )
                else:
                    bits.append(
                        '<font color="#198754" size="7">confirmed — observed '
                        'directly by the tool</font>'
                    )
            score_bits = []
            if r.cvss_score:
                score_bits.append(f"CVSS {r.cvss_score}")
            if r.epss_score is not None:
                score_bits.append(f"EPSS {r.epss_score:.2f}")
            if score_bits:
                bits.append(
                    f'<font color="#6c757d" size="7">{" &middot; ".join(score_bits)}</font>'
                )

            if r.correlations:
                bits.append(f"<b>{len(r.correlations)} public exploit(s):</b>")
                for c in r.correlations:
                    title = _esc(c.exploit_title or "(untitled)")
                    if c.exploit_id:
                        # Linked title — readers can click straight through to the
                        # rendered Exploit-DB page from the PDF.
                        title_html = (
                            f'<link href="https://www.exploit-db.com/exploits/{c.exploit_id}" '
                            f'color="#0d6efd">{title}</link> '
                            f'<font color="#6c757d" size="7">[EDB-{c.exploit_id}]</font>'
                        )
                    else:
                        title_html = title
                    # Mark how the exploit was linked: a CVE match targets this
                    # exact flaw; a banner match only shares the software name and
                    # does not elevate ranking (see priority_key).
                    if (c.match_type or "product") == "cve":
                        tag = '<font size="7" color="#198754"> [CVE match]</font>'
                    else:
                        tag = '<font size="7" color="#b8860b"> [banner match — not ranked]</font>'
                    path = _esc(c.exploit_path or "(no path)")
                    bits.append(f"• {title_html}{tag}<br/>&nbsp;&nbsp;<font size=\"7\" color=\"#6c757d\">{path}</font>")
                    if c.synopsis:
                        bits.append(
                            f'&nbsp;&nbsp;<font size="7" color="#0d6efd">{_esc(c.synopsis)}</font>'
                        )
            else:
                ctx = r.exploitation_context
                if ctx:
                    bits.append(f'<i><font color="#6c757d">{_esc(ctx)}</font></i>')

            exploit_cell = "<br/>".join(bits) if bits else "&mdash;"

            # Finding cell — credentials masked, then cross-tool correlation
            # notes. Identity ("also detected by") and co-location ("same path")
            # are shown separately so a shared path never reads as corroboration.
            finding_html = _esc((r.finding_redacted or "")[:600])
            if r.is_corroborated:
                finding_html += (
                    f'<br/><font size="7" color="#6c757d">&#9656; also detected by '
                    f'{_esc(", ".join(r.corroborating_tools))}</font>'
                )
                # If the corroborating tools disagree on the version, show both
                # banners rather than letting the version-agnostic merge hide it.
                conflict = version_conflicts.get(r.dup_group)
                if conflict:
                    finding_html += (
                        f'<br/><font size="7" color="#b8860b">&#9656; versions '
                        f'differ across tools: {_esc(" / ".join(conflict))}</font>'
                    )
            if r.is_colocated:
                finding_html += (
                    f'<br/><font size="7" color="#9aa5b5">&#9656; same path also '
                    f'mapped by {_esc(", ".join(r.colocated_tools))}</font>'
                )

            rows.append([
                Paragraph(_esc(r.tool_name or ""), styles["cell"]),
                Paragraph(_esc(r.severity or "Info"), styles["cell"]),
                Paragraph(_esc(host_port), styles["cell"]),
                Paragraph(finding_html, styles["cell"]),
                Paragraph(exploit_cell, styles["cell"]),   # already escaped + intentional markup
            ])
            sev_color = SEVERITY_COLORS.get(r.severity)
            if sev_color:
                severity_cell_styles.append((idx, sev_color))

        table = Table(
            rows,
            colWidths=[18*mm, 18*mm, 38*mm, 60*mm, 48*mm],
            repeatRows=1,
            # A finding can carry up to MAX_HITS_PER_RESULT exploits (each with a
            # synopsis + path), making a single cell taller than a page. Allow
            # ReportLab to split such a row across pages instead of raising
            # LayoutError.
            splitInRow=1,
        )

        style = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#212529")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, 0), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#dee2e6")),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                [colors.white, colors.HexColor("#f8f9fa")]),
        ])
        for row_idx, color in severity_cell_styles:
            style.add("BACKGROUND", (1, row_idx), (1, row_idx), color)
            if color in (SEVERITY_COLORS["Critical"],
                         SEVERITY_COLORS["High"],
                         SEVERITY_COLORS["Low"]):
                style.add("TEXTCOLOR", (1, row_idx), (1, row_idx), colors.white)
        table.setStyle(style)
        return table
