"""ReportGenerator (spec section 6) — per-scan PDF + JSON.

Inputs: a ScanJob row (with its ScanResults and their ExploitCorrelations).
Outputs: bytes for download.
"""
import io
import json
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)


SEVERITY_COLORS = {
    "Critical": colors.HexColor("#dc3545"),
    "High":     colors.HexColor("#fd7e14"),
    "Medium":   colors.HexColor("#ffc107"),
    "Low":      colors.HexColor("#20c997"),
    "Info":     colors.HexColor("#0dcaf0"),
}


class ReportGenerator:
    # --- PDF -------------------------------------------------------------
    def generate_pdf(self, scan) -> bytes:
        styles = self._styles()
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=15*mm, rightMargin=15*mm,
            topMargin=15*mm, bottomMargin=15*mm,
            title=f"VulnFlow Report — {scan.target}",
        )

        story = [
            Paragraph("VulnFlow Vulnerability Report", styles["title"]),
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
            Spacer(1, 6*mm),
        ]

        results = list(scan.results)
        counts = {sev: 0 for sev in SEVERITY_COLORS}
        for r in results:
            counts[r.severity] = counts.get(r.severity, 0) + 1
        summary_bits = [f"<b>{sev}</b>: {n}" for sev, n in counts.items() if n]
        summary_text = " &nbsp;|&nbsp; ".join(summary_bits) if summary_bits else "No findings."
        story.append(Paragraph(
            f"<b>Findings:</b> {len(results)} &nbsp; ({summary_text})", styles["body"]
        ))
        story.append(Spacer(1, 4*mm))

        if results:
            story.append(self._results_table(results, styles))
        else:
            story.append(Paragraph(
                "No findings were recorded for this scan.", styles["body"]
            ))

        doc.build(story)
        return buf.getvalue()

    # --- JSON ------------------------------------------------------------
    def generate_json(self, scan) -> bytes:
        payload = {
            "scan_id": scan.scan_id,
            "target": scan.target,
            "status": scan.status,
            "selected_modules": scan.selected_modules or [],
            "start_time": scan.start_time.isoformat() if scan.start_time else None,
            "end_time": scan.end_time.isoformat() if scan.end_time else None,
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
            "results": [
                {
                    "id": r.id,
                    "tool_name": r.tool_name,
                    "host": r.host,
                    "port": r.port,
                    "service": r.service,
                    "finding": r.finding,
                    "severity": r.severity,
                    "cve_id": r.cve_id,
                    "raw_output": r.raw_output,
                    "exploits": [
                        {
                            "title": c.exploit_title,
                            "edb_id": c.exploit_id,
                            "path": c.exploit_path,
                        }
                        for c in r.correlations
                    ],
                }
                for r in scan.results
            ],
        }
        return json.dumps(payload, indent=2).encode("utf-8")

    # --- Internals -------------------------------------------------------
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
    def _results_table(results, styles):
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
                bits.append(f"<b>{r.product} {r.version}</b>")

            if r.correlations:
                bits.append(f"<b>{len(r.correlations)} public exploit(s):</b>")
                for c in r.correlations[:3]:
                    title = c.exploit_title or "(untitled)"
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
                    path = c.exploit_path or "(no path)"
                    bits.append(f"• {title_html}<br/>&nbsp;&nbsp;<font size=\"7\" color=\"#6c757d\">{path}</font>")
                if len(r.correlations) > 3:
                    bits.append(f"… and {len(r.correlations) - 3} more")
            elif r.cve_id or (r.product and r.version):
                bits.append("No public exploit found.")

            exploit_cell = "<br/>".join(bits) if bits else "&mdash;"

            rows.append([
                Paragraph(r.tool_name or "", styles["cell"]),
                Paragraph(r.severity or "Info", styles["cell"]),
                Paragraph(host_port, styles["cell"]),
                Paragraph((r.finding or "")[:600], styles["cell"]),
                Paragraph(exploit_cell, styles["cell"]),
            ])
            sev_color = SEVERITY_COLORS.get(r.severity)
            if sev_color:
                severity_cell_styles.append((idx, sev_color))

        table = Table(
            rows,
            colWidths=[18*mm, 18*mm, 38*mm, 60*mm, 48*mm],
            repeatRows=1,
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
