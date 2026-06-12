import io
import re

from flask import Blueprint, abort, send_file


class ReportController:
    """Per-scan PDF + JSON downloads (spec section 12)."""

    def __init__(self, db_manager, report_generator):
        self.db = db_manager
        self.report_gen = report_generator
        self.bp = Blueprint("report", __name__, url_prefix="/api/scan")
        self.bp.add_url_rule(
            "/<scan_id>/report/pdf", "pdf", self.download_pdf, methods=["GET"]
        )
        self.bp.add_url_rule(
            "/<scan_id>/report/json", "json", self.download_json, methods=["GET"]
        )

    def register(self, app):
        app.register_blueprint(self.bp)

    def _safe_filename(self, scan):
        return re.sub(r"[^A-Za-z0-9._-]+", "_", scan.target)

    def download_pdf(self, scan_id):
        scan = self.db.get_scan(scan_id)
        if not scan:
            abort(404)
        filename = f"vulnflow-{self._safe_filename(scan)}-{scan_id[:8]}.pdf"
        pdf_bytes = self.report_gen.generate_pdf(scan)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
        )

    def download_json(self, scan_id):
        scan = self.db.get_scan(scan_id)
        if not scan:
            abort(404)
        filename = f"vulnflow-{self._safe_filename(scan)}-{scan_id[:8]}.json"
        json_bytes = self.report_gen.generate_json(scan)
        return send_file(
            io.BytesIO(json_bytes),
            mimetype="application/json",
            as_attachment=True,
            download_name=filename,
        )
