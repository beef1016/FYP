import io
import re

from flask import Blueprint, abort, send_file

from app.extensions import auth


class ReportController:
    """Per-scan PDF + JSON downloads (spec section 12).

    Report endpoints are auth-gated (chapter 6.4 control AUTH-1) because
    scan UUIDs leak in browser history, server logs, and screenshots. Even
    with the UUID's 128-bit entropy, a leaked ID would otherwise hand the
    entire scan report to anyone who saw it.
    """

    def __init__(self, db_manager, report_generator):
        self.db = db_manager
        self.report_gen = report_generator
        self.bp = Blueprint("report", __name__, url_prefix="/api/scan")
        self.bp.add_url_rule(
            "/<scan_id>/report/pdf", "pdf",
            auth.login_required(self.download_pdf),
            methods=["GET"],
        )
        self.bp.add_url_rule(
            "/<scan_id>/report/json", "json",
            auth.login_required(self.download_json),
            methods=["GET"],
        )

    def register(self, app):
        app.register_blueprint(self.bp)

    def _safe_filename(self, scan):
        return re.sub(r"[^A-Za-z0-9._-]+", "_", scan.target)

    def download_pdf(self, scan_id):
        scan = self.db.get_scan(scan_id)
        if not scan:
            abort(404)
        filename = f"exploitlink-{self._safe_filename(scan)}-{scan_id[:8]}.pdf"
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
        filename = f"exploitlink-{self._safe_filename(scan)}-{scan_id[:8]}.json"
        json_bytes = self.report_gen.generate_json(scan)
        return send_file(
            io.BytesIO(json_bytes),
            mimetype="application/json",
            as_attachment=True,
            download_name=filename,
        )
