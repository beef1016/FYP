from flask import Blueprint, render_template

# Order is meaningful — the Chart.js dataset slices in this order.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _severity_counts(scan):
    """Return {Critical: n, High: n, Medium: n, Low: n, Info: n} for a scan."""
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for r in scan.results:
        counts[r.severity] = counts.get(r.severity, 0) + 1
    return counts


class PagesController:
    """Serves the HTML pages: scan config, per-scan dashboard, and history.

    /dashboard lists ScanJobs (most recent first); each card has its own
    severity donut + findings table + per-scan PDF/JSON link.
    """

    def __init__(self, db_manager):
        self.db = db_manager
        self.bp = Blueprint("pages", __name__)
        self.bp.add_url_rule("/", "index", self.index)
        self.bp.add_url_rule("/dashboard", "dashboard", self.dashboard)
        self.bp.add_url_rule("/history", "history", self.history)

    def register(self, app):
        app.register_blueprint(self.bp)

    def index(self):
        return render_template("index.html")

    def dashboard(self):
        scans = self.db.all_scans()
        # Pre-compute per-scan severity counts so the template stays declarative.
        scan_views = [
            {
                "scan": scan,
                "counts": _severity_counts(scan),
                "total_findings": len(scan.results),
            }
            for scan in scans
        ]
        return render_template(
            "dashboard.html",
            scan_views=scan_views,
            severity_order=SEVERITY_ORDER,
        )

    def history(self):
        """Condensed list of past scans (spec section 12: GET /history)."""
        scans = self.db.all_scans()
        scan_rows = [
            {
                "scan": scan,
                "counts": _severity_counts(scan),
                "total_findings": len(scan.results),
            }
            for scan in scans
        ]
        return render_template(
            "history.html",
            scan_rows=scan_rows,
            severity_order=SEVERITY_ORDER,
        )
