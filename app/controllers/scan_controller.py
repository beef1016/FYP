"""ScanController (spec section 6 / 12).

Routes are now keyed by scan_id (UUID) per spec section 12.
"""
import re
from urllib.parse import urlparse

from flask import Blueprint, jsonify, request

from app.engine.registry import SCANNER_REGISTRY


# Allowed URL schemes for the URL-input convenience parser. Anything else
# falls through to the bare-host regex.
_ALLOWED_SCHEMES = {"http", "https"}
_DEFAULT_PORT_FOR_SCHEME = {"http": 80, "https": 443}


class ScanController:
    def __init__(self, orchestrator, db_manager):
        self.orchestrator = orchestrator
        self.db = db_manager
        self.bp = Blueprint("scan", __name__, url_prefix="/api/scan")
        self.bp.add_url_rule("/start", "start", self.start_scan, methods=["POST"])
        self.bp.add_url_rule("/<scan_id>/status", "status", self.get_scan_status, methods=["GET"])
        self.bp.add_url_rule("/<scan_id>/results", "results", self.get_scan_results, methods=["GET"])

    def register(self, app):
        app.register_blueprint(self.bp)

    # --- helpers ---------------------------------------------------------
    @staticmethod
    def _is_valid_target(target):
        """Strict IPv4 or domain. ONLY guard against shell injection — do not relax."""
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        domain_pattern = re.compile(
            r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        )
        return bool(ip_pattern.match(target) or domain_pattern.match(target))

    @classmethod
    def _parse_target_input(cls, raw):
        """Accept either a bare host (`example.com`, `192.168.1.50`) or a URL
        (`https://example.com:8443/admin`). Return `(host, port, scheme)` where
        port and scheme may be None for a bare host.

        Returns (None, None, None) on invalid input — the caller turns that
        into a 400. The returned `host` is always re-validated through
        `_is_valid_target` before being trusted in any subprocess argv.
        """
        raw = (raw or "").strip()
        if not raw:
            return (None, None, None)

        # If it looks URL-shaped, parse it; otherwise treat as bare host.
        if "://" in raw:
            try:
                parsed = urlparse(raw)
            except ValueError:
                return (None, None, None)
            scheme = (parsed.scheme or "").lower()
            if scheme not in _ALLOWED_SCHEMES:
                return (None, None, None)
            host = parsed.hostname            # urllib drops user:pass, brackets, port
            port = parsed.port or _DEFAULT_PORT_FOR_SCHEME[scheme]
        else:
            host, port, scheme = raw, None, None

        if not host or not cls._is_valid_target(host):
            return (None, None, None)
        return (host, port, scheme)

    @staticmethod
    def _parse_tool_selection(raw):
        if raw is None or raw == "":
            return list(SCANNER_REGISTRY.keys())
        if isinstance(raw, str):
            names = [s.strip() for s in raw.split(",") if s.strip()]
        else:
            names = [s.strip() for s in raw if s and s.strip()]
        sel = set(names)
        return [n for n in SCANNER_REGISTRY if n in sel]

    # --- handlers --------------------------------------------------------
    def start_scan(self):
        raw_target = request.values.get("ip") or request.values.get("target")
        if not raw_target:
            return jsonify({"error": "No target provided"}), 400

        host, hint_port, hint_scheme = self._parse_target_input(raw_target)
        if not host:
            print(f"[SECURITY WARNING] Blocked invalid scan target: {raw_target}")
            return jsonify({
                "error": "Invalid format. Must be an IPv4 address, domain, or http(s):// URL."
            }), 400

        raw_tools = (
            request.values.getlist("tools")
            or request.values.getlist("modules")
            or request.values.get("tools")
            or request.values.get("modules")
        )
        selected_tools = self._parse_tool_selection(raw_tools)
        if not selected_tools:
            return jsonify({"error": "No valid tools selected."}), 400

        in_flight = self.db.has_inflight_scan_for_target(host)
        if in_flight:
            return jsonify({
                "error": f"A scan for {host} is already running (status: {in_flight.status})",
                "scan_id": in_flight.scan_id,
            }), 409

        scan = self.orchestrator.create_scan_job(
            host, selected_tools,
            target_port=hint_port, target_scheme=hint_scheme,
        )
        return jsonify({
            "message": f"Scan initiated for {host}",
            "scan_id": scan.scan_id,
            "tools": selected_tools,
            "target_port": hint_port,
            "target_scheme": hint_scheme,
        }), 202

    def get_scan_status(self, scan_id):
        job = self.db.get_scan(scan_id)
        if not job:
            return jsonify({"error": "Scan not found"}), 404
        progress = self.orchestrator.progress_for(scan_id)
        return jsonify({
            "scan_id": job.scan_id,
            "target": job.target,
            "current_status": job.status,
            "step": progress.get("step"),
            "total": progress.get("total"),
            "current_tool": progress.get("current_tool"),
        })

    def get_scan_results(self, scan_id):
        job = self.db.get_scan(scan_id)
        if not job:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify({
            "scan_id": job.scan_id,
            "target": job.target,
            "status": job.status,
            "selected_modules": job.selected_modules or [],
            "start_time": job.start_time.isoformat() if job.start_time else None,
            "end_time": job.end_time.isoformat() if job.end_time else None,
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
                    "has_public_exploit": r.has_public_exploit,
                    "exploits": [
                        {
                            "title": c.exploit_title,
                            "edb_id": c.exploit_id,
                            "path": c.exploit_path,
                        }
                        for c in r.correlations
                    ],
                }
                for r in job.results
            ],
        })
