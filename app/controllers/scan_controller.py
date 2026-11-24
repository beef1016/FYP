"""ScanController (FYP1 spec §6 / §12).

Routes are keyed by scan_id (UUID) per spec §12.

Security controls applied here (chapter 6.4):
- HTTP Basic Auth required on every route (`@auth.login_required`)
- /api/scan/start rate-limited to 10/minute per source IP
- Target validation rejects shell metacharacters AND
  RFC1918 / loopback / link-local / multicast / cloud-metadata IPs
  (unless EXPLOITLINK_ALLOW_PRIVATE_TARGETS is set, for the lab demo)
"""
import ipaddress
import re
import socket
from urllib.parse import urlparse

from flask import Blueprint, current_app, jsonify, request

from app.engine.registry import SCANNER_REGISTRY
from app.extensions import auth, limiter
from app.services.finding_dedup import finding_totals, group_version_conflicts


# Allowed URL schemes for the URL-input convenience parser.
_ALLOWED_SCHEMES = {"http", "https"}
_DEFAULT_PORT_FOR_SCHEME = {"http": 80, "https": 443}

# Cloud metadata hostnames — block by domain, not just IP, because some
# resolve to internal CIDRs that aren't caught by the ip_address checks.
_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
}


class ScanController:
    def __init__(self, orchestrator, db_manager):
        self.orchestrator = orchestrator
        self.db = db_manager
        self.bp = Blueprint("scan", __name__, url_prefix="/api/scan")
        self.bp.add_url_rule(
            "/start", "start",
            limiter.limit("10 per minute")(auth.login_required(self.start_scan)),
            methods=["POST"],
        )
        self.bp.add_url_rule(
            "/<scan_id>/status", "status",
            auth.login_required(self.get_scan_status),
            methods=["GET"],
        )
        self.bp.add_url_rule(
            "/<scan_id>/results", "results",
            auth.login_required(self.get_scan_results),
            methods=["GET"],
        )
        self.bp.add_url_rule(
            "/<scan_id>", "delete",
            auth.login_required(self.delete_scan),
            methods=["DELETE"],
        )

    def register(self, app):
        app.register_blueprint(self.bp)

    def delete_scan(self, scan_id):
        """Delete a scan and its results/correlations (cascade). AUTH-1 protected."""
        if self.db.delete_scan(scan_id):
            return jsonify({"deleted": scan_id}), 200
        return jsonify({"error": "Scan not found"}), 404

    # --- helpers ---------------------------------------------------------
    @staticmethod
    def _is_valid_target_shape(target: str) -> bool:
        """Layer 1: strict regex for shell-injection prevention."""
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        domain_pattern = re.compile(
            r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        )
        return bool(ip_pattern.match(target) or domain_pattern.match(target))

    @staticmethod
    def _is_dangerous_ip(host: str) -> bool:
        """Layer 2: SSRF guard. Returns True if the host resolves to a
        private/loopback/link-local/multicast/metadata address that the
        scanner should NOT touch unless the operator explicitly opts in.
        """
        try:
            ip = ipaddress.ip_address(host)
            return (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
        except ValueError:
            pass

        # Domain — block by name first
        lower = host.lower()
        if lower in _METADATA_HOSTS or lower.endswith(".internal"):
            return True

        # Then attempt resolution and check the resulting IP. Failure to
        # resolve is NOT treated as dangerous (Nmap will surface the error).
        try:
            resolved = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved)
            return (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
        except (socket.gaierror, ValueError):
            return False

    @classmethod
    def _is_valid_target(cls, target):
        """Combined validator used by tests + by _parse_target_input."""
        if not cls._is_valid_target_shape(target):
            return False
        if current_app.config.get("EXPLOITLINK_ALLOW_PRIVATE_TARGETS"):
            return True
        if cls._is_dangerous_ip(target):
            return False
        return True

    @classmethod
    def _parse_target_input(cls, raw):
        """Accept bare host or http(s):// URL. Returns (host, port, scheme)
        or (None, None, None) on invalid / dangerous input."""
        raw = (raw or "").strip()
        if not raw:
            return (None, None, None)

        if "://" in raw:
            try:
                parsed = urlparse(raw)
            except ValueError:
                return (None, None, None)
            scheme = (parsed.scheme or "").lower()
            if scheme not in _ALLOWED_SCHEMES:
                return (None, None, None)
            host = parsed.hostname
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
            print(f"[SECURITY WARNING] Blocked invalid/dangerous scan target: {raw_target}")
            return jsonify({
                "error": "Invalid or dangerous target. Must be a public IPv4, "
                         "domain, or http(s):// URL. Private/loopback/metadata "
                         "targets are blocked unless EXPLOITLINK_ALLOW_PRIVATE_TARGETS "
                         "is set."
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
        results = sorted(job.results, key=lambda r: r.priority_key)
        reported, collapsed, unique = finding_totals(results)
        conflicts = group_version_conflicts(results)
        return jsonify({
            "scan_id": job.scan_id,
            "target": job.target,
            "status": job.status,
            "selected_modules": job.selected_modules or [],
            "start_time": job.start_time.isoformat() if job.start_time else None,
            "end_time": job.end_time.isoformat() if job.end_time else None,
            "finding_counts": {
                "reported": reported, "collapsed": collapsed, "unique": unique,
            },
            "results": [
                {
                    "id": r.id,
                    "tool_name": r.tool_name,
                    "host": r.host,
                    "port": r.port,
                    "service": r.service,
                    "finding": r.finding_redacted,   # credentials masked
                    "severity": r.severity,
                    "priority_tier": r.priority_tier,
                    "priority_tier_rank": r.priority_tier_rank,
                    "evidence": r.evidence or "confirmed",
                    "show_evidence": r.show_evidence,
                    "cvss_score": r.cvss_score,
                    "epss_score": r.epss_score,
                    "cve_id": r.cve_id,
                    "has_public_exploit": r.has_public_exploit,
                    "has_cve_exploit": r.has_cve_exploit,
                    "instance_count": r.instance_count,
                    "kev_listed": r.kev_listed,
                    "kev": r.kev_data,
                    "dup_group": r.dup_group,
                    "corroborated_by": r.corroborating_tools,
                    "version_conflict": conflicts.get(r.dup_group),
                    "loc_group": r.loc_group,
                    "colocated_with": r.colocated_tools,
                    "exploits": [
                        {
                            "title": c.exploit_title,
                            "edb_id": c.exploit_id,
                            "path": c.exploit_path,
                            "match_type": c.match_type or "product",
                        }
                        for c in r.correlations
                    ],
                }
                for r in results
            ],
        })
