"""
Flask application factory.

Wires together the SQLAlchemy + Flask-Migrate + security extensions
(HTTPBasicAuth, Limiter, Talisman) and registers controller Blueprints.
Implements the Factory Pattern called out in FYP1 spec section 18.
"""
import os
from flask import Flask
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, migrate, auth, limiter
from .config import DevConfig


# --- Talisman policy ---------------------------------------------------------
# Strict Content-Security-Policy. We use inline scripts in the templates
# (Chart.js initialisation, the scan-form fetch logic, severity-sort handler)
# so 'unsafe-inline' is required for `script-src` until those are extracted
# into separate static .js files. Style-src needs 'unsafe-inline' for the
# Bootstrap CDN sheet + inline styles in templates.
_CSP = {
    "default-src": "'self'",
    "script-src": [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net",
    ],
    "style-src": [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net",
    ],
    "img-src": ["'self'", "data:"],
    "connect-src": "'self'",
    "frame-ancestors": "'none'",       # block click-jacking
    "form-action": "'self'",
    "base-uri": "'self'",
}


def create_app(config_class=DevConfig):
    app = Flask(__name__)
    app.config.from_object(config_class)

    os.makedirs(app.config["INSTANCE_DIR"], exist_ok=True)

    # --- Security: trust X-Forwarded-* headers from the reverse proxy ---
    # When Caddy (or nginx) terminates TLS in front of us, the actual client
    # protocol/host/IP comes through X-Forwarded-Proto / X-Forwarded-For /
    # X-Forwarded-Host. ProxyFix tells Flask to honour these so:
    #   - `request.scheme` returns "https" when the client used HTTPS
    #   - `request.remote_addr` returns the client IP, not Caddy's 127.0.0.1
    #     (matters for the per-IP rate limiter)
    # x_for=1 means we trust exactly one hop (the immediate reverse proxy).
    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1
    )

    # Register models against db.metadata BEFORE init_app so Flask-Migrate sees them
    from . import models  # noqa: F401

    db.init_app(app)
    migrate.init_app(app, db)

    # --- Security: Talisman (CSP + X-Frame-Options + X-Content-Type-Options)
    # force_https=False because Caddy in front already redirects :80 → :443
    # AND sets HSTS. Setting force_https=True here would cause a redirect
    # loop when Caddy proxies plain HTTP to us internally.
    Talisman(
        app,
        content_security_policy=_CSP,
        force_https=False,
        strict_transport_security=False,
        session_cookie_secure=False,
        frame_options="DENY",
        referrer_policy="no-referrer",
    )

    # --- Security: rate limiter (per-source-IP, in-memory) ----------
    limiter.init_app(app)

    # --- Security: HTTP Basic Auth ----------------------------------
    # Single hashed password stored in app config (loaded from env var by
    # config.py). Werkzeug's check_password_hash is constant-time.
    _expected_user = app.config["EXPLOITLINK_AUTH_USER"]
    _expected_password = app.config["EXPLOITLINK_AUTH_PASSWORD"]
    _expected_hash = (
        generate_password_hash(_expected_password) if _expected_password else None
    )

    @auth.verify_password
    def verify_password(username, password):
        if not _expected_hash or not username or not password:
            return None
        if username != _expected_user:
            return None
        if not check_password_hash(_expected_hash, password):
            return None
        return username

    # --- Wire services ----------------------------------------------------
    from .services.db_manager import DatabaseManager
    from .services.exploit_correlator import ExploitCorrelator
    from .services.report_generator import ReportGenerator
    from .engine.searchsploit_adapter import SearchsploitAdapter
    from .engine.orchestration import OrchestrationEngine

    db_manager = DatabaseManager(db)
    searchsploit = SearchsploitAdapter()
    correlator = ExploitCorrelator(searchsploit, db_manager)
    report_gen = ReportGenerator()
    orchestrator = OrchestrationEngine(app, db_manager, correlator)

    # --- Register controllers --------------------------------------------
    from .controllers.pages_controller import PagesController
    from .controllers.scan_controller import ScanController
    from .controllers.tool_controller import ToolController
    from .controllers.report_controller import ReportController

    PagesController(db_manager).register(app)
    ScanController(orchestrator, db_manager).register(app)
    ToolController().register(app)
    ReportController(db_manager, report_gen).register(app)

    return app
