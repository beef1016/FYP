"""Application entry point.

The Flask app instance is built by the factory in `app/__init__.py`. Running
this file (or pointing `flask run` at it) starts the dev server.

Environment-driven settings (all optional except EXPLOITLINK_AUTH_PASSWORD):

  EXPLOITLINK_AUTH_PASSWORD  — REQUIRED. App refuses to start without it.
                            Single-user HTTP Basic Auth credential.
  EXPLOITLINK_AUTH_USER      — Defaults to "admin".
  EXPLOITLINK_ALLOW_PRIVATE_TARGETS
                          — "true" to permit scanning RFC1918 / loopback / etc.
                            Off by default (production-safe). Enable for the
                            FYP Metasploitable lab demo.
  FLASK_HOST              — Bind address. Defaults to 127.0.0.1.
                            Set to 0.0.0.0 only if you accept the network
                            exposure (and have HTTPS in front of it).
  FLASK_PORT              — Port. Defaults to 5000.
  FLASK_DEBUG             — "true" enables Werkzeug debug. Defaults to OFF.
                            NEVER enable on a host reachable from outside
                            127.0.0.1 — the debug console is a known RCE.
"""
import os
import sys

from app import create_app


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


# Validate critical security config BEFORE building the app
if not os.environ.get("EXPLOITLINK_AUTH_PASSWORD"):
    sys.stderr.write(
        "FATAL: EXPLOITLINK_AUTH_PASSWORD is not set.\n"
        "       Single-user HTTP Basic Auth password is mandatory.\n"
        "       Set it before starting the app, e.g.:\n"
        "         export EXPLOITLINK_AUTH_PASSWORD='your-strong-password'\n"
        "       In Docker, set it in docker-compose.yml under `environment:`.\n"
    )
    sys.exit(1)


app = create_app()


if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = _env_bool("FLASK_DEBUG", default=False)

    # Loudly warn if a dangerous combination is requested
    if debug and host != "127.0.0.1":
        sys.stderr.write(
            "WARNING: FLASK_DEBUG=true with FLASK_HOST!=127.0.0.1 exposes\n"
            "         the Werkzeug debug console. This is an RCE vector.\n"
            "         Continuing because you explicitly asked for it.\n"
        )

    app.run(host=host, port=port, debug=debug)
