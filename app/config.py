"""Per-environment Flask config classes (FYP spec section 18: Factory pattern).

All security-sensitive values are sourced from environment variables. Defaults
are chosen for **safe production posture**, not developer convenience:

  - Private/RFC1918/loopback/metadata IP scanning is BLOCKED by default.
    Set EXPLOITLINK_ALLOW_PRIVATE_TARGETS=true to enable the FYP Metasploitable
    demo (the docker-compose.yml does this for the lab environment).
  - Authentication is REQUIRED by default. Set EXPLOITLINK_AUTH_PASSWORD before
    starting the app or it refuses to boot (see run.py).
  - Rate limiting is ENABLED by default at 200/minute total, 10/minute on
    /api/scan/start.
  - Strict CSP via Flask-Talisman is ENABLED.
"""
import os
import secrets

# Project root (the directory containing the `app/` package and `run.py`)
_BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
_INSTANCE_DIR = os.path.join(_BASE_DIR, "instance")


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


class BaseConfig:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    INSTANCE_DIR = _INSTANCE_DIR

    # --- Security: authentication ---------------------------------------
    # Single-user HTTP Basic Auth. Username defaults to "admin"; password is
    # mandatory in production (run.py refuses to start without it).
    EXPLOITLINK_AUTH_USER = os.environ.get("EXPLOITLINK_AUTH_USER", "admin")
    EXPLOITLINK_AUTH_PASSWORD = os.environ.get("EXPLOITLINK_AUTH_PASSWORD")

    # --- Security: target validation ------------------------------------
    # Whether _is_valid_target permits private RFC1918, loopback,
    # link-local, and known cloud-metadata IPs. Default OFF (production-safe);
    # FYP Metasploitable demo flips this on via docker-compose env var.
    EXPLOITLINK_ALLOW_PRIVATE_TARGETS = _env_bool("EXPLOITLINK_ALLOW_PRIVATE_TARGETS")

    # --- Security: rate limiting ----------------------------------------
    RATELIMIT_DEFAULT = "200 per minute"
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_STORAGE_URI = "memory://"   # per-process; swap for redis:// in HA setup

    # --- Security: Flask session / CSRF token --------------------------
    # Used only by Talisman session-cookie hardening defaults. We don't use
    # Flask sessions for app state, but Flask itself signs the cookie.
    SECRET_KEY = os.environ.get("EXPLOITLINK_SECRET_KEY") or secrets.token_hex(32)


class DevConfig(BaseConfig):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(_INSTANCE_DIR, "scans.db")


class TestConfig(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    # Disable rate limiting in tests so test suite doesn't hit limits
    RATELIMIT_ENABLED = False


class ProdConfig(BaseConfig):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(_INSTANCE_DIR, "scans.db")


CONFIG_BY_NAME = {
    "dev": DevConfig,
    "test": TestConfig,
    "prod": ProdConfig,
}
