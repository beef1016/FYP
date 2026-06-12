import uuid
from datetime import datetime, timezone

from app.extensions import db


class ScanStatus:
    """Spec section 11: PENDING / RUNNING / COMPLETED / FAILED."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

    TERMINAL = (COMPLETED, FAILED)
    ALL = (PENDING, RUNNING, COMPLETED, FAILED)


def _new_scan_id() -> str:
    return str(uuid.uuid4())


class ScanJob(db.Model):
    """A single scan invocation (spec section 11: scan_jobs)."""
    __tablename__ = "scan_jobs"

    scan_id = db.Column(db.String(36), primary_key=True, default=_new_scan_id)
    target = db.Column(db.String(255), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default=ScanStatus.PENDING)
    start_time = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    end_time = db.Column(db.DateTime, nullable=True)

    # Stored as JSON so the dashboard can re-display the user's tool choices.
    selected_modules = db.Column(db.JSON, nullable=False, default=list)

    # Optional URL hint — populated when the user types a URL like
    # `https://example.com:8443/admin` rather than a bare host. Persisted so the
    # orchestrator can force this port into the http_targets list for WhatWeb /
    # Gobuster even when Nmap wasn't selected or didn't reach this port.
    target_port = db.Column(db.Integer, nullable=True)
    target_scheme = db.Column(db.String(8), nullable=True)   # "http" or "https"

    results = db.relationship(
        "ScanResult",
        backref="scan",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="ScanResult.id",
    )

    def __repr__(self) -> str:
        return f"<ScanJob {self.scan_id[:8]} target={self.target} status={self.status}>"
