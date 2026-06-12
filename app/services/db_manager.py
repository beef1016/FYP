"""DatabaseManager (spec section 6): thin façade around SQLAlchemy.

Now scan-centric (no more Target entity). Centralises persistence so
controllers and the orchestrator never reach into ORM internals directly.
"""
from app.models import ScanJob, ScanStatus


class DatabaseManager:
    def __init__(self, db):
        self.db = db

    # --- Generic session helpers -----------------------------------------
    @property
    def session(self):
        return self.db.session

    def add(self, obj):
        self.db.session.add(obj)
        return obj

    def commit(self):
        self.db.session.commit()

    def rollback(self):
        self.db.session.rollback()

    def get(self, model_cls, pk):
        return self.db.session.get(model_cls, pk)

    # --- ScanJob queries -------------------------------------------------
    def all_scans(self):
        return ScanJob.query.order_by(ScanJob.start_time.desc()).all()

    def get_scan(self, scan_id: str):
        return self.db.session.get(ScanJob, scan_id)

    def latest_scan_for_target(self, target: str):
        return (
            ScanJob.query.filter_by(target=target)
            .order_by(ScanJob.start_time.desc())
            .first()
        )

    def has_inflight_scan_for_target(self, target: str):
        return ScanJob.query.filter(
            ScanJob.target == target,
            ~ScanJob.status.in_(ScanStatus.TERMINAL),
        ).first()
