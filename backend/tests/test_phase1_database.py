from sqlalchemy import inspect, text

from app.db.base import Base
from app.db.session import make_engine
from app.models import entities  # noqa: F401


def test_initial_sqlite_schema_and_integrity():
    engine = make_engine("sqlite://", test_mode=True)
    try:
        Base.metadata.create_all(engine)
        inspector = inspect(engine)
        names = set(inspector.get_table_names())
        assert {"users", "auth_sessions", "targets", "scans", "scan_events", "findings", "finding_status_history", "reports"} <= names
        assert "ix_scans_owner_started" in {item["name"] for item in inspector.get_indexes("scans")}
        assert "uq_finding_scan_fingerprint" in {item["name"] for item in inspector.get_unique_constraints("findings")}
        with engine.connect() as connection:
            assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
            assert connection.execute(text("SELECT 1")).scalar_one() == 1
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
