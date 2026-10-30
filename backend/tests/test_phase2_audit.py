from sqlalchemy import inspect

from app.db.base import Base
from app.db.session import make_engine
from app.models import entities  # noqa: F401


def test_audit_log_is_persistent_and_indexed():
    engine = make_engine("sqlite://", test_mode=True)
    try:
        Base.metadata.create_all(engine)
        inspector = inspect(engine)
        assert "audit_logs" in inspector.get_table_names()
        assert "ix_audit_actor_time" in {item["name"] for item in inspector.get_indexes("audit_logs")}
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
