"""Initial VulnSight SQLite schema.

Revision ID: 0001_initial_schema
Revises:
"""
from alembic import op
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from app.db.base import Base  # noqa: E402
from app.models import entities  # noqa: F401,E402

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Preserve the historical Phase 1 baseline even as later models are added.
    tables = [table for table in Base.metadata.sorted_tables if table.name != "audit_logs"]
    Base.metadata.create_all(bind=op.get_bind(), tables=tables)


def downgrade() -> None:
    tables = [table for table in reversed(Base.metadata.sorted_tables) if table.name != "audit_logs"]
    Base.metadata.drop_all(bind=op.get_bind(), tables=tables)
