"""Add durable user-scoped audit logs.

Revision ID: 0002_audit_log
Revises: 0001_initial_schema
"""
from pathlib import Path
import sys
from typing import cast

from alembic import op
from sqlalchemy import Table

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from app.models.entities import AuditLog  # noqa: E402

revision = "0002_audit_log"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    cast(Table, AuditLog.__table__).create(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    cast(Table, AuditLog.__table__).drop(bind=op.get_bind(), checkfirst=True)
