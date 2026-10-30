"""Persist optional scan names and descriptions.

Revision ID: 0003_scan_metadata
Revises: 0002_audit_log
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_scan_metadata"
down_revision = "0002_audit_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The initial schema is also used by fresh installs; keep this revision safe both
    # for databases created before these columns existed and for already-current schemas.
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("scans")}
    if "name" not in columns:
        op.add_column("scans", sa.Column("name", sa.String(length=120), nullable=False, server_default=""))
    if "description" not in columns:
        op.add_column("scans", sa.Column("description", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("scans")}
    if "description" in columns:
        op.drop_column("scans", "description")
    if "name" in columns:
        op.drop_column("scans", "name")
