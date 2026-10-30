"""Add reversible scan-history archival without deleting evidence.

Revision ID: 0005_scan_archival
Revises: 0004_user_preferences
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_scan_archival"
down_revision = "0004_user_preferences"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("scans")}
    if "archived_at" not in columns:
        op.add_column("scans", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("scans")}
    if "ix_scans_archived_at" not in indexes:
        op.create_index("ix_scans_archived_at", "scans", ["archived_at"])


def downgrade() -> None:
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("scans")}
    if "ix_scans_archived_at" in indexes:
        op.drop_index("ix_scans_archived_at", table_name="scans")
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("scans")}
    if "archived_at" in columns:
        op.drop_column("scans", "archived_at")
