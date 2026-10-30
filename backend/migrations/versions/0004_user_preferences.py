"""Persist per-user interface and report preferences.

Revision ID: 0004_user_preferences
Revises: 0003_scan_metadata
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_user_preferences"
down_revision = "0003_scan_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("users")}
    if "preferences" not in columns:
        op.add_column(
            "users",
            sa.Column("preferences", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        )


def downgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("users")}
    if "preferences" in columns:
        op.drop_column("users", "preferences")
