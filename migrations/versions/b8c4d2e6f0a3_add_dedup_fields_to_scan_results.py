"""add cross-tool correlation fields to scan_results

Adds the keep-both-and-link correlation columns, as two INDEPENDENT groupings:
  * dup_group / dup_tools — identity cluster (same finding: CVE / banner)
  * loc_group / loc_tools — co-location cluster (same URL path across tools)

All are nullable; NULL means "no cross-tool overlap of that kind".

Revision ID: b8c4d2e6f0a3
Revises: a7b3c1d5e9f2
Create Date: 2026-11-23
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "b8c4d2e6f0a3"
down_revision = "a7b3c1d5e9f2"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("scan_results", schema=None) as batch_op:
        batch_op.add_column(sa.Column("dup_group", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("dup_tools", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("loc_group", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("loc_tools", sa.JSON(), nullable=True))
        batch_op.create_index(
            "ix_scan_results_dup_group", ["dup_group"], unique=False
        )
        batch_op.create_index(
            "ix_scan_results_loc_group", ["loc_group"], unique=False
        )


def downgrade():
    with op.batch_alter_table("scan_results", schema=None) as batch_op:
        batch_op.drop_index("ix_scan_results_loc_group")
        batch_op.drop_index("ix_scan_results_dup_group")
        batch_op.drop_column("loc_tools")
        batch_op.drop_column("loc_group")
        batch_op.drop_column("dup_tools")
        batch_op.drop_column("dup_group")
