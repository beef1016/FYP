"""add instance_count to scan_results and match_type to exploit_correlations

  * scan_results.instance_count       — how many raw tool hits this (collapsed)
                                         row represents; default 1. Lets reports
                                         show a tool-reported total alongside the
                                         post-collapse row count.
  * exploit_correlations.match_type    — "cve" (exploit targets this finding's
                                         CVE) vs "product" (banner-only match).
                                         Ranking treats a CVE match as real
                                         exploitability evidence; a banner match
                                         does not elevate a finding.

Revision ID: d1e6f4a8b2c5
Revises: c9d5e3f7a1b4
Create Date: 2026-11-24
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "d1e6f4a8b2c5"
down_revision = "c9d5e3f7a1b4"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("scan_results", schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            "instance_count", sa.Integer(), nullable=False, server_default="1"))

    with op.batch_alter_table("exploit_correlations", schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            "match_type", sa.String(length=10), nullable=True))


def downgrade():
    with op.batch_alter_table("exploit_correlations", schema=None) as batch_op:
        batch_op.drop_column("match_type")

    with op.batch_alter_table("scan_results", schema=None) as batch_op:
        batch_op.drop_column("instance_count")
