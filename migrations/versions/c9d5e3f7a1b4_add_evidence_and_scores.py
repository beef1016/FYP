"""add evidence + cvss/epss score fields to scan_results

  * evidence    — "confirmed" vs "presumed" (version-inferred) finding strength
  * cvss_score  — CVSS base score captured from Nuclei CVE templates
  * epss_score  — EPSS probability snapshot from the Nuclei template feed

All nullable; used for evidence-aware ranking and as free tie-breakers.

Revision ID: c9d5e3f7a1b4
Revises: b8c4d2e6f0a3
Create Date: 2026-11-23
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "c9d5e3f7a1b4"
down_revision = "b8c4d2e6f0a3"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("scan_results", schema=None) as batch_op:
        batch_op.add_column(sa.Column("evidence", sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column("cvss_score", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("epss_score", sa.Float(), nullable=True))


def downgrade():
    with op.batch_alter_table("scan_results", schema=None) as batch_op:
        batch_op.drop_column("epss_score")
        batch_op.drop_column("cvss_score")
        batch_op.drop_column("evidence")
