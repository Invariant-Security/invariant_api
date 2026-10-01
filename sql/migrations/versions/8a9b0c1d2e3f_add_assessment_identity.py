"""add assessment identity columns

Revision ID: 8a9b0c1d2e3f
Revises: 7f8a9b0c1d2e
Create Date: 2026-10-01 18:00:00.000000

"""
from pathlib import Path
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8a9b0c1d2e3f'
down_revision: Union[str, Sequence[str], None] = '7f8a9b0c1d2e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA_FILE = Path(__file__).resolve().parents[2] / "schema" / "00014_assessment_identity.sql"


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(_SCHEMA_FILE.read_text())


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP INDEX assessment_summaries_public_id_idx; ALTER TABLE assessment_summaries DROP COLUMN public_id, DROP COLUMN assessed_ip, DROP COLUMN source;")
