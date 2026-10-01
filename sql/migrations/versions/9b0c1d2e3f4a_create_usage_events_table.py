"""create usage_events table

Revision ID: 9b0c1d2e3f4a
Revises: 8a9b0c1d2e3f
Create Date: 2026-10-01 18:00:00.000000

"""
from pathlib import Path
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9b0c1d2e3f4a'
down_revision: Union[str, Sequence[str], None] = '8a9b0c1d2e3f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA_FILE = Path(__file__).resolve().parents[2] / "schema" / "00015_usage_events.sql"


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(_SCHEMA_FILE.read_text())


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TABLE usage_events;")
