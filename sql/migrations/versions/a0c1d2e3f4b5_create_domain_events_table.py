"""create domain_events table

Revision ID: a0c1d2e3f4b5
Revises: 9b0c1d2e3f4a
Create Date: 2026-10-01 18:00:00.000000

"""
from pathlib import Path
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a0c1d2e3f4b5'
down_revision: Union[str, Sequence[str], None] = '9b0c1d2e3f4a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA_FILE = Path(__file__).resolve().parents[2] / "schema" / "00016_domain_events.sql"


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(_SCHEMA_FILE.read_text())


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TABLE domain_events;")
