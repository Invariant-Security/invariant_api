"""create demo_host_snapshots table

Revision ID: 4d5e6f7a8b9c
Revises: 3c4d5e6f7a8b
Create Date: 2026-09-20 05:00:01.000000

"""
from pathlib import Path
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4d5e6f7a8b9c'
down_revision: Union[str, Sequence[str], None] = '3c4d5e6f7a8b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA_FILE = Path(__file__).resolve().parents[2] / "schema" / "00012_demo_host_snapshots.sql"


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(_SCHEMA_FILE.read_text())


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TABLE demo_host_snapshots CASCADE;")
