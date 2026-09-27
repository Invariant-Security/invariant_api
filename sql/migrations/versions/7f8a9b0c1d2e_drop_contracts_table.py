"""drop contracts table

Pix checkout (routes/billing.py) foi removido -- o site não recebe mais
pagamento. A tabela guardava nome/e-mail de contratante sem finalidade
restante (LGPD art. 16), então sai junto. IF EXISTS porque em prod ela foi
apagada à mão (com dump antes) antes desta migração chegar em main.

Revision ID: 7f8a9b0c1d2e
Revises: 6e7f8a9b0c1d
Create Date: 2026-09-27 18:00:00.000000

"""
from pathlib import Path
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7f8a9b0c1d2e'
down_revision: Union[str, Sequence[str], None] = '6e7f8a9b0c1d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA_FILE = Path(__file__).resolve().parents[2] / "schema" / "00003_contracts.sql"


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("DROP TABLE IF EXISTS contracts CASCADE;")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute(_SCHEMA_FILE.read_text())
