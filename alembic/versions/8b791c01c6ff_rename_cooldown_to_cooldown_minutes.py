"""rename cooldown to cooldown_minutes

Revision ID: 8b791c01c6ff
Revises: 7e81ca8b5dcd
Create Date: 2026-10-15 18:04:09.160765

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8b791c01c6ff'
down_revision: Union[str, Sequence[str], None] = '7e81ca8b5dcd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column("rules", "cooldown", new_column_name="cooldown_minutes")
    pass


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column("rules", "cooldown_minutes", new_column_name="cooldown")
    pass
