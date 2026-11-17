"""Persist validation nonces to prevent M2M request replay."""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20261117_nonce_guard"
down_revision: Union[str, None] = "9c4d1e2a7b10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "validation_nonces",
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("installation_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["installation_id"], ["installations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("nonce"),
    )
    op.create_index("ix_validation_nonces_installation_id", "validation_nonces", ["installation_id"])
    op.create_index("ix_validation_nonces_created_at", "validation_nonces", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_validation_nonces_created_at", table_name="validation_nonces")
    op.drop_index("ix_validation_nonces_installation_id", table_name="validation_nonces")
    op.drop_table("validation_nonces")
