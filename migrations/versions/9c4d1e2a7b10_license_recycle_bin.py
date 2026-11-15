"""Add soft-delete support for commercial licenses."""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
revision: str = "9c4d1e2a7b10"
down_revision: Union[str, None] = "33a54bb9b371"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None
def upgrade() -> None:
    op.add_column("licenses", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_licenses_deleted_at", "licenses", ["deleted_at"])
def downgrade() -> None:
    op.drop_index("ix_licenses_deleted_at", table_name="licenses")
    op.drop_column("licenses", "deleted_at")
