"""Verify that the Release process migrated the configured database to repository head."""

import logging

from app.database.migrations import verify_database_schema_current


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    verify_database_schema_current()
