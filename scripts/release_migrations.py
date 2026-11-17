"""Run and verify the Hostless Release migration from the repository root."""

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable

logger = logging.getLogger("simpati.release")


def run_alembic_upgrade(
    project_root: Path,
    run_command: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> None:
    """Run the canonical Alembic upgrade and preserve its failure exit status."""
    result = run_command(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(project_root),
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    os.chdir(project_root)

    from scripts.validate_release_config import main as validate_release_config

    validate_release_config()
    run_alembic_upgrade(project_root)

    from app.database.migrations import verify_database_schema_current

    verify_database_schema_current()
    logger.info("Hostless Release migration verified against repository head.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    main()
