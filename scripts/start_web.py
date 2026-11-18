"""Run deployment migrations once, then start the Web server."""

import logging
import os
import subprocess
import sys

from scripts.release_migrations import main as run_release_migrations

logger = logging.getLogger("simpati.startup")


def main() -> None:
    logger.info("Running database migrations before starting Uvicorn.")
    try:
        run_release_migrations()
    except SystemExit as exc:
        logger.error("Startup aborted: migration runner exited with status %s.", exc.code)
        raise

    logger.info("Database migrations completed; starting Uvicorn.")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "0.0.0.0",
            "--port",
            os.environ.get("PORT", "8000"),
            "--proxy-headers",
            "--forwarded-allow-ips",
            "*",
        ],
        check=False,
    )
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    main()
