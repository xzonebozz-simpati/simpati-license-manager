"""Validate that the Hostless Release process targets a deployment database."""

import logging

from sqlalchemy.engine import make_url

from app.config import Settings, get_settings

logger = logging.getLogger("simpati.release")


def release_configuration_summary(settings: Settings) -> str:
    """Return a safe deployment target summary without exposing the database URL."""
    driver = make_url(settings.normalized_database_url).drivername
    return (
        "Hostless Release configuration verified: "
        f"APP_ENV={settings.APP_ENV} "
        f"DATABASE_URL_SOURCE={settings.database_url_source} "
        f"DATABASE_DRIVER={driver}"
    )


def main() -> None:
    settings = get_settings()
    if not settings.is_production:
        raise RuntimeError("Hostless Release requires APP_ENV=staging or APP_ENV=production.")

    logger.info(release_configuration_summary(settings))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    main()
