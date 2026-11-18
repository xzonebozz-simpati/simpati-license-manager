"""Compatibility migrations for schemas created before the current ORM models."""

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine


def repair_package_modules_foreign_key(engine: Engine) -> None:
    """Align legacy package-module foreign keys with the current package table."""
    if engine.dialect.name != "postgresql":
        return

    inspector = inspect(engine)
    schema = inspector.default_schema_name
    if not inspector.has_table("package_modules", schema=schema):
        return
    if not inspector.has_table("license_packages", schema=schema):
        raise RuntimeError(
            "Cannot repair package_modules foreign key: license_packages table is missing."
        )

    foreign_keys = inspector.get_foreign_keys("package_modules", schema=schema)
    mismatched_foreign_keys = [
        foreign_key
        for foreign_key in foreign_keys
        if foreign_key.get("constrained_columns") == ["package_id"]
        and (
            foreign_key.get("referred_table") != "license_packages"
            or foreign_key.get("referred_schema") not in (None, schema)
        )
    ]
    if not mismatched_foreign_keys:
        return

    if any(not foreign_key.get("name") for foreign_key in mismatched_foreign_keys):
        raise RuntimeError(
            "Cannot repair package_modules foreign key: constraint name is unavailable."
        )

    preparer = engine.dialect.identifier_preparer
    package_modules_table = preparer.quote("package_modules")
    license_packages_table = preparer.quote("license_packages")
    if schema:
        quoted_schema = preparer.quote_schema(schema)
        package_modules_table = f"{quoted_schema}.{package_modules_table}"
        license_packages_table = f"{quoted_schema}.{license_packages_table}"

    with engine.begin() as connection:
        orphan_count = connection.execute(
            text(
                f"SELECT count(*) FROM {package_modules_table} AS pm "
                f"WHERE NOT EXISTS (SELECT 1 FROM {license_packages_table} AS lp "
                "WHERE lp.id = pm.package_id)"
            )
        ).scalar_one()
        if orphan_count:
            raise RuntimeError(
                "Cannot repair package_modules foreign key: "
                f"{orphan_count} existing rows do not reference license_packages."
            )

        for foreign_key in mismatched_foreign_keys:
            constraint_name = preparer.quote(foreign_key["name"])
            connection.execute(
                text(
                    f"ALTER TABLE {package_modules_table} "
                    f"DROP CONSTRAINT {constraint_name}"
                )
            )

        has_current_foreign_key = any(
            foreign_key.get("constrained_columns") == ["package_id"]
            and foreign_key.get("referred_table") == "license_packages"
            and foreign_key.get("referred_schema") in (None, schema)
            for foreign_key in foreign_keys
        )
        if not has_current_foreign_key:
            connection.execute(
                text(
                    f"ALTER TABLE {package_modules_table} "
                    "ADD CONSTRAINT package_modules_package_id_fkey "
                    f"FOREIGN KEY (package_id) REFERENCES {license_packages_table} (id) "
                    "ON DELETE CASCADE"
                )
            )
