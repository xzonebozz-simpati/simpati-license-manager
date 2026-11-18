"""Compatibility migrations for schemas created before the current ORM models."""

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine


def repair_package_modules_foreign_keys(engine: Engine) -> None:
    """Align legacy package-module foreign keys with the current catalog tables."""
    if engine.dialect.name != "postgresql":
        return

    inspector = inspect(engine)
    schema = inspector.default_schema_name
    if not inspector.has_table("package_modules", schema=schema):
        return

    foreign_keys = inspector.get_foreign_keys("package_modules", schema=schema)
    expected_targets = {
        "package_id": "license_packages",
        "module_id": "module_registry",
    }
    mismatched_foreign_keys = [
        foreign_key
        for foreign_key in foreign_keys
        if foreign_key.get("constrained_columns") in (
            ["package_id"],
            ["module_id"],
        )
        and (
            foreign_key.get("referred_table")
            != expected_targets[foreign_key["constrained_columns"][0]]
            or foreign_key.get("referred_schema") not in (None, schema)
        )
    ]
    if not mismatched_foreign_keys:
        return

    affected_columns = {
        foreign_key["constrained_columns"][0]
        for foreign_key in mismatched_foreign_keys
    }
    for column in affected_columns:
        target_table = expected_targets[column]
        if not inspector.has_table(target_table, schema=schema):
            raise RuntimeError(
                "Cannot repair package_modules foreign key: "
                f"{target_table} table is missing."
            )

    if any(not foreign_key.get("name") for foreign_key in mismatched_foreign_keys):
        raise RuntimeError(
            "Cannot repair package_modules foreign keys: "
            "constraint name is unavailable."
        )

    preparer = engine.dialect.identifier_preparer
    package_modules_table = preparer.quote("package_modules")
    quoted_targets = {
        table: preparer.quote(table)
        for table in set(expected_targets.values())
    }
    if schema:
        quoted_schema = preparer.quote_schema(schema)
        package_modules_table = f"{quoted_schema}.{package_modules_table}"
        quoted_targets = {
            table: f"{quoted_schema}.{quoted_table}"
            for table, quoted_table in quoted_targets.items()
        }

    with engine.begin() as connection:
        for column in affected_columns:
            target_table = expected_targets[column]
            quoted_column = preparer.quote(column)
            orphan_count = connection.execute(
                text(
                    f"SELECT count(*) FROM {package_modules_table} AS pm "
                    f"WHERE NOT EXISTS (SELECT 1 FROM {quoted_targets[target_table]} "
                    f"AS parent WHERE parent.id = pm.{quoted_column})"
                )
            ).scalar_one()
            if orphan_count:
                raise RuntimeError(
                    "Cannot repair package_modules foreign key: "
                    f"{orphan_count} existing {column} rows do not reference "
                    f"{target_table}."
                )

        for foreign_key in mismatched_foreign_keys:
            constraint_name = preparer.quote(foreign_key["name"])
            connection.execute(
                text(
                    f"ALTER TABLE {package_modules_table} "
                    f"DROP CONSTRAINT {constraint_name}"
                )
            )

        for column in affected_columns:
            target_table = expected_targets[column]
            has_current_foreign_key = any(
                foreign_key.get("constrained_columns") == [column]
                and foreign_key.get("referred_table") == target_table
                and foreign_key.get("referred_schema") in (None, schema)
                for foreign_key in foreign_keys
            )
            if has_current_foreign_key:
                continue

            connection.execute(
                text(
                    f"ALTER TABLE {package_modules_table} "
                    f"ADD CONSTRAINT package_modules_{column}_fkey "
                    f"FOREIGN KEY ({preparer.quote(column)}) "
                    f"REFERENCES {quoted_targets[target_table]} (id) "
                    "ON DELETE CASCADE"
                )
            )
