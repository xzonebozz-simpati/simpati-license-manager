import asyncio
from unittest.mock import MagicMock, Mock

import pytest
from sqlalchemy.dialects import postgresql

from app.database import startup_compatibility


def _mock_postgres_engine(monkeypatch, foreign_keys, orphan_count=0):
    inspector = Mock()
    inspector.default_schema_name = "public"
    inspector.has_table.return_value = True
    inspector.get_foreign_keys.return_value = foreign_keys
    monkeypatch.setattr(startup_compatibility, "inspect", lambda engine: inspector)

    connection = Mock()
    connection.execute.return_value.scalar_one.return_value = orphan_count
    engine = MagicMock()
    engine.dialect.name = "postgresql"
    engine.dialect.identifier_preparer = postgresql.dialect().identifier_preparer
    engine.begin.return_value.__enter__.return_value = connection
    return engine, connection


@pytest.mark.parametrize(
    ("column", "legacy_table", "target_table"),
    [
        ("package_id", "packages", "license_packages"),
        ("module_id", "modules", "module_registry"),
    ],
)
def test_repairs_legacy_package_modules_foreign_key(
    monkeypatch, column, legacy_table, target_table
):
    engine, connection = _mock_postgres_engine(
        monkeypatch,
        [
            {
                "name": f"package_modules_{column}_fkey",
                "constrained_columns": [column],
                "referred_table": legacy_table,
                "referred_schema": "public",
            }
        ],
    )

    startup_compatibility.repair_package_modules_foreign_keys(engine)

    statements = [str(call.args[0]) for call in connection.execute.call_args_list]
    assert f"DROP CONSTRAINT package_modules_{column}_fkey" in statements[1]
    assert f"REFERENCES public.{target_table} (id)" in statements[2]
    assert len(statements) == 3


def test_does_not_change_foreign_key_when_legacy_rows_would_be_orphaned(monkeypatch):
    engine, connection = _mock_postgres_engine(
        monkeypatch,
        [
            {
                "name": "package_modules_module_id_fkey",
                "constrained_columns": ["module_id"],
                "referred_table": "modules",
                "referred_schema": "public",
            }
        ],
        orphan_count=2,
    )

    with pytest.raises(RuntimeError, match="2 existing module_id rows"):
        startup_compatibility.repair_package_modules_foreign_keys(engine)

    assert connection.execute.call_count == 1


def test_lifespan_repairs_schema_before_seeding(monkeypatch):
    from app import main

    startup_steps = []
    monkeypatch.setattr(
        main, "validate_universal_api_service_configuration", lambda: None
    )
    monkeypatch.setattr(
        main.Base.metadata,
        "create_all",
        lambda bind: startup_steps.append("schema"),
    )
    monkeypatch.setattr(
        main,
        "repair_package_modules_foreign_keys",
        lambda engine: startup_steps.append("compatibility"),
    )
    monkeypatch.setattr(
        main, "seed_initial_data", lambda: startup_steps.append("seeding")
    )

    async def start_application():
        async with main.lifespan(main.app):
            pass

    asyncio.run(start_application())

    assert startup_steps == ["schema", "compatibility", "seeding"]
