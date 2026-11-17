web: python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips "*"
release: python -m scripts.validate_release_config && python -m alembic -c alembic.ini upgrade head && python -m scripts.verify_database_migrations
