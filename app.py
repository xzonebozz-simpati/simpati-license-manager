"""SIMPATI License Manager - Main Application Runner.

Run with:
    python app.py
or:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""

import sys
import uvicorn
from app.config import get_settings

settings = get_settings()

if __name__ == "__main__":
    print(f"===============================================================")
    print(f" {settings.APP_NAME} v{settings.APP_VERSION}")
    print(f" Environment: {settings.APP_ENV}")
    print(f" Listening on: http://{settings.APP_HOST}:{settings.APP_PORT}")
    print(f" Web Dashboard: http://localhost:{settings.APP_PORT}/")
    print(f" API Docs: http://localhost:{settings.APP_PORT}/docs")
    print(f"===============================================================")
    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.APP_DEBUG
    )
