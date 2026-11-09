"""SIMPATI License Manager - Main Application Runner.

Configured for local execution and cloud deployment (Hostless / Container).

Run locally:
    python app.py
or via Uvicorn CLI:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips "*"
"""

import os
import sys
import uvicorn
from app.config import get_settings

settings = get_settings()

# Dynamic port discovery: Hostless sets the PORT environment variable
effective_port = int(os.environ.get("PORT") or settings.APP_PORT)
effective_host = os.environ.get("HOST") or settings.APP_HOST

if __name__ == "__main__":
    print("===============================================================")
    print(f" {settings.APP_NAME} v{settings.APP_VERSION}")
    print(f" Environment : {settings.APP_ENV}")
    print(f" Listening on: http://{effective_host}:{effective_port}")
    print(f" Web URL     : http://localhost:{effective_port}/")
    print(f" API Docs    : http://localhost:{effective_port}/docs")
    print(f" Health Check: http://localhost:{effective_port}/healthz")
    print(f" Proxy Trust : {settings.FORWARDED_ALLOW_IPS}")
    print("===============================================================")

    uvicorn.run(
        "app.main:app",
        host=effective_host,
        port=effective_port,
        reload=settings.APP_DEBUG,
        proxy_headers=True,
        forwarded_allow_ips=settings.FORWARDED_ALLOW_IPS,
        access_log=True,
    )
