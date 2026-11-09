"""Tests for application health and database connection probes."""

def test_app_healthz(client):
    """Checks that /healthz responds with OK and valid metadata."""
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "SIMPATI License Manager" in data["app"]
    assert "version" in data
    assert "timestamp" in data


def test_database_health(client):
    """Checks that /api/v1/health/db verifies database connectivity."""
    response = client.get("/api/v1/health/db")
    assert response.status_code in [200, 503]
    data = response.json()
    assert "dialect" in data
    assert "latency_ms" in data
    assert data["tables_registered"] >= 20
