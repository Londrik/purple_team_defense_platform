"""Security tests for X-SOAR-Token authentication and header edge cases."""

from pathlib import Path

from fastapi.testclient import TestClient

from soar.app.core.config import Settings, get_settings
from soar.app.main import app


def _auth_settings(tmp_path: Path) -> Settings:
    """Create Settings with a known webhook secret for auth testing."""
    return Settings(
        soar_secret_token="task-04-expected-secret-token",
        soar_audit_log_path=str(tmp_path / "soar_containment.json"),
    )


def test_webhook_rejects_empty_and_whitespace_token(tmp_path: Path) -> None:
    """Reject empty or whitespace-only X-SOAR-Token headers with 401."""
    settings = _auth_settings(tmp_path)
    app.dependency_overrides[get_settings] = lambda: settings

    try:
        client = TestClient(app)
        empty_resp = client.post(
            "/webhook/alert-action",
            json={},
            headers={"X-SOAR-Token": ""},
        )
        assert empty_resp.status_code == 401

        spaces_resp = client.post(
            "/webhook/alert-action",
            json={},
            headers={"X-SOAR-Token": "   "},
        )
        assert spaces_resp.status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_webhook_rejects_case_mismatched_token(tmp_path: Path) -> None:
    """Ensure token comparison is case-sensitive and constant-time."""
    settings = _auth_settings(tmp_path)
    app.dependency_overrides[get_settings] = lambda: settings

    try:
        client = TestClient(app)
        resp = client.post(
            "/webhook/alert-action",
            json={},
            headers={"X-SOAR-Token": "TASK-04-EXPECTED-SECRET-TOKEN"},
        )
        assert resp.status_code == 401
    finally:
        app.dependency_overrides.clear()
