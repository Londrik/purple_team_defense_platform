"""Unit tests for optional Sentry SDK initialization."""

from pathlib import Path

from soar.app.core.config import Settings
from soar.app.core.sentry_setup import configure_sentry


def test_configure_sentry_noop_without_dsn(tmp_path: Path) -> None:
    """Verify Sentry initialization is a safe no-op when no DSN is supplied."""
    settings = Settings(
        soar_secret_token="unit-test-secret-token",
        soar_audit_log_path=str(tmp_path / "soar_containment.json"),
    )
    configure_sentry(settings=settings, dsn=None)
