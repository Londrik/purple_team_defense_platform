"""Sentry error tracking initialization for the Purple Team SOAR service."""

import sentry_sdk

from soar.app.core.config import Settings


def configure_sentry(settings: Settings, dsn: str | None = None) -> None:
    """Initialize Sentry SDK when a valid DSN is provided.

    Args:
        settings: Validated SOAR settings instance.
        dsn: Optional Sentry DSN override; when None, SDK remains inactive.
    """
    if not dsn:
        return
    sentry_sdk.init(
        dsn=dsn,
        environment="lab",
        release="purple-team-soar@0.1.0-alpha",
        server_name=settings.iptables_chain,
    )
