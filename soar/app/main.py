"""FastAPI entrypoint for the Purple Team SOAR containment webhook receiver."""

import secrets
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status

from soar.app.core.config import Settings, get_settings
from soar.app.models.ecs_alert import AlertWebhookPayload, ContainmentResponse
from soar.app.services.firewall import FirewallContainmentService

app = FastAPI(
    title="Purple Team SOAR Receiver",
    version="0.1.0-alpha",
    description="Automated host containment service for Kibana Detection Engine alerts.",
)


def get_containment_service(
    settings: Annotated[Settings, Depends(get_settings)],
) -> FirewallContainmentService:
    """Provide a FirewallContainmentService instance via FastAPI dependency injection.

    Args:
        settings: Validated SOAR settings.

    Returns:
        Configured FirewallContainmentService.
    """
    return FirewallContainmentService(settings=settings)


def verify_soar_token(
    settings: Annotated[Settings, Depends(get_settings)],
    x_soar_token: Annotated[str | None, Header(alias="X-SOAR-Token")] = None,
) -> None:
    """Validate the shared webhook token using constant-time comparison.

    Args:
        settings: Validated SOAR settings.
        x_soar_token: Token supplied in the X-SOAR-Token HTTP header.

    Raises:
        HTTPException: If the header is missing or does not match the configured secret.
    """
    if not x_soar_token or not secrets.compare_digest(
        x_soar_token,
        settings.soar_secret_token,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing SOAR webhook token.",
        )


@app.get("/health", tags=["observability"])
def health_check() -> dict[str, str]:
    """Return service liveness status.

    Returns:
        Dictionary indicating healthy status.
    """
    return {"status": "ok"}


@app.post(
    "/webhook/alert-action",
    response_model=ContainmentResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_soar_token)],
    tags=["containment"],
)
def handle_alert_webhook(
    payload: AlertWebhookPayload,
    service: Annotated[FirewallContainmentService, Depends(get_containment_service)],
) -> ContainmentResponse:
    """Receive a Kibana Detection Engine alert and execute host containment.

    Args:
        payload: Validated ECS/MITRE alert webhook payload.
        service: Injected FirewallContainmentService.

    Returns:
        ContainmentResponse indicating whether the source IP was blocked or ignored.
    """
    return service.contain_alert(payload)
