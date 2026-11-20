# Runbook: `X-SOAR-Token` Rotation and Post-Containment Recovery

## 1. Scope and Cadence
- Rotate `SOAR_SECRET_TOKEN` immediately upon suspected token exposure or routinely at planned maintenance windows.
- Align containment review and recovery steps with NIST SP 800-61 Rev. 2 (Containment, Eradication & Recovery).

## 2. Token Rotation Steps
1. Generate a high-entropy secret token on the host:
   `openssl rand -hex 32`
2. Update `SOAR_SECRET_TOKEN` in the SOAR runtime environment configuration and restart the FastAPI SOAR service.
3. Update the `X-SOAR-Token` header in the Kibana Detection Engine webhook action connector.
4. Validate authentication behavior:
   - Requests without `X-SOAR-Token` or with the previous token must return `401 Unauthorized`.
   - Requests with the rotated token must return `200 OK`.
