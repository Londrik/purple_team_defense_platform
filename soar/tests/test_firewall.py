"""Unit, API contract, and edge-case tests for the Purple Team SOAR service."""

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from soar.app.core.config import Settings, get_settings
from soar.app.main import app, get_containment_service
from soar.app.models.ecs_alert import AlertWebhookPayload
from soar.app.services.firewall import FirewallContainmentService


def _build_settings(tmp_path: Path) -> Settings:
    """Create isolated Settings writing audit logs to a temporary directory."""
    return Settings(
        soar_secret_token="unit-test-secret-token",
        soar_audit_log_path=str(tmp_path / "soar_containment.json"),
        iptables_chain="PURPLE_JAIL",
        minimum_block_severity="high",
    )


def _sample_payload(
    source_ip: str = "203.0.113.50",
    severity: str = "high",
) -> dict[str, str]:
    """Generate a valid Kibana webhook JSON payload."""
    return {
        "alert_id": "alert-001",
        "rule_name": "Purple Team: SQL Injection Attempt",
        "severity": severity,
        "source_ip": source_ip,
        "attack_url": "/rest/products/search?q=' OR 1=1--",
        "mitre_tactic_id": "TA0001",
        "mitre_technique_id": "T1190",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@pytest.mark.parametrize(
    "protected_ip",
    [
        "127.0.0.1",
        "172.18.0.1",
        "10.10.1.5",
        "172.16.5.4",
        "192.168.1.1",
    ],
)
def test_safelist_prevents_self_dos(tmp_path: Path, protected_ip: str) -> None:
    """Ensure loopback, bridge gateway, and RFC 1918 ranges are never blocked."""
    executed: list[list[str]] = []

    def fake_runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        executed.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    settings = _build_settings(tmp_path)
    service = FirewallContainmentService(settings=settings, runner=fake_runner)
    payload = AlertWebhookPayload.model_validate(_sample_payload(source_ip=protected_ip))

    result = service.contain_alert(payload)

    assert result.status == "ignored_safelist"
    assert executed == []


def test_blocks_external_malicious_ip_and_writes_ecs_audit(tmp_path: Path) -> None:
    """Verify iptables insertion and structured ECS audit logging for external IP."""
    executed: list[list[str]] = []

    def fake_runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        executed.append(cmd)
        if cmd[1] == "-C":
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    settings = _build_settings(tmp_path)
    service = FirewallContainmentService(settings=settings, runner=fake_runner)
    payload = AlertWebhookPayload.model_validate(_sample_payload(source_ip="203.0.113.99"))

    result = service.contain_alert(payload)

    assert result.status == "blocked"
    assert executed == [
        ["iptables", "-C", "PURPLE_JAIL", "-s", "203.0.113.99", "-j", "DROP"],
        ["iptables", "-I", "PURPLE_JAIL", "1", "-s", "203.0.113.99", "-j", "DROP"],
    ]

    audit_file = Path(settings.soar_audit_log_path)
    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    audit_event = json.loads(lines[0])
    assert audit_event["source"]["ip"] == "203.0.113.99"
    assert audit_event["threat"]["tactic"]["id"] == "TA0001"
    assert audit_event["threat"]["technique"]["id"] == "T1190"


def test_idempotent_block_when_rule_already_exists(tmp_path: Path) -> None:
    """Avoid duplicate iptables insertions when rule check (-C) succeeds."""
    executed: list[list[str]] = []

    def fake_runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        executed.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    settings = _build_settings(tmp_path)
    service = FirewallContainmentService(settings=settings, runner=fake_runner)
    payload = AlertWebhookPayload.model_validate(_sample_payload(source_ip="198.51.100.12"))

    result = service.contain_alert(payload)

    assert result.status == "blocked"
    assert len(executed) == 1
    assert executed[0][1] == "-C"


def test_ignores_low_severity_alert(tmp_path: Path) -> None:
    """Ensure alerts below threshold do not trigger Netfilter changes."""
    executed: list[list[str]] = []

    def fake_runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        executed.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    settings = _build_settings(tmp_path)
    service = FirewallContainmentService(settings=settings, runner=fake_runner)
    payload = AlertWebhookPayload.model_validate(
        _sample_payload(source_ip="198.51.100.25", severity="medium")
    )

    result = service.contain_alert(payload)

    assert result.status == "ignored_severity"
    assert executed == []


def test_reports_failure_when_iptables_returns_nonzero(tmp_path: Path) -> None:
    """Return failed status when iptables insertion exits with non-zero code."""

    def fake_runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        if cmd[1] == "-C":
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=1,
            stdout="",
            stderr="iptables: Permission denied",
        )

    settings = _build_settings(tmp_path)
    service = FirewallContainmentService(settings=settings, runner=fake_runner)
    payload = AlertWebhookPayload.model_validate(_sample_payload(source_ip="198.51.100.33"))

    result = service.contain_alert(payload)

    assert result.status == "failed"
    assert "Permission denied" in result.reason


def test_webhook_rejects_unauthorized_and_accepts_valid_token(tmp_path: Path) -> None:
    """Verify FastAPI endpoint enforces X-SOAR-Token and delegates containment."""
    settings = _build_settings(tmp_path)

    def fake_runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        if cmd[1] == "-C":
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_containment_service] = lambda: FirewallContainmentService(
        settings=settings,
        runner=fake_runner,
    )

    try:
        client = TestClient(app)
        unauth = client.post("/webhook/alert-action", json=_sample_payload())
        assert unauth.status_code == 401

        invalid = client.post(
            "/webhook/alert-action",
            json=_sample_payload(),
            headers={"X-SOAR-Token": "wrong-token"},
        )
        assert invalid.status_code == 401

        valid = client.post(
            "/webhook/alert-action",
            json=_sample_payload(source_ip="203.0.113.77"),
            headers={"X-SOAR-Token": "unit-test-secret-token"},
        )
        assert valid.status_code == 200
        body = valid.json()
        assert body["status"] == "blocked"
        assert body["source_ip"] == "203.0.113.77"
    finally:
        app.dependency_overrides.clear()
