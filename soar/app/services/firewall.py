"""Netfilter containment engine and ECS audit logger for Purple Team SOAR."""

import json
import subprocess  # nosec B404
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Any

from soar.app.core.config import Settings
from soar.app.models.ecs_alert import AlertWebhookPayload, ContainmentResponse

CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]

SEVERITY_RANK: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def default_command_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Execute a parameterized system command without shell interpolation.

    Args:
        command: Argument vector passed directly to subprocess.run.

    Returns:
        CompletedProcess containing stdout, stderr, and returncode.
    """
    return subprocess.run(  # nosec B603
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )


class FirewallContainmentService:
    """Evaluates alert eligibility, applies iptables rules, and logs ECS audits."""

    def __init__(
        self,
        settings: Settings,
        runner: CommandRunner = default_command_runner,
    ) -> None:
        """Initialize the containment service.

        Args:
            settings: Validated application settings.
            runner: Injectable command runner for isolated testing.
        """
        self._settings = settings
        self._runner = runner

    def is_ip_safelisted(self, target_ip: IPv4Address | IPv6Address) -> bool:
        """Check whether an IP falls within protected CIDR ranges.

        Args:
            target_ip: Source IP extracted from the SIEM alert.

        Returns:
            True if the IP is protected and must not be blocked; False otherwise.
        """
        parsed_ip = ip_address(str(target_ip))
        return any(parsed_ip in network for network in self._settings.parsed_safelist_networks())

    def meets_severity_threshold(self, severity: str) -> bool:
        """Determine whether alert severity meets the configured containment threshold.

        Args:
            severity: Normalized alert severity string.

        Returns:
            True if severity is equal to or higher than minimum_block_severity.
        """
        incoming_rank = SEVERITY_RANK.get(severity.lower(), 0)
        threshold_rank = SEVERITY_RANK.get(self._settings.minimum_block_severity.lower(), 3)
        return incoming_rank >= threshold_rank

    def contain_alert(self, payload: AlertWebhookPayload) -> ContainmentResponse:
        """Process an incoming alert and enforce containment if eligible.

        Args:
            payload: Validated Kibana webhook payload.

        Returns:
            ContainmentResponse describing the action taken.
        """
        ip_str = str(payload.source_ip)

        if self.is_ip_safelisted(payload.source_ip):
            response = ContainmentResponse(
                status="ignored_safelist",
                source_ip=ip_str,
                chain=self._settings.iptables_chain,
                reason="Source IP matches protected safelist CIDR.",
            )
            self._write_audit_log(payload, response)
            return response

        if not self.meets_severity_threshold(payload.severity):
            response = ContainmentResponse(
                status="ignored_severity",
                source_ip=ip_str,
                chain=self._settings.iptables_chain,
                reason=f"Severity '{payload.severity}' is below threshold.",
            )
            self._write_audit_log(payload, response)
            return response

        check_cmd = [
            "iptables",
            "-C",
            self._settings.iptables_chain,
            "-s",
            ip_str,
            "-j",
            "DROP",
        ]
        check_result = self._runner(check_cmd)
        if check_result.returncode == 0:
            response = ContainmentResponse(
                status="blocked",
                source_ip=ip_str,
                chain=self._settings.iptables_chain,
                reason="Source IP already contained in chain.",
            )
            self._write_audit_log(payload, response)
            return response

        insert_cmd = [
            "iptables",
            "-I",
            self._settings.iptables_chain,
            "1",
            "-s",
            ip_str,
            "-j",
            "DROP",
        ]
        insert_result = self._runner(insert_cmd)
        if insert_result.returncode != 0:
            response = ContainmentResponse(
                status="failed",
                source_ip=ip_str,
                chain=self._settings.iptables_chain,
                reason=insert_result.stderr.strip() or "iptables command failed.",
            )
            self._write_audit_log(payload, response)
            return response

        response = ContainmentResponse(
            status="blocked",
            source_ip=ip_str,
            chain=self._settings.iptables_chain,
            reason="Source IP dropped in dedicated Netfilter chain.",
        )
        self._write_audit_log(payload, response)
        return response

    def _write_audit_log(
        self,
        payload: AlertWebhookPayload,
        response: ContainmentResponse,
    ) -> None:
        """Append an ECS-compliant JSON audit record to the configured log path.

        Args:
            payload: Original alert payload.
            response: Resulting containment decision.
        """
        record: dict[str, Any] = {
            "@timestamp": datetime.now(UTC).isoformat(),
            "event": {
                "kind": "alert",
                "category": ["configuration", "intrusion_detection"],
                "type": ["denied"],
                "action": f"soar-{response.status}",
                "outcome": "failure" if response.status == "failed" else "success",
            },
            "rule": {
                "id": payload.alert_id,
                "name": payload.rule_name,
            },
            "source": {
                "ip": response.source_ip,
            },
            "url": {
                "path": payload.attack_url,
            },
            "threat": {
                "framework": "MITRE ATT&CK",
                "tactic": {"id": payload.mitre_tactic_id},
                "technique": {"id": payload.mitre_technique_id},
            },
            "soar": {
                "chain": response.chain,
                "status": response.status,
                "reason": response.reason,
            },
        }
        audit_path = Path(self._settings.soar_audit_log_path)
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")


SAFELIST_NETWORKS = (
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)


def is_safelisted(ip_address: str) -> bool:
    """Return True if the given IPv4 or IPv6 address belongs to a protected network."""
    import ipaddress

    try:
        parsed = ipaddress.ip_address(ip_address.strip())
    except ValueError:
        return False

    if parsed.is_loopback or parsed.is_link_local:
        return True

    for cidr in SAFELIST_NETWORKS:
        network = ipaddress.ip_network(cidr, strict=False)
        if parsed.version == network.version and parsed in network:
            return True

    return False
