"""Pydantic v2 DTOs for Kibana webhook alerts and SOAR containment responses."""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AlertWebhookPayload(BaseModel):
    """Incoming alert payload sent by Kibana Detection Engine."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alert_id: str = Field(..., min_length=1, max_length=128)
    rule_name: str = Field(..., min_length=1, max_length=256)
    severity: Literal["low", "medium", "high", "critical"]
    source_ip: IPv4Address | IPv6Address
    attack_url: str = Field(default="/", max_length=2048)
    mitre_tactic_id: str = Field(default="TA0001", pattern=r"^TA\d{4}$")
    mitre_technique_id: str = Field(default="T1190", pattern=r"^T\d{4}(\.\d{3})?$")
    timestamp: datetime


class ContainmentResponse(BaseModel):
    """Structured API response returned after evaluating a containment request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["blocked", "ignored_safelist", "ignored_severity", "failed"]
    source_ip: str
    chain: str
    reason: str
