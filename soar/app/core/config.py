"""Application settings for the Purple Team SOAR receiver."""

from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_network

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated SOAR configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="forbid",
    )

    soar_secret_token: str = Field(
        default="change-me-in-production",
        min_length=8,
        description="Shared secret token required in the X-SOAR-Token header.",
    )
    soar_audit_log_path: str = Field(
        default="/var/log/soar_containment.json",
        description="Filesystem destination for ECS-formatted containment audit records.",
    )
    iptables_chain: str = Field(
        default="PURPLE_JAIL",
        description="Dedicated Netfilter chain managed by the SOAR service.",
    )
    safelist_cidrs: list[str] = Field(
        default_factory=lambda: [
            "127.0.0.0/8",
            "::1/128",
            "172.18.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ],
        description="Protected CIDR ranges that must never be blocked.",
    )
    minimum_block_severity: str = Field(
        default="high",
        description="Minimum alert severity required to trigger host containment.",
    )

    def parsed_safelist_networks(self) -> list[IPv4Network | IPv6Network]:
        """Parse configured safelist CIDRs into ipaddress network objects.

        Returns:
            A list of IPv4Network or IPv6Network instances.
        """
        return [ip_network(cidr, strict=False) for cidr in self.safelist_cidrs]


@lru_cache
def get_settings() -> Settings:
    """Return cached SOAR settings instance.

    Returns:
        Singleton Settings object.
    """
    return Settings()
