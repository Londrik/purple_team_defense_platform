"""Additional safelist tests covering IPv6 loopback and private ranges."""

import pytest

from soar.app.services.firewall import is_safelisted


@pytest.mark.parametrize(
    "ip_address",
    [
        "::1",
        "fc00::1",
        "fd12:3456:789a::1",
        "fe80::1",
    ],
)
def test_ipv6_local_and_private_addresses_are_safelisted(ip_address: str) -> None:
    """Prevent accidental containment of IPv6 loopback and local addresses."""
    assert is_safelisted(ip_address) is True


@pytest.mark.parametrize(
    "public_ip",
    [
        "198.51.100.42",
        "203.0.113.99",
        "2001:db8::10",
    ],
)
def test_external_test_addresses_are_not_safelisted(public_ip: str) -> None:
    """Confirm external non-reserved test addresses are eligible for containment."""
    assert is_safelisted(public_ip) is False
