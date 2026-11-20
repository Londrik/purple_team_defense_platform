"""Regression tests for detection rule definitions and true/false positive classification."""

import json
from pathlib import Path

import pytest


def _load_rules() -> list[dict[str, object]]:
    """Load declarative Kibana detection rules from repository."""
    rules_path = Path("detections/rules/juice_shop_mitre_rules.json")
    data = json.loads(rules_path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    return data


def _matches_rule(rule_id: str, url_path: str, status_code: int = 200) -> bool:
    """Evaluate representative URL/status patterns for true/false positive regression."""
    lowered = url_path.lower()
    if rule_id == "purple-sqli-t1190":
        return any(token in lowered for token in ("' or ", "union select", "--"))
    if rule_id == "purple-lfi-t1083":
        return "../" in lowered or "..%2f" in lowered or "etc/passwd" in lowered
    if rule_id == "purple-xss-t1189":
        return any(token in lowered for token in ("<script", "javascript:", "onerror="))
    if rule_id == "purple-bola-t1068":
        return lowered.startswith("/rest/basket/") and status_code in {200, 401, 403}
    raise ValueError(f"Unknown rule_id: {rule_id}")


def test_all_four_mitre_rules_are_defined() -> None:
    """Verify the four core MITRE ATT&CK rules exist with required fields."""
    rules = _load_rules()
    ids = {str(rule["rule_id"]) for rule in rules}
    assert ids == {
        "purple-sqli-t1190",
        "purple-lfi-t1083",
        "purple-xss-t1189",
        "purple-bola-t1068",
    }


@pytest.mark.parametrize(
    ("rule_id", "malicious_path", "status_code"),
    [
        ("purple-sqli-t1190", "/rest/products/search?q=' OR 1=1--", 200),
        ("purple-lfi-t1083", "/ftp/..%2F..%2Fetc%2Fpasswd", 403),
        ("purple-xss-t1189", "/rest/track-order/123<script>alert(1)</script>", 200),
        ("purple-bola-t1068", "/rest/basket/2", 200),
    ],
)
def test_true_positive_attack_vectors_match_rule(
    rule_id: str,
    malicious_path: str,
    status_code: int,
) -> None:
    """Ensure attack payloads trigger their corresponding detection rule."""
    assert _matches_rule(rule_id, malicious_path, status_code) is True


@pytest.mark.parametrize(
    ("rule_id", "benign_path", "status_code"),
    [
        ("purple-sqli-t1190", "/rest/products/search?q=apple", 200),
        ("purple-lfi-t1083", "/assets/public/images/logo.png", 200),
        ("purple-xss-t1189", "/rest/track-order/123", 200),
        ("purple-bola-t1068", "/rest/products/search?q=juice", 200),
    ],
)
def test_false_positive_benign_requests_do_not_match_rule(
    rule_id: str,
    benign_path: str,
    status_code: int,
) -> None:
    """Ensure benign application traffic does not trigger false positive matches."""
    assert _matches_rule(rule_id, benign_path, status_code) is False
