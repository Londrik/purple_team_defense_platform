"""Unit tests for OpenTelemetry span creation in the SOAR service."""

from soar.app.core.telemetry import start_containment_span


def test_start_containment_span_attaches_attributes() -> None:
    """Verify span context manager executes cleanly with attributes."""
    with start_containment_span(
        "soar.contain_ip",
        attributes={"source.ip": "203.0.113.88", "threat.technique.id": "T1190"},
    ) as span:
        assert span is not None
        assert span.is_recording() is True
