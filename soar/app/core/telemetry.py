"""OpenTelemetry instrumentation helpers for the Purple Team SOAR service."""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider


def configure_tracer(service_name: str = "purple-team-soar") -> trace.Tracer:
    """Configure an OpenTelemetry tracer for SOAR containment operations.

    Args:
        service_name: Logical service name attached to emitted spans.

    Returns:
        Configured OpenTelemetry Tracer instance.
    """
    current_provider = trace.get_tracer_provider()
    if not isinstance(current_provider, TracerProvider):
        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(provider)
    return trace.get_tracer(__name__)


@contextmanager
def start_containment_span(
    span_name: str,
    attributes: dict[str, Any] | None = None,
) -> Iterator[trace.Span]:
    """Start a tracing span with optional attributes for SOAR workflows.

    Args:
        span_name: Descriptive operation name.
        attributes: Optional key-value metadata attached to the span.

    Yields:
        Active OpenTelemetry Span.
    """
    tracer = configure_tracer()
    with tracer.start_as_current_span(span_name) as span:
        if attributes:
            for key, value in attributes.items():
                span.set_attribute(key, str(value))
        yield span
