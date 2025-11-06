"""OpenTelemetry tracer setup and management.

Handles initialization of the OTLP exporter and tracer provider.
"""

import atexit
import logging
from typing import Literal

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
    OTLPSpanExporter as GrpcOTLPSpanExporter,
)
from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
    OTLPSpanExporter as HttpOTLPSpanExporter,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter

from .config import Config

logger = logging.getLogger(__name__)


class TracerManager:
    """Manages OpenTelemetry tracer lifecycle."""

    def __init__(self, config: Config):
        """Initialize the tracer manager.

        Args:
            config: Application configuration containing OTLP settings.
        """
        self.config = config
        self.tracer_provider: TracerProvider | None = None
        self.tracer: trace.Tracer | None = None

    def setup(self) -> trace.Tracer:
        """Set up OpenTelemetry tracer with configured exporter.

        Returns:
            Configured Tracer instance.

        Raises:
            ValueError: If tracer setup fails.
        """
        logger.info("Initializing OpenTelemetry tracer...")

        # Create resource with service attributes
        resource = Resource.create(self.config.resource_attributes())

        # Initialize tracer provider
        self.tracer_provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(self.tracer_provider)

        # Create appropriate exporter based on protocol
        # Use signal-specific traces endpoint/protocol with fallback to base
        traces_endpoint = self.config.get_traces_endpoint()
        traces_protocol = self.config.get_traces_protocol()

        exporter = self._create_exporter(traces_endpoint, traces_protocol)

        # Add batch span processor
        span_processor = BatchSpanProcessor(exporter)
        self.tracer_provider.add_span_processor(span_processor)

        # Get tracer instance
        self.tracer = trace.get_tracer(__name__)

        # Register shutdown handler
        atexit.register(self.shutdown)

        logger.info(
            f"OpenTelemetry tracer initialized with {traces_protocol.upper()} "
            f"exporter to {traces_endpoint}"
        )

        return self.tracer

    def _create_exporter(
        self, endpoint: str, protocol: Literal["grpc", "http"]
    ) -> SpanExporter:
        """Create OTLP span exporter based on protocol.

        Args:
            endpoint: OTLP collector endpoint URL.
            protocol: Protocol to use (grpc or http).

        Returns:
            Configured SpanExporter instance.

        Raises:
            ValueError: If protocol is invalid.
        """
        if protocol == "grpc":
            logger.debug(f"Creating gRPC OTLP exporter for endpoint: {endpoint}")
            return GrpcOTLPSpanExporter(
                endpoint=endpoint,
                insecure=endpoint.startswith("http://"),
            )
        elif protocol == "http":
            logger.debug(f"Creating HTTP OTLP exporter for endpoint: {endpoint}")
            # HTTP exporter expects full path including /v1/traces
            if not endpoint.endswith("/v1/traces"):
                endpoint = f"{endpoint.rstrip('/')}/v1/traces"
            return HttpOTLPSpanExporter(endpoint=endpoint)
        else:
            raise ValueError(f"Invalid protocol: {protocol}. Must be 'grpc' or 'http'.")

    def shutdown(self) -> None:
        """Gracefully shutdown the tracer provider, flushing pending spans."""
        if self.tracer_provider:
            logger.info("Shutting down OpenTelemetry tracer provider...")
            try:
                self.tracer_provider.shutdown()
                logger.info("OpenTelemetry tracer provider shutdown complete")
            except Exception as e:
                logger.error(f"Error during tracer provider shutdown: {e}")

    def get_tracer(self) -> trace.Tracer:
        """Get the configured tracer instance.

        Returns:
            Tracer instance.

        Raises:
            RuntimeError: If tracer has not been set up.
        """
        if self.tracer is None:
            raise RuntimeError("Tracer not initialized. Call setup() first.")
        return self.tracer
