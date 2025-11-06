"""OpenTelemetry metrics setup and helper utilities."""

from __future__ import annotations

import atexit
import logging
from dataclasses import dataclass
from typing import Any, Literal

from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
    OTLPMetricExporter as GrpcOTLPMetricExporter,
)
from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
    OTLPMetricExporter as HttpOTLPMetricExporter,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource

from opentelemetry.metrics import get_meter, set_meter_provider

from .config import Config

logger = logging.getLogger(__name__)


@dataclass
class CollectorMetrics:
    """Helper around the instruments exposed by the NetFlow collector."""

    packet_counter: Any
    packet_bytes_counter: Any
    flow_counter: Any
    packet_error_counter: Any
    packet_size_histogram: Any
    flows_per_packet_histogram: Any

    def record_packet(self, size_bytes: int) -> None:
        """Record that a NetFlow packet was processed."""
        self.packet_counter.add(1)
        self.packet_bytes_counter.add(size_bytes)
        self.packet_size_histogram.record(size_bytes)

    def record_flows(self, flow_count: int) -> None:
        """Record the number of flows extracted from the most recent packet."""
        if flow_count < 0:
            return
        self.flow_counter.add(flow_count)
        self.flows_per_packet_histogram.record(flow_count)

    def record_error(self) -> None:
        """Record that a NetFlow packet failed to process."""
        self.packet_error_counter.add(1)


class MetricsManager:
    """Sets up the OpenTelemetry meter provider and instruments."""

    def __init__(self, config: Config):
        self.config = config
        self.meter_provider: MeterProvider | None = None
        self.metrics: CollectorMetrics | None = None

    def setup(self) -> CollectorMetrics:
        """Initialise the MeterProvider, exporter, and instruments."""
        logger.info("Initializing OpenTelemetry metrics exporter...")

        resource = Resource.create(self.config.resource_attributes())

        # Use signal-specific metrics endpoint/protocol with fallback to base
        metrics_endpoint = self.config.get_metrics_endpoint()
        metrics_protocol = self.config.get_metrics_protocol()

        exporter = self._create_exporter(metrics_endpoint, metrics_protocol)

        reader = PeriodicExportingMetricReader(exporter)
        self.meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
        set_meter_provider(self.meter_provider)

        meter = get_meter(__name__)

        collector_metrics = CollectorMetrics(
            packet_counter=meter.create_counter(
                name="netflow_packets_total",
                unit="1",
                description="Total number of NetFlow export packets processed.",
            ),
            packet_bytes_counter=meter.create_counter(
                name="netflow_packet_bytes_total",
                unit="By",
                description="Total bytes of NetFlow export packets processed.",
            ),
            flow_counter=meter.create_counter(
                name="netflow_flows_total",
                unit="1",
                description="Total number of NetFlow flow records processed.",
            ),
            packet_error_counter=meter.create_counter(
                name="netflow_packet_errors_total",
                unit="1",
                description="Total number of NetFlow packets that failed to process.",
            ),
            packet_size_histogram=meter.create_histogram(
                name="netflow_packet_size_bytes",
                unit="By",
                description="Distribution of NetFlow packet sizes processed.",
            ),
            flows_per_packet_histogram=meter.create_histogram(
                name="netflow_flows_per_packet",
                unit="1",
                description="Distribution of flow records per NetFlow packet.",
            ),
        )

        self.metrics = collector_metrics
        atexit.register(self.shutdown)

        logger.info(
            "OpenTelemetry metrics initialised with %s exporter to %s",
            metrics_protocol.upper(),
            metrics_endpoint,
        )

        return collector_metrics

    def shutdown(self) -> None:
        """Shutdown the MeterProvider flushing any pending metrics."""
        if not self.meter_provider:
            return

        logger.info("Shutting down OpenTelemetry meter provider...")
        try:
            self.meter_provider.shutdown()
            logger.info("OpenTelemetry meter provider shutdown complete")
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.error("Error during meter provider shutdown: %s", exc)

    def _create_exporter(
        self, endpoint: str, protocol: Literal["grpc", "http"]
    ) -> GrpcOTLPMetricExporter | HttpOTLPMetricExporter:
        if protocol == "grpc":
            logger.debug("Creating gRPC OTLP metric exporter for endpoint: %s", endpoint)
            return GrpcOTLPMetricExporter(
                endpoint=endpoint,
                insecure=endpoint.startswith("http://"),
            )

        if protocol == "http":
            logger.debug("Creating HTTP OTLP metric exporter for endpoint: %s", endpoint)
            if not endpoint.endswith("/v1/metrics"):
                endpoint = f"{endpoint.rstrip('/')}/v1/metrics"
            return HttpOTLPMetricExporter(endpoint=endpoint)

        raise ValueError(f"Invalid protocol: {protocol}. Must be 'grpc' or 'http'.")
