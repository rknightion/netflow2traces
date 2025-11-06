"""Configuration management for NetFlow to Traces application.

Loads configuration from environment variables with sensible defaults.
"""

import logging
import os
from dataclasses import dataclass
from typing import Any, Literal


@dataclass
class Config:
    """Application configuration loaded from environment variables."""

    # NetFlow listener settings
    netflow_listen_host: str
    netflow_listen_port: int

    # OpenTelemetry settings - base configuration
    otel_exporter_endpoint: str
    otel_exporter_protocol: Literal["grpc", "http"]
    otel_service_name: str
    otel_service_version: str

    # OpenTelemetry settings - signal-specific configuration
    # These take precedence over base endpoint/protocol when set
    otel_traces_endpoint: str | None
    otel_traces_protocol: Literal["grpc", "http"] | None
    otel_metrics_endpoint: str | None
    otel_metrics_protocol: Literal["grpc", "http"] | None

    # Logging settings
    log_level: str

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables.

        Returns:
            Config: Configuration instance with values from environment or defaults.

        Raises:
            ValueError: If required environment variables are missing or invalid.
        """
        # NetFlow listener
        netflow_listen_host = os.getenv("NETFLOW_LISTEN_HOST", "0.0.0.0")
        netflow_listen_port = int(os.getenv("NETFLOW_LISTEN_PORT", "2055"))

        # OpenTelemetry - base endpoint (required unless signal-specific are provided)
        otel_exporter_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")

        # Signal-specific endpoints (optional - take precedence over base)
        otel_traces_endpoint = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        otel_metrics_endpoint = os.getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")

        # Validate that at least one endpoint is configured
        if not otel_exporter_endpoint and not (otel_traces_endpoint or otel_metrics_endpoint):
            raise ValueError(
                "At least one OTLP endpoint must be configured:\n"
                "  - OTEL_EXPORTER_OTLP_ENDPOINT (base endpoint for all signals)\n"
                "  - OTEL_EXPORTER_OTLP_TRACES_ENDPOINT (traces only)\n"
                "  - OTEL_EXPORTER_OTLP_METRICS_ENDPOINT (metrics only)\n"
                "Example: OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317"
            )

        # OTLP protocols - base and signal-specific
        otel_protocol = os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc").lower()
        # Normalize http/protobuf to http (OTEL spec allows both forms)
        if otel_protocol == "http/protobuf":
            otel_protocol = "http"
        if otel_protocol not in ("grpc", "http"):
            raise ValueError(
                f"Invalid OTEL_EXPORTER_OTLP_PROTOCOL: {otel_protocol}. "
                "Must be 'grpc' or 'http' (or 'http/protobuf')."
            )

        # Signal-specific protocols (optional)
        otel_traces_protocol = os.getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
        if otel_traces_protocol:
            otel_traces_protocol = otel_traces_protocol.lower()
            # Normalize http/protobuf to http (OTEL spec allows both forms)
            if otel_traces_protocol == "http/protobuf":
                otel_traces_protocol = "http"
            if otel_traces_protocol not in ("grpc", "http"):
                raise ValueError(
                    f"Invalid OTEL_EXPORTER_OTLP_TRACES_PROTOCOL: {otel_traces_protocol}. "
                    "Must be 'grpc' or 'http' (or 'http/protobuf')."
                )

        otel_metrics_protocol = os.getenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL")
        if otel_metrics_protocol:
            otel_metrics_protocol = otel_metrics_protocol.lower()
            # Normalize http/protobuf to http (OTEL spec allows both forms)
            if otel_metrics_protocol == "http/protobuf":
                otel_metrics_protocol = "http"
            if otel_metrics_protocol not in ("grpc", "http"):
                raise ValueError(
                    f"Invalid OTEL_EXPORTER_OTLP_METRICS_PROTOCOL: {otel_metrics_protocol}. "
                    "Must be 'grpc' or 'http' (or 'http/protobuf')."
                )

        otel_service_name = os.getenv("OTEL_SERVICE_NAME", "netflow-to-traces")
        otel_service_version = os.getenv("OTEL_SERVICE_VERSION", "0.1.0")

        # Logging
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError(
                f"Invalid LOG_LEVEL: {log_level}. "
                "Must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL"
            )

        return cls(
            netflow_listen_host=netflow_listen_host,
            netflow_listen_port=netflow_listen_port,
            otel_exporter_endpoint=otel_exporter_endpoint,
            otel_exporter_protocol=otel_protocol,
            otel_service_name=otel_service_name,
            otel_service_version=otel_service_version,
            otel_traces_endpoint=otel_traces_endpoint,
            otel_traces_protocol=otel_traces_protocol,
            otel_metrics_endpoint=otel_metrics_endpoint,
            otel_metrics_protocol=otel_metrics_protocol,
            log_level=log_level,
        )

    def setup_logging(self) -> None:
        """Configure logging based on LOG_LEVEL setting."""
        logging.basicConfig(
            level=getattr(logging, self.log_level),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def __str__(self) -> str:
        """Return string representation with sensitive info masked."""
        return (
            f"Config(\n"
            f"  netflow_listen_host={self.netflow_listen_host}\n"
            f"  netflow_listen_port={self.netflow_listen_port}\n"
            f"  otel_exporter_endpoint={self.otel_exporter_endpoint}\n"
            f"  otel_exporter_protocol={self.otel_exporter_protocol}\n"
            f"  otel_service_name={self.otel_service_name}\n"
            f"  otel_service_version={self.otel_service_version}\n"
            f"  log_level={self.log_level}\n"
            f")"
        )

    def resource_attributes(self) -> dict[str, Any]:
        """Return OpenTelemetry resource attributes shared by all telemetry signals.

        Note: netflow.collector.* attributes are set as span attributes rather than
        resource attributes to allow better flexibility in querying and filtering.
        """
        return {
            "service.name": self.otel_service_name,
            "service.version": self.otel_service_version,
        }

    def get_traces_endpoint(self) -> str:
        """Get the effective traces endpoint (signal-specific or fallback to base).

        Returns:
            str: The endpoint URL for traces export.
        """
        return self.otel_traces_endpoint or self.otel_exporter_endpoint

    def get_traces_protocol(self) -> Literal["grpc", "http"]:
        """Get the effective traces protocol (signal-specific or fallback to base).

        Returns:
            str: The protocol for traces export ('grpc' or 'http').
        """
        return self.otel_traces_protocol or self.otel_exporter_protocol

    def get_metrics_endpoint(self) -> str:
        """Get the effective metrics endpoint (signal-specific or fallback to base).

        Returns:
            str: The endpoint URL for metrics export.
        """
        return self.otel_metrics_endpoint or self.otel_exporter_endpoint

    def get_metrics_protocol(self) -> Literal["grpc", "http"]:
        """Get the effective metrics protocol (signal-specific or fallback to base).

        Returns:
            str: The protocol for metrics export ('grpc' or 'http').
        """
        return self.otel_metrics_protocol or self.otel_exporter_protocol
