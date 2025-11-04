"""Configuration management for NetFlow to Traces application.

Loads configuration from environment variables with sensible defaults.
"""

import logging
import os
from dataclasses import dataclass
from typing import Literal


@dataclass
class Config:
    """Application configuration loaded from environment variables."""

    # NetFlow listener settings
    netflow_listen_host: str
    netflow_listen_port: int

    # OpenTelemetry settings
    otel_exporter_endpoint: str
    otel_exporter_protocol: Literal["grpc", "http"]
    otel_service_name: str
    otel_service_version: str

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

        # OpenTelemetry - endpoint is required
        otel_exporter_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        if not otel_exporter_endpoint:
            raise ValueError(
                "OTEL_EXPORTER_OTLP_ENDPOINT environment variable is required. "
                "Example: http://localhost:4317 (gRPC) or http://localhost:4318 (HTTP)"
            )

        # OTLP protocol
        otel_protocol = os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc").lower()
        if otel_protocol not in ("grpc", "http"):
            raise ValueError(
                f"Invalid OTEL_EXPORTER_OTLP_PROTOCOL: {otel_protocol}. "
                "Must be 'grpc' or 'http'."
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
