"""NetFlow collector that listens for NetFlow packets and creates OTEL traces.

Uses Scapy for NetFlow parsing with automatic template handling.
Creates one trace per NetFlow export packet with child spans for each flow record.
"""

import logging
import socket
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from scapy.all import NetflowHeader, NetflowHeaderV5, NetflowHeaderV9
from scapy.layers.netflow import NetflowSession, netflowv9_defragment

from .config import Config
from .utils import build_flow_attributes, format_bytes

logger = logging.getLogger(__name__)


class NetflowCollector:
    """Collects NetFlow packets and converts them to OpenTelemetry traces."""

    def __init__(self, config: Config, tracer: trace.Tracer):
        """Initialize the NetFlow collector.

        Args:
            config: Application configuration.
            tracer: OpenTelemetry tracer instance.
        """
        self.config = config
        self.tracer = tracer
        self.sock: socket.socket | None = None
        self.session = NetflowSession()
        self.packet_count = 0
        self.flow_count = 0
        self.error_count = 0

    def start(self) -> None:
        """Start the NetFlow collector UDP listener.

        Raises:
            OSError: If unable to bind to the configured port.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.sock.bind((self.config.netflow_listen_host, self.config.netflow_listen_port))
            logger.info(
                f"NetFlow collector listening on "
                f"{self.config.netflow_listen_host}:{self.config.netflow_listen_port}"
            )
        except OSError as e:
            logger.error(f"Failed to bind to port {self.config.netflow_listen_port}: {e}")
            raise

        self._listen_loop()

    def _listen_loop(self) -> None:
        """Main listening loop for NetFlow packets."""
        logger.info("NetFlow collector started. Waiting for packets...")

        while True:
            try:
                # Receive UDP packet
                data, addr = self.sock.recvfrom(65535)  # Max UDP packet size
                self.packet_count += 1

                logger.debug(
                    f"Received {len(data)} bytes from {addr[0]}:{addr[1]} "
                    f"(packet #{self.packet_count})"
                )

                # Process the packet
                self._process_packet(data, addr)

            except KeyboardInterrupt:
                logger.info("Received interrupt signal, stopping collector...")
                break
            except Exception as e:
                self.error_count += 1
                logger.error(f"Error processing packet: {e}", exc_info=True)
                continue

    def _process_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        """Process a NetFlow packet and create OpenTelemetry traces.

        Args:
            data: Raw UDP packet data.
            addr: Source address tuple (ip, port).
        """
        exporter_ip, exporter_port = addr

        # Create a trace for this NetFlow export
        with self.tracer.start_as_current_span("netflow.export") as export_span:
            export_span.set_attributes(
                {
                    "netflow.exporter.address": exporter_ip,
                    "netflow.exporter.port": exporter_port,
                    "netflow.packet.size_bytes": len(data),
                }
            )

            try:
                # Parse with Scapy
                parsed = self._parse_netflow(data)
                if parsed is None:
                    export_span.set_status(Status(StatusCode.ERROR, "Failed to parse packet"))
                    return

                # Extract NetFlow version and flow count
                netflow_version = self._get_netflow_version(parsed)
                flows = self._extract_flows(parsed, netflow_version)

                export_span.set_attributes(
                    {
                        "netflow.version": netflow_version,
                        "netflow.flow.count": len(flows),
                    }
                )

                logger.info(
                    f"Parsed NetFlow v{netflow_version} packet from {exporter_ip}: "
                    f"{len(flows)} flow(s)"
                )

                # Create spans for each flow record
                self._process_flows(flows, netflow_version)

                export_span.set_status(Status(StatusCode.OK))

            except Exception as e:
                error_msg = f"Error processing NetFlow packet: {e}"
                logger.error(error_msg, exc_info=True)
                export_span.set_status(Status(StatusCode.ERROR, error_msg))
                export_span.record_exception(e)

    def _parse_netflow(self, data: bytes) -> Any | None:
        """Parse raw NetFlow packet data using Scapy.

        Args:
            data: Raw UDP packet bytes.

        Returns:
            Parsed Scapy packet or None if parsing fails.
        """
        try:
            # Use Scapy's NetflowSession for automatic template handling
            from scapy.all import UDP, IP, Raw
            from scapy.layers.netflow import NetflowHeader

            # Wrap the data in a UDP packet structure for Scapy
            # Scapy needs context of IP/UDP layers for proper parsing
            raw_pkt = Raw(data)
            netflow_pkt = NetflowHeader(data)

            # For NetFlow v9/IPFIX, defragment to handle templates
            if hasattr(netflow_pkt, "version") and netflow_pkt.version in (9, 10):
                # Store and use session for template caching
                defragmented = netflowv9_defragment([netflow_pkt])
                if defragmented:
                    return defragmented[0]
                return netflow_pkt

            return netflow_pkt

        except Exception as e:
            logger.error(f"Failed to parse NetFlow packet: {e}", exc_info=True)
            return None

    def _get_netflow_version(self, packet: Any) -> int:
        """Extract NetFlow version from parsed packet.

        Args:
            packet: Parsed Scapy NetFlow packet.

        Returns:
            NetFlow version number (1, 5, 9, or 10 for IPFIX).
        """
        if hasattr(packet, "version"):
            return int(packet.version)
        # Try to infer from packet type
        if isinstance(packet, NetflowHeaderV5):
            return 5
        if isinstance(packet, NetflowHeaderV9):
            return 9
        # Default to version 5 (most common)
        logger.warning("Could not determine NetFlow version, assuming v5")
        return 5

    def _extract_flows(self, packet: Any, version: int) -> list[Any]:
        """Extract flow records from a NetFlow packet.

        Args:
            packet: Parsed Scapy NetFlow packet.
            version: NetFlow version number.

        Returns:
            List of flow records.
        """
        flows = []

        # NetFlow v5 - records are in 'records' field
        if version == 5 and hasattr(packet, "records"):
            flows = packet.records

        # NetFlow v9/IPFIX - records are in flowsets
        elif version in (9, 10):
            # Walk through the packet structure to find data flowsets
            layer = packet
            while layer:
                if hasattr(layer, "templates"):
                    # Skip template flowsets
                    pass
                elif hasattr(layer, "records"):
                    # Data flowset with records
                    flows.extend(layer.records if isinstance(layer.records, list) else [layer.records])
                elif hasattr(layer, "flowsets"):
                    # Process flowsets
                    for flowset in layer.flowsets:
                        if hasattr(flowset, "records"):
                            records = flowset.records
                            flows.extend(records if isinstance(records, list) else [records])

                # Move to next layer
                layer = layer.payload if hasattr(layer, "payload") else None

        # NetFlow v1 - similar to v5
        elif version == 1 and hasattr(packet, "records"):
            flows = packet.records

        return flows

    def _process_flows(self, flows: list[Any], netflow_version: int) -> None:
        """Create OpenTelemetry spans for each flow record.

        Args:
            flows: List of NetFlow flow records.
            netflow_version: NetFlow version number.
        """
        with self.tracer.start_as_current_span("netflow.process_flows") as process_span:
            process_span.set_attribute("netflow.flow.count", len(flows))

            for i, flow in enumerate(flows):
                try:
                    with self.tracer.start_as_current_span("netflow.flow") as flow_span:
                        # Extract and set span attributes
                        attributes = build_flow_attributes(flow, netflow_version)
                        flow_span.set_attributes(attributes)
                        flow_span.set_attribute("netflow.flow.index", i)

                        self.flow_count += 1

                        # Log flow details at debug level
                        if logger.isEnabledFor(logging.DEBUG):
                            src = attributes.get("source.address", "unknown")
                            dst = attributes.get("destination.address", "unknown")
                            proto = attributes.get("network.transport", "unknown")
                            bytes_val = attributes.get("netflow.flow.bytes", 0)
                            logger.debug(
                                f"Flow {i}: {src} -> {dst} ({proto}) - {format_bytes(bytes_val)}"
                            )

                except Exception as e:
                    logger.error(f"Error processing flow {i}: {e}", exc_info=True)
                    continue

    def stop(self) -> None:
        """Stop the collector and close the socket."""
        if self.sock:
            logger.info("Closing NetFlow collector socket...")
            self.sock.close()
            self.sock = None

        logger.info(
            f"NetFlow collector stopped. "
            f"Processed {self.packet_count} packets, {self.flow_count} flows, "
            f"{self.error_count} errors"
        )

    def get_stats(self) -> dict[str, int]:
        """Get collector statistics.

        Returns:
            Dictionary with packet_count, flow_count, and error_count.
        """
        return {
            "packet_count": self.packet_count,
            "flow_count": self.flow_count,
            "error_count": self.error_count,
        }
