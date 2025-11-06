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
from scapy.layers.netflow import NetflowSession

from .config import Config
from .metrics import CollectorMetrics
from .utils import build_flow_attributes, format_bytes

logger = logging.getLogger(__name__)


class NetflowCollector:
    """Collects NetFlow packets and converts them to OpenTelemetry traces."""

    def __init__(
        self, config: Config, tracer: trace.Tracer, metrics: CollectorMetrics | None = None
    ):
        """Initialize the NetFlow collector.

        Args:
            config: Application configuration.
            tracer: OpenTelemetry tracer instance.
        """
        self.config = config
        self.tracer = tracer
        self.metrics = metrics
        self.sock: socket.socket | None = None
        self.session = NetflowSession()
        self.running = False
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
        self.running = True
        logger.info("NetFlow collector started. Waiting for packets...")

        while self.running:
            try:
                # Safety check for socket closure during shutdown
                if self.sock is None:
                    break

                # Receive UDP packet
                data, addr = self.sock.recvfrom(65535)  # Max UDP packet size
                self.packet_count += 1
                if self.metrics:
                    self.metrics.record_packet(len(data))

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
                if self.metrics:
                    self.metrics.record_error()
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
                    # Exporter information
                    "netflow.exporter.address": exporter_ip,
                    "netflow.exporter.port": exporter_port,
                    "netflow.packet.size_bytes": len(data),
                    # Collector information (moved from resource attributes)
                    "netflow.collector.host": self.config.netflow_listen_host,
                    "netflow.collector.port": self.config.netflow_listen_port,
                    "netflow.collector.protocol": "udp",
                }
            )

            try:
                # Add dedicated parsing span to capture parsing latency
                with self.tracer.start_as_current_span("netflow.parse_packet") as parse_span:
                    parse_span.set_attribute("netflow.packet.size_bytes", len(data))

                    # Parse with Scapy
                    parsed = self._parse_netflow(data)

                    if parsed is None:
                        parse_span.set_status(Status(StatusCode.ERROR, "Parse failed"))
                        export_span.set_status(Status(StatusCode.ERROR, "Failed to parse packet"))
                        if self.metrics:
                            self.metrics.record_error()
                        return

                    # Extract version and record in parse span
                    netflow_version = self._get_netflow_version(parsed)
                    parse_span.set_attribute("netflow.version", netflow_version)
                    parse_span.set_status(Status(StatusCode.OK))

                # Extract flow records
                flows = self._extract_flows(parsed, netflow_version)

                export_span.set_attributes(
                    {
                        "netflow.version": netflow_version,
                        "netflow.flow.count": len(flows),
                    }
                )

                if self.metrics:
                    self.metrics.record_flows(len(flows))

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
                if self.metrics:
                    self.metrics.record_error()

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

            # For NetFlow v9/IPFIX, use session to persist templates across packets
            if hasattr(netflow_pkt, "version") and netflow_pkt.version in (9, 10):
                # Process through session to cache templates and reconstruct records
                processed = self.session.process(netflow_pkt)
                return processed if processed else netflow_pkt

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

        # Debug logging to identify packet structure
        logger.debug(f"Extracting flows from NetFlow v{version} packet")
        logger.debug(f"Packet type: {type(packet).__name__}")
        logger.debug(f"Packet attributes: {[attr for attr in dir(packet) if not attr.startswith('_')]}")

        # NetFlow v5 - flow records are accessible via iteration or fields
        if version == 5:
            # Try multiple approaches to extract NetFlow v5 records
            # Approach 1: Check if packet is iterable (Scapy packets can be iterated)
            try:
                # NetFlow v5 header has a count field, and records follow
                if hasattr(packet, "count") and hasattr(packet, "getlayer"):
                    count = packet.count
                    logger.debug(f"NetFlow v5 packet reports {count} flow(s)")

                    # Try to get NetflowRecordV5 layers
                    from scapy.layers.netflow import NetflowRecordV5
                    layer = packet.getlayer(NetflowRecordV5)
                    while layer:
                        flows.append(layer)
                        layer = layer.payload.getlayer(NetflowRecordV5) if layer.payload else None

                    logger.debug(f"Extracted {len(flows)} flows via getlayer(NetflowRecordV5)")

                # Approach 2: Check if has 'records' attribute (alternate field name)
                elif hasattr(packet, "records"):
                    flows = packet.records if isinstance(packet.records, list) else [packet.records]
                    logger.debug(f"Found {len(flows)} flow(s) in 'records' field")

                # Approach 3: Try iterating through packet layers
                elif hasattr(packet, "layers"):
                    layer_list = packet.layers()
                    logger.debug(f"Packet has {len(layer_list)} layers: {[l.name for l in layer_list]}")
                    for layer in layer_list:
                        if "NetflowRecord" in layer.name:
                            flows.append(layer)
            except Exception as e:
                logger.error(f"Error extracting v5 flows: {e}", exc_info=True)

            if len(flows) == 0:
                logger.warning(f"NetFlow v5 packet missing flows. Packet type: {type(packet).__name__}")

        # NetFlow v9/IPFIX - records are in flowsets
        elif version in (9, 10):
            logger.debug("Processing NetFlow v9/IPFIX packet structure")
            # Walk through the packet structure to find data flowsets
            layer = packet
            layer_count = 0
            while layer:
                layer_count += 1
                logger.debug(f"Layer {layer_count}: {type(layer).__name__}")

                if hasattr(layer, "templates"):
                    # Skip template flowsets
                    logger.debug("  - Has templates (skipping)")
                    pass
                elif hasattr(layer, "records"):
                    # Data flowset with records
                    records = layer.records if isinstance(layer.records, list) else [layer.records]
                    flows.extend(records)
                    logger.debug(f"  - Found {len(records)} record(s) in 'records' field")
                elif hasattr(layer, "flowsets"):
                    # Process flowsets
                    logger.debug(f"  - Has flowsets: {len(layer.flowsets)}")
                    for idx, flowset in enumerate(layer.flowsets):
                        logger.debug(f"    Flowset {idx}: {type(flowset).__name__}")
                        if hasattr(flowset, "records"):
                            records = flowset.records
                            record_list = records if isinstance(records, list) else [records]
                            flows.extend(record_list)
                            logger.debug(f"      - Found {len(record_list)} record(s)")

                # Move to next layer
                layer = layer.payload if hasattr(layer, "payload") else None

        # NetFlow v1 - similar to v5
        elif version == 1:
            if hasattr(packet, "records"):
                flows = packet.records if isinstance(packet.records, list) else [packet.records]
                logger.debug(f"Found {len(flows)} flow(s) in 'records' field")
            else:
                logger.warning(f"NetFlow v1 packet missing 'records' attribute. Available: {dir(packet)}")

        logger.debug(f"Total flows extracted: {len(flows)}")
        if len(flows) == 0:
            logger.warning(f"No flows extracted from NetFlow v{version} packet. Packet structure may be unexpected.")

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
                    # Extract and set span attributes
                    attributes = build_flow_attributes(flow, netflow_version)

                    # Build span name with low cardinality (per OTEL recommendations)
                    # Format: "ipflow {protocol} {src} → {dst}"
                    src_addr = attributes.get("source.address", "unknown")
                    dst_addr = attributes.get("destination.address", "unknown")
                    protocol = attributes.get("network.protocol.name", "unknown")

                    # Include ports only for TCP/UDP to keep cardinality manageable
                    if protocol in ("tcp", "udp"):
                        src_port = attributes.get("source.port", "")
                        dst_port = attributes.get("destination.port", "")
                        span_name = f"ipflow {protocol} {src_addr}:{src_port} → {dst_addr}:{dst_port}"
                    else:
                        span_name = f"ipflow {protocol} {src_addr} → {dst_addr}"

                    # Create span with INTERNAL kind (flow observations are not client/server operations)
                    with self.tracer.start_as_current_span(
                        span_name,
                        kind=trace.SpanKind.INTERNAL
                    ) as flow_span:
                        flow_span.set_attributes(attributes)
                        flow_span.set_attribute("flow.index", i)

                        self.flow_count += 1

                        # Log flow details at debug level
                        if logger.isEnabledFor(logging.DEBUG):
                            bytes_val = attributes.get("flow.bytes", 0)
                            duration = attributes.get("flow.duration_ms")
                            duration_str = f", duration: {duration}ms" if duration is not None else ""
                            logger.debug(
                                f"Flow {i}: {src_addr} → {dst_addr} ({protocol}) - "
                                f"{format_bytes(bytes_val)}{duration_str}"
                            )

                except Exception as e:
                    logger.error(f"Error processing flow {i}: {e}", exc_info=True)
                    continue

    def stop(self) -> None:
        """Stop the collector and close the socket."""
        # Signal the listen loop to stop
        self.running = False

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
