"""Utility functions for NetFlow data processing.

Provides protocol mappings, field extraction helpers, and span attribute builders.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# IANA Protocol Numbers to Names
# Reference: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
PROTOCOL_NUMBERS = {
    1: "icmp",
    6: "tcp",
    17: "udp",
    41: "ipv6",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "ipv6-icmp",
    89: "ospf",
    132: "sctp",
}


def get_protocol_name(protocol_number: int) -> str:
    """Convert IANA protocol number to protocol name.

    Args:
        protocol_number: IANA protocol number.

    Returns:
        Protocol name (lowercase) or "unknown" if not found.
    """
    return PROTOCOL_NUMBERS.get(protocol_number, f"protocol-{protocol_number}")


def safe_get_field(flow: Any, field_name: str, default: Any = None) -> Any:
    """Safely extract a field from a NetFlow record.

    Args:
        flow: NetFlow flow record object.
        field_name: Name of the field to extract.
        default: Default value if field doesn't exist.

    Returns:
        Field value or default if not present.
    """
    try:
        value = getattr(flow, field_name, default)
        if value is None:
            return default
        return value
    except Exception as e:
        logger.debug(f"Error accessing field {field_name}: {e}")
        return default


def _is_common_server_port(port: int) -> bool:
    """Check if a port number is a common server port.

    Args:
        port: Port number to check.

    Returns:
        True if the port is a common server port.
    """
    # Common server ports (HTTP, HTTPS, SSH, DB, etc.)
    common_ports = {
        20, 21,      # FTP
        22,          # SSH
        23,          # Telnet
        25,          # SMTP
        53,          # DNS
        80,          # HTTP
        110,         # POP3
        143,         # IMAP
        443,         # HTTPS
        445,         # SMB
        3306,        # MySQL
        5432,        # PostgreSQL
        6379,        # Redis
        8080,        # HTTP alternate
        8443,        # HTTPS alternate
        9090,        # Prometheus
        27017,       # MongoDB
    }
    return port in common_ports


def _detect_network_type(address: str) -> str | None:
    """Detect network type (ipv4 or ipv6) from address string.

    Args:
        address: IP address string.

    Returns:
        "ipv4", "ipv6", or None if cannot be determined.
    """
    if not address:
        return None

    # Simple heuristic: IPv6 contains colons, IPv4 contains dots
    if ":" in address:
        return "ipv6"
    elif "." in address:
        return "ipv4"
    return None


def _is_transport_protocol(protocol_num: int) -> bool:
    """Check if a protocol number represents a transport protocol.

    Transport protocols per OTEL conventions: TCP, UDP, SCTP, QUIC (not ICMP, IGMP, etc.)

    Args:
        protocol_num: IANA protocol number.

    Returns:
        True if it's a transport protocol.
    """
    # OTEL transport protocols: tcp, udp, sctp, quic, unix, pipe
    # For network flows, we only see: tcp (6), udp (17), sctp (132)
    # QUIC runs over UDP, so it would appear as UDP in NetFlow
    transport_protocols = {
        6,    # TCP
        17,   # UDP
        132,  # SCTP
    }
    return protocol_num in transport_protocols


def build_flow_attributes(flow: Any, netflow_version: int) -> dict[str, Any]:
    """Build OpenTelemetry span attributes from a NetFlow flow record.

    Extracts common fields and maps them to appropriate span attributes,
    following OpenTelemetry semantic conventions where applicable.

    Args:
        flow: NetFlow flow record from Scapy.
        netflow_version: NetFlow version (1, 5, 9, or 10 for IPFIX).

    Returns:
        Dictionary of span attributes.
    """
    attributes = {}

    # NetFlow metadata
    attributes["netflow.version"] = netflow_version

    # Network addresses - try both IPv4 and IPv6 field names
    src_addr = safe_get_field(flow, "src", None) or safe_get_field(flow, "srcaddr", None)
    dst_addr = safe_get_field(flow, "dst", None) or safe_get_field(flow, "dstaddr", None)

    # Always set source/destination (for packet-based flows)
    if src_addr:
        attributes["source.address"] = str(src_addr)
    if dst_addr:
        attributes["destination.address"] = str(dst_addr)

    # Network type detection (Stable) - detect from address format
    if src_addr:
        network_type = _detect_network_type(str(src_addr))
        if network_type:
            attributes["network.type"] = network_type

    # Ports
    src_port = safe_get_field(flow, "srcport", None)
    dst_port = safe_get_field(flow, "dstport", None)

    if src_port:
        attributes["source.port"] = int(src_port)
    if dst_port:
        attributes["destination.port"] = int(dst_port)

    # Infer client/server from ports (well-known ports <= 1024 are typically servers)
    # This follows OTEL stable semantic conventions for connection-based traffic
    if src_port is not None and dst_port is not None:
        src_port_int = int(src_port)
        dst_port_int = int(dst_port)

        # Heuristic: Well-known port (<=1024) or common service ports are servers
        if dst_port_int <= 1024 and src_port_int > 1024:
            # Typical client -> server pattern
            if src_addr:
                attributes["client.address"] = str(src_addr)
            attributes["client.port"] = src_port_int
            if dst_addr:
                attributes["server.address"] = str(dst_addr)
            attributes["server.port"] = dst_port_int
        elif src_port_int <= 1024 and dst_port_int > 1024:
            # Server -> client (response traffic)
            if src_addr:
                attributes["server.address"] = str(src_addr)
            attributes["server.port"] = src_port_int
            if dst_addr:
                attributes["client.address"] = str(dst_addr)
            attributes["client.port"] = dst_port_int
        elif _is_common_server_port(dst_port_int) and not _is_common_server_port(src_port_int):
            # Common server port heuristic (e.g., 80, 443, 3306, 5432)
            if src_addr:
                attributes["client.address"] = str(src_addr)
            attributes["client.port"] = src_port_int
            if dst_addr:
                attributes["server.address"] = str(dst_addr)
            attributes["server.port"] = dst_port_int
        # If both are high ports or both are low ports, don't infer client/server

    # Network peer attributes (destination is typically the remote peer)
    if dst_addr:
        attributes["network.peer.address"] = str(dst_addr)
    if dst_port:
        attributes["network.peer.port"] = int(dst_port)

    # Protocol
    protocol = safe_get_field(flow, "prot", None)
    if protocol is not None:
        protocol_num = int(protocol)
        protocol_name = get_protocol_name(protocol_num)

        # network.transport (Stable) - only for actual transport protocols
        # Per OTEL conventions: tcp, udp, sctp, quic, unix, pipe
        # Do NOT set for ICMP, IGMP, ESP, etc.
        if _is_transport_protocol(protocol_num):
            attributes["network.transport"] = protocol_name

        # network.protocol.name - set for all protocols (can be transport or other)
        attributes["network.protocol.name"] = protocol_name
        attributes["network.protocol.number"] = protocol_num

    # Flow metrics - use flow.* namespace for generic flow telemetry
    # Per OTEL guidance, bytes/packets ideally should be metrics, but we include as attributes
    bytes_in = safe_get_field(flow, "dOctets", None) or safe_get_field(flow, "in_bytes", None)
    packets_in = safe_get_field(flow, "dPkts", None) or safe_get_field(flow, "in_pkts", None)

    if bytes_in is not None:
        attributes["flow.bytes"] = int(bytes_in)
    if packets_in is not None:
        attributes["flow.packets"] = int(packets_in)

    # Next hop router
    next_hop = safe_get_field(flow, "nexthop", None)
    if next_hop:
        attributes["netflow.nexthop"] = str(next_hop)

    # Network interface (Development status)
    # NetFlow provides interface indices; we format as "if{index}" since we don't have name mappings
    input_iface = safe_get_field(flow, "input", None)
    output_iface = safe_get_field(flow, "output", None)

    if input_iface is not None:
        # Set network.interface.name for ingress interface (Development status)
        attributes["network.interface.name"] = f"if{int(input_iface)}"
        # Keep NetFlow-specific index for reference
        attributes["netflow.interface.input"] = int(input_iface)
    if output_iface is not None:
        # Keep NetFlow-specific output interface index
        attributes["netflow.interface.output"] = int(output_iface)

    # Type of Service (TOS) - use flow.* namespace
    tos = safe_get_field(flow, "tos", None)
    if tos is not None:
        attributes["flow.tos"] = int(tos)

    # TCP flags - use flow.tcp.flags namespace
    tcp_flags = safe_get_field(flow, "tcp_flags", None)
    if tcp_flags is not None:
        attributes["flow.tcp.flags"] = int(tcp_flags)

    # Source/Destination AS numbers
    src_as = safe_get_field(flow, "src_as", None)
    dst_as = safe_get_field(flow, "dst_as", None)

    if src_as is not None:
        attributes["netflow.src_as"] = int(src_as)
    if dst_as is not None:
        attributes["netflow.dst_as"] = int(dst_as)

    # Source/Destination mask
    src_mask = safe_get_field(flow, "src_mask", None)
    dst_mask = safe_get_field(flow, "dst_mask", None)

    if src_mask is not None:
        attributes["netflow.src_mask"] = int(src_mask)
    if dst_mask is not None:
        attributes["netflow.dst_mask"] = int(dst_mask)

    # Flow duration and timestamps - use flow.* namespace
    # NetFlow v5 uses: First (start time), Last (end time) as uptime milliseconds
    # NetFlow v9/IPFIX may use: flowStartMilliseconds, flowEndMilliseconds
    first_switched = safe_get_field(flow, "First", None) or safe_get_field(
        flow, "first_switched", None
    ) or safe_get_field(flow, "flowStartMilliseconds", None)
    last_switched = safe_get_field(flow, "Last", None) or safe_get_field(
        flow, "last_switched", None
    ) or safe_get_field(flow, "flowEndMilliseconds", None)

    if first_switched is not None:
        attributes["flow.first_switched"] = int(first_switched)
    if last_switched is not None:
        attributes["flow.last_switched"] = int(last_switched)

    # Calculate duration if both timestamps are available
    if first_switched is not None and last_switched is not None:
        duration_ms = int(last_switched) - int(first_switched)
        if duration_ms >= 0:  # Sanity check
            attributes["flow.duration_ms"] = duration_ms

    return attributes


def format_bytes(byte_count: int) -> str:
    """Format byte count in human-readable format.

    Args:
        byte_count: Number of bytes.

    Returns:
        Human-readable string (e.g., "1.5 MB").
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if byte_count < 1024.0:
            return f"{byte_count:.2f} {unit}"
        byte_count /= 1024.0
    return f"{byte_count:.2f} PB"
