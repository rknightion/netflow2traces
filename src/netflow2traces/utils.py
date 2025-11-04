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

    if src_addr:
        attributes["source.address"] = str(src_addr)
    if dst_addr:
        attributes["destination.address"] = str(dst_addr)

    # Ports
    src_port = safe_get_field(flow, "srcport", None)
    dst_port = safe_get_field(flow, "dstport", None)

    if src_port:
        attributes["source.port"] = int(src_port)
    if dst_port:
        attributes["destination.port"] = int(dst_port)

    # Protocol
    protocol = safe_get_field(flow, "prot", None)
    if protocol is not None:
        protocol_num = int(protocol)
        attributes["network.transport"] = get_protocol_name(protocol_num)
        attributes["network.protocol.number"] = protocol_num

    # Flow metrics
    bytes_in = safe_get_field(flow, "dOctets", None) or safe_get_field(flow, "in_bytes", None)
    packets_in = safe_get_field(flow, "dPkts", None) or safe_get_field(flow, "in_pkts", None)

    if bytes_in is not None:
        attributes["netflow.flow.bytes"] = int(bytes_in)
    if packets_in is not None:
        attributes["netflow.flow.packets"] = int(packets_in)

    # Next hop router
    next_hop = safe_get_field(flow, "nexthop", None)
    if next_hop:
        attributes["netflow.nexthop"] = str(next_hop)

    # Input/Output interface indices
    input_iface = safe_get_field(flow, "input", None)
    output_iface = safe_get_field(flow, "output", None)

    if input_iface is not None:
        attributes["netflow.interface.input"] = int(input_iface)
    if output_iface is not None:
        attributes["netflow.interface.output"] = int(output_iface)

    # Type of Service (TOS)
    tos = safe_get_field(flow, "tos", None)
    if tos is not None:
        attributes["netflow.tos"] = int(tos)

    # TCP flags
    tcp_flags = safe_get_field(flow, "tcp_flags", None)
    if tcp_flags is not None:
        attributes["netflow.tcp_flags"] = int(tcp_flags)

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
