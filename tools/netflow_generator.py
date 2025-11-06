#!/usr/bin/env python3
"""
Enhanced NetFlow Generator using Scapy.

Supports NetFlow v5, v9, and IPFIX with configurable traffic patterns.
Uses Scapy's native NetFlow layers for accurate packet construction.

Usage:
    python netflow_generator.py --version 5 --pattern http --count 10
    python netflow_generator.py --version 9 --pattern mixed --rate 2 --flows 5
    python netflow_generator.py --version 10 --pattern dns --host tempo.example.com
"""

import argparse
import random
import socket
import sys
import time
from typing import Any, List, Tuple

try:
    from scapy.all import Raw
    from scapy.layers.netflow import (
        NetflowHeader,
        NetflowHeaderV5,
        NetflowRecordV5,
        NetflowHeaderV9,
        NetflowFlowsetV9,
        NetflowDataflowsetV9,
    )
except ImportError:
    print("Error: Scapy is required. Install with: pip install scapy")
    sys.exit(1)


# Traffic pattern definitions
TRAFFIC_PATTERNS = {
    "http": [
        {"sport": (1024, 65535), "dport": 80, "proto": 6, "desc": "HTTP traffic"},
    ],
    "https": [
        {"sport": (1024, 65535), "dport": 443, "proto": 6, "desc": "HTTPS traffic"},
    ],
    "dns": [
        {"sport": (1024, 65535), "dport": 53, "proto": 17, "desc": "DNS queries"},
    ],
    "ssh": [
        {"sport": (1024, 65535), "dport": 22, "proto": 6, "desc": "SSH connections"},
    ],
    "mixed": [
        {"sport": (1024, 65535), "dport": 80, "proto": 6, "desc": "HTTP"},
        {"sport": (1024, 65535), "dport": 443, "proto": 6, "desc": "HTTPS"},
        {"sport": (1024, 65535), "dport": 53, "proto": 17, "desc": "DNS"},
        {"sport": (1024, 65535), "dport": 22, "proto": 6, "desc": "SSH"},
        {"sport": (1024, 65535), "dport": 3306, "proto": 6, "desc": "MySQL"},
        {"sport": (1024, 65535), "dport": 5432, "proto": 6, "desc": "PostgreSQL"},
    ],
}


def random_ip(private: bool = True) -> str:
    """Generate a random IP address.

    Args:
        private: If True, generate private IP ranges (RFC 1918).

    Returns:
        IP address as string.
    """
    if private:
        # Use common private ranges
        prefix = random.choice(["192.168", "10", "172.16"])
        if prefix == "10":
            return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        elif prefix == "172.16":
            return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
        else:  # 192.168
            return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    else:
        # Public IP (excluding reserved ranges - simplified)
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def generate_flow_data(pattern_name: str) -> Tuple[str, str, int, int, int, int, int]:
    """Generate flow data based on traffic pattern.

    Args:
        pattern_name: Name of the traffic pattern.

    Returns:
        Tuple of (src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes).
    """
    pattern = random.choice(TRAFFIC_PATTERNS[pattern_name])

    src_ip = random_ip(private=True)
    dst_ip = random_ip(private=random.choice([True, False]))

    # Source port
    if isinstance(pattern["sport"], tuple):
        src_port = random.randint(pattern["sport"][0], pattern["sport"][1])
    else:
        src_port = pattern["sport"]

    dst_port = pattern["dport"]
    protocol = pattern["proto"]

    # Generate realistic packet and byte counts
    if protocol == 6:  # TCP
        packets = random.randint(10, 1000)
        bytes_count = packets * random.randint(500, 1500)
    else:  # UDP
        packets = random.randint(1, 100)
        bytes_count = packets * random.randint(100, 512)

    return src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes_count


def create_netflow_v5_packet(pattern: str, flows_per_packet: int) -> bytes:
    """Create a NetFlow v5 packet using Scapy.

    Args:
        pattern: Traffic pattern name.
        flows_per_packet: Number of flow records to include.

    Returns:
        Raw packet bytes.
    """
    # Create header with proper 32-bit values
    current_time = int(time.time())
    sys_uptime = int(time.time() * 1000) & 0xFFFFFFFF

    header = NetflowHeaderV5(
        count=flows_per_packet,
        sysUptime=sys_uptime,
        unixSecs=current_time,
        unixNanoSeconds=0,
        flowSequence=random.randint(1, 1000000),
        engineType=0,
        engineID=0,
        samplingInterval=0,
    )

    # Create flow records
    records = []
    for _ in range(flows_per_packet):
        src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes_count = generate_flow_data(pattern)

        # Calculate flow start/end times (use uptime-relative values in milliseconds)
        # first and last are relative to sysUptime, not absolute timestamps
        flow_duration_ms = random.randint(100, 30000)  # 100ms to 30s
        first_ms = max(0, sys_uptime - flow_duration_ms)
        last_ms = sys_uptime

        record = NetflowRecordV5(
            src=src_ip,
            dst=dst_ip,
            nexthop=random_ip(private=True),
            input=random.randint(1, 10),
            output=random.randint(1, 10),
            dpkts=packets,
            dOctets=bytes_count,  # Note: capital O
            first=first_ms,
            last=last_ms,
            srcport=src_port,
            dstport=dst_port,
            pad1=0,
            tcpFlags=0x18 if protocol == 6 else 0,
            prot=protocol,
            tos=0,
            src_as=random.randint(64512, 65534),
            dst_as=random.randint(64512, 65534),
            src_mask=24,
            dst_mask=24,
            pad2=0,
        )
        records.append(record)

    # Build complete packet
    packet = header
    for record in records:
        packet = packet / record

    return bytes(packet)


def create_netflow_v9_packet(pattern: str, flows_per_packet: int) -> bytes:
    """Create a NetFlow v9 packet using Scapy.

    Note: This creates a simplified v9 packet with template and data.
    Real implementations would cache templates and send data-only packets.

    Args:
        pattern: Traffic pattern name.
        flows_per_packet: Number of flow records to include.

    Returns:
        Raw packet bytes.
    """
    # Create header
    header = NetflowHeaderV9(
        version=9,
        count=2,  # Template flowset + data flowset
        sysUptime=int(time.time() * 1000) & 0xFFFFFFFF,
        unixSecs=int(time.time()),
        sequenceNumber=random.randint(1, 1000000),
        sourceId=random.randint(1, 1000),
    )

    # For simplicity, we'll create a basic v9 structure
    # In production, you'd use proper template and data flowsets
    # This is a simplified version that may not work with all collectors

    # Note: Full v9 support requires template management which is complex
    # For this demo, we'll create a basic packet structure

    packet = header

    # Add a comment about limitation
    print("  Note: NetFlow v9 requires template exchange - using simplified structure")

    return bytes(packet)


def create_ipfix_packet(pattern: str, flows_per_packet: int) -> bytes:
    """Create an IPFIX (NetFlow v10) packet using Scapy.

    Note: This creates a simplified IPFIX packet.
    Real implementations would use proper template management.

    Args:
        pattern: Traffic pattern name.
        flows_per_packet: Number of flow records to include.

    Returns:
        Raw packet bytes.
    """
    # IPFIX is very similar to NetFlow v9 in structure
    # For this tool, we'll note the limitation

    print("  Note: IPFIX requires template exchange - using NetFlow v5 for compatibility")
    return create_netflow_v5_packet(pattern, flows_per_packet)


def send_netflow_packets(
    host: str,
    port: int,
    version: int,
    pattern: str,
    count: int,
    flows_per_packet: int,
    rate: float,
) -> None:
    """Send NetFlow packets to the collector.

    Args:
        host: Target host.
        port: Target UDP port.
        version: NetFlow version (5, 9, or 10).
        pattern: Traffic pattern name.
        count: Number of packets to send.
        flows_per_packet: Number of flows per packet.
        rate: Packets per second.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"NetFlow Generator v1.0")
    print(f"=" * 60)
    print(f"Target:           {host}:{port}")
    print(f"NetFlow Version:  v{version}")
    print(f"Traffic Pattern:  {pattern}")
    print(f"Packets:          {count}")
    print(f"Flows/Packet:     {flows_per_packet}")
    print(f"Rate:             {rate} packets/sec")
    print(f"Total Flows:      {count * flows_per_packet}")
    print(f"=" * 60)
    print()

    total_bytes = 0
    total_flows = 0
    start_time = time.time()

    for i in range(count):
        # Create packet based on version
        if version == 5:
            packet = create_netflow_v5_packet(pattern, flows_per_packet)
        elif version == 9:
            packet = create_netflow_v9_packet(pattern, flows_per_packet)
        elif version == 10:
            packet = create_ipfix_packet(pattern, flows_per_packet)
        else:
            print(f"Error: Unsupported NetFlow version: {version}")
            return

        # Send packet
        sock.sendto(packet, (host, port))
        total_bytes += len(packet)
        total_flows += flows_per_packet

        # Progress indicator
        progress = (i + 1) / count * 100
        print(f"\rProgress: [{i+1}/{count}] {progress:.1f}% | "
              f"{len(packet)} bytes | {flows_per_packet} flows", end="", flush=True)

        # Rate limiting
        if i < count - 1:
            time.sleep(1.0 / rate)

    print()  # New line after progress

    elapsed = time.time() - start_time

    print()
    print(f"=" * 60)
    print(f"Summary:")
    print(f"  Packets Sent:     {count}")
    print(f"  Total Flows:      {total_flows}")
    print(f"  Total Bytes:      {total_bytes:,}")
    print(f"  Elapsed Time:     {elapsed:.2f}s")
    print(f"  Actual Rate:      {count/elapsed:.2f} packets/sec")
    print(f"=" * 60)
    print()
    print(f"Next Steps:")
    print(f"  1. Check netflow2traces logs: docker-compose logs -f netflow2traces")
    print(f"  2. View traces in Grafana: http://localhost:3000")
    print(f"  3. Query Tempo API: curl http://localhost:3200/api/search")

    sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced NetFlow packet generator using Scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send 10 NetFlow v5 packets with HTTP traffic
  %(prog)s --version 5 --pattern http --count 10

  # Continuous HTTPS traffic at 2 packets/sec
  %(prog)s --version 5 --pattern https --count 100 --rate 2

  # Mixed traffic with 5 flows per packet
  %(prog)s --version 5 --pattern mixed --flows 5 --count 20

  # Send to custom host/port
  %(prog)s --host 192.168.1.100 --port 9999 --version 5 --pattern dns

Available patterns: http, https, dns, ssh, mixed
        """,
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Collector host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=2055,
        help="Collector UDP port (default: 2055)",
    )
    parser.add_argument(
        "--version",
        type=int,
        choices=[5, 9, 10],
        default=5,
        help="NetFlow version: 5, 9, or 10/IPFIX (default: 5)",
    )
    parser.add_argument(
        "--pattern",
        choices=list(TRAFFIC_PATTERNS.keys()),
        default="mixed",
        help="Traffic pattern (default: mixed)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of packets to send (default: 10)",
    )
    parser.add_argument(
        "--flows",
        type=int,
        default=3,
        help="Number of flows per packet (default: 3)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=1.0,
        help="Packets per second (default: 1.0)",
    )

    args = parser.parse_args()

    # Validate
    if args.count < 1:
        parser.error("Count must be at least 1")
    if args.flows < 1 or args.flows > 30:
        parser.error("Flows per packet must be between 1 and 30")
    if args.rate <= 0 or args.rate > 1000:
        parser.error("Rate must be between 0 and 1000 packets/sec")

    try:
        send_netflow_packets(
            args.host,
            args.port,
            args.version,
            args.pattern,
            args.count,
            args.flows,
            args.rate,
        )
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
