#!/usr/bin/env python3
"""
Simple test script to generate and send NetFlow v5 packets to the collector.
This helps verify the application can receive and process NetFlow data.

Usage:
    python test_netflow_sender.py [--host HOST] [--port PORT] [--count COUNT]
"""

import argparse
import socket
import struct
import time


def create_netflow_v5_packet():
    """Create a simple NetFlow v5 packet with one flow record.

    Returns:
        bytes: Raw NetFlow v5 packet
    """
    # NetFlow v5 Header (24 bytes)
    version = 5
    count = 1  # Number of flow records
    sys_uptime = int(time.time() * 1000) & 0xFFFFFFFF
    unix_secs = int(time.time())
    unix_nsecs = 0
    flow_sequence = 1
    engine_type = 0
    engine_id = 0
    sampling_interval = 0

    header = struct.pack(
        "!HHIIIIBBH",
        version,
        count,
        sys_uptime,
        unix_secs,
        unix_nsecs,
        flow_sequence,
        engine_type,
        engine_id,
        sampling_interval,
    )

    # NetFlow v5 Flow Record (48 bytes)
    # Example: HTTP traffic from 192.168.1.100:52341 to 10.0.0.50:443
    src_addr = socket.inet_aton("192.168.1.100")
    dst_addr = socket.inet_aton("10.0.0.50")
    next_hop = socket.inet_aton("192.168.1.1")
    input_snmp = 2
    output_snmp = 5
    packets = 100
    octets = 150000
    first_switched = sys_uptime - 45000  # Flow started 45 seconds ago
    last_switched = sys_uptime
    src_port = 52341
    dst_port = 443
    pad1 = 0
    tcp_flags = 0x18  # ACK + PSH flags
    protocol = 6  # TCP
    tos = 0
    src_as = 65001
    dst_as = 65002
    src_mask = 24
    dst_mask = 24
    pad2 = 0

    record = struct.pack(
        "!4s4s4sHHIIIIHHBBBBHHBBH",
        src_addr,
        dst_addr,
        next_hop,
        input_snmp,
        output_snmp,
        packets,
        octets,
        first_switched,
        last_switched,
        src_port,
        dst_port,
        pad1,
        tcp_flags,
        protocol,
        tos,
        src_as,
        dst_as,
        src_mask,
        dst_mask,
        pad2,
    )

    return header + record


def send_netflow_packets(host, port, count):
    """Send NetFlow v5 packets to the collector.

    Args:
        host: Target host
        port: Target UDP port
        count: Number of packets to send
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"Sending {count} NetFlow v5 packet(s) to {host}:{port}")
    print(f"Flow: 192.168.1.100:52341 -> 10.0.0.50:443 (TCP)")
    print(f"Metrics: 100 packets, 150000 bytes")
    print()

    for i in range(count):
        packet = create_netflow_v5_packet()
        sock.sendto(packet, (host, port))
        print(f"Sent packet {i+1}/{count} ({len(packet)} bytes)")

        if i < count - 1:
            time.sleep(1)  # Wait 1 second between packets

    sock.close()
    print()
    print("Done! Check the netflow2traces logs for processing confirmation.")


def main():
    parser = argparse.ArgumentParser(
        description="Send test NetFlow v5 packets to netflow2traces collector"
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
        "--count",
        type=int,
        default=3,
        help="Number of packets to send (default: 3)",
    )

    args = parser.parse_args()
    send_netflow_packets(args.host, args.port, args.count)


if __name__ == "__main__":
    main()
