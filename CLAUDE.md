# NetFlow to OpenTelemetry Traces - Architecture & Development Guide

## Project Overview

**netflow2traces** is a Python application that listens for NetFlow/IPFIX network flow data via UDP and converts it into OpenTelemetry traces. This enables high-cardinality network traffic monitoring by leveraging trace-based observability instead of metric-based approaches.

### Key Value Proposition
- Converts network flows (NetFlow v1/v5/v9/IPFIX) into OTEL traces
- Bypasses metric cardinality limits in observability backends
- Sends to any OTLP-compatible collector (Grafana Tempo, Jaeger, Grafana Cloud, etc.)
- Provides network observability through modern distributed tracing

### Technology Stack
- **Language**: Python 3.14+
- **Dependency Management**: uv (with lockfile for reproducibility)
- **NetFlow Parsing**: Scapy (with automatic v9/IPFIX template handling)
- **Telemetry**: OpenTelemetry Python SDK with gRPC/HTTP OTLP exporters
- **Container**: Multi-stage Docker build with Python 3.14-slim
- **Demo Stack**: Grafana Tempo, Loki, Prometheus, Grafana, OpenTelemetry Collector

---

## Architecture Overview

### High-Level Data Flow

NetFlow Exporter sends UDP packets to netflow2traces, which parses them with Scapy, creates OpenTelemetry traces, and exports them via gRPC/HTTP OTLP to backends like Tempo, Jaeger, or Grafana Cloud.

### Trace Structure

One trace per NetFlow export packet:
- Root span: `netflow.export` (kind: INTERNAL)
  - Child span: `netflow.parse_packet` (kind: INTERNAL)
  - Child span: `netflow.process_flows` (kind: INTERNAL)
    - Child spans: `ipflow {protocol} {src} → {dst}` (kind: INTERNAL, one per flow record)
      - Example: `ipflow tcp 10.1.2.3:51528 → 10.9.8.7:443`
      - Each flow span includes: source/destination IP, port, protocol, bytes, packets, interfaces, AS numbers, etc.

**Span Naming Conventions:**
- Flow spans use descriptive names with protocol and endpoints for better observability
- Low cardinality maintained by using protocol names and addresses (not full 5-tuple in all cases)
- Ports included only for TCP/UDP flows to manage cardinality

### Span Attributes Reference

**Network Attributes (OpenTelemetry Semantic Conventions):**

*Stable:*
- `network.type` - Network layer type: "ipv4" or "ipv6" (auto-detected from address)
- `network.transport` - Transport protocol name: "tcp", "udp", "sctp" (ONLY for actual transport protocols, NOT ICMP/IGMP/etc)
- `network.interface.name` - Network interface name (formatted as "if{index}" from NetFlow interface index)
- `client.address`, `client.port` - Inferred client endpoint (port-based heuristics)
- `server.address`, `server.port` - Inferred server endpoint (well-known ports or port ≤1024)

*Development Status (packet/flow telemetry):*
- `source.address`, `source.port` - Flow source endpoint (always set)
- `destination.address`, `destination.port` - Flow destination endpoint (always set)
- `network.peer.address`, `network.peer.port` - Remote peer identification (typically destination)
- `network.protocol.name` - Protocol name (set for ALL protocols including ICMP)
- `network.protocol.number` - IANA protocol number

**Generic Flow Attributes (flow.* namespace):**
Custom attributes for flow telemetry, vendor-neutral:
- `flow.bytes` - Octets in flow (ideally should be metrics per OTEL guidance)
- `flow.packets` - Packet count in flow (ideally should be metrics per OTEL guidance)
- `flow.first_switched` - Flow start timestamp (uptime-relative milliseconds)
- `flow.last_switched` - Flow end timestamp (uptime-relative milliseconds)
- `flow.duration_ms` - Flow duration in milliseconds (calculated)
- `flow.index` - Flow record index in this export packet
- `flow.tos` - IP Type of Service byte
- `flow.tcp.flags` - TCP flags (for TCP flows only)

**NetFlow-Specific Attributes (netflow.* namespace):**
NetFlow protocol-specific fields:
- `netflow.version` - NetFlow version (1, 5, 9, or 10 for IPFIX)
- `netflow.nexthop` - Next hop router IP address
- `netflow.interface.input`, `netflow.interface.output` - SNMP interface indices (raw values)
- `netflow.src_as`, `netflow.dst_as` - Source/destination AS numbers
- `netflow.src_mask`, `netflow.dst_mask` - Source/destination netmask length

**Export Span Attributes (netflow.export):**
- `netflow.exporter.address`, `netflow.exporter.port` - NetFlow exporter endpoint
- `netflow.collector.host`, `netflow.collector.port`, `netflow.collector.protocol` - Collector info
- `netflow.packet.size_bytes` - Raw UDP packet size
- `netflow.flow.count` - Number of flows in this export
- `netflow.version` - NetFlow version

---

## Directory Structure

netflow2traces/
  src/netflow2traces/
    __init__.py - Package exports and version
    __main__.py - Entry point, signal handling, orchestration
    config.py - Environment variable configuration
    tracer.py - OpenTelemetry setup and management
    collector.py - UDP listener, Scapy parsing, trace creation
    utils.py - Protocol mappings, attribute builders
  
  demo/
    docker-compose.yml - Full LGTM stack
    .env, tempo/, loki/, grafana/, otel-collector/
  
  pyproject.toml - Dependencies and build config
  Dockerfile - Multi-stage production build
  .env.example - Configuration template
  README.md - User documentation
  test_netflow_sender.py - Test utility
  uv.lock - Reproducible dependency lock

---

## Key Module Responsibilities

### src/netflow2traces/__main__.py
Entry point handling app initialization, signal handling, and graceful shutdown.
1. Load config from environment (Config.from_env())
2. Setup logging
3. Register signal handlers for SIGINT/SIGTERM
4. Initialize TracerManager (OTEL exporter setup)
5. Initialize NetflowCollector (UDP listener)
6. Start blocking listen loop
7. On shutdown: stop collector, flush spans

### src/netflow2traces/config.py
Environment variable configuration via dataclass.
Config fields:
- netflow_listen_host (default: 0.0.0.0)
- netflow_listen_port (default: 2055)
- otel_exporter_endpoint (REQUIRED)
- otel_exporter_protocol (default: grpc)
- otel_service_name (default: netflow-to-traces)
- otel_service_version (default: 0.1.0)
- log_level (default: INFO)

Validates endpoint and protocol, provides setup_logging() method.

### src/netflow2traces/tracer.py
OpenTelemetry initialization and lifecycle management.
TracerManager class:
- setup(): Creates Resource, TracerProvider, OTLP exporter, BatchSpanProcessor
- _create_exporter(): Factory for gRPC/HTTP exporters (HTTP appends /v1/traces)
- shutdown(): Gracefully flushes pending spans

Resource attributes attached to all spans:
- service.name, service.version

Note: Collector information (host, port, protocol) is set as span attributes on the root export span rather than resource attributes for better query flexibility.

### src/netflow2traces/collector.py
UDP listener, NetFlow parsing, trace creation.
Key methods:
- start(): Binds UDP socket, enters listen loop
- _listen_loop(): Main event loop receiving packets
- _process_packet(): Creates trace span, parses packet, processes flows
- _parse_netflow(): Uses Scapy to parse raw UDP data
- _get_netflow_version(): Extracts version (1, 5, 9, 10)
- _extract_flows(): Recursively extracts flow records
- _process_flows(): Creates child spans for each flow
- stop(): Closes socket, logs stats
- get_stats(): Returns packet_count, flow_count, error_count

### src/netflow2traces/utils.py
Protocol mappings and attribute extraction helpers.
Functions:
- get_protocol_name(num): Maps IANA protocol numbers to names
- safe_get_field(obj, field, default): Safe field extraction from Scapy objects
- build_flow_attributes(flow, version): Main workhorse - extracts all span attributes
- format_bytes(count): Human-readable byte formatting

---

## Development Commands

### Installation & Setup
uv sync
uv sync --extra dev
source .venv/bin/activate

### Running the Application
uv run python -m netflow2traces
python -m netflow2traces
netflow2traces
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 python -m netflow2traces

### Testing
pytest --cov=netflow2traces
pytest tests/test_collector.py -v

### Code Quality
ruff check src/
ruff format src/

### Dependency Management
uv add package-name
uv add --dev package-name
uv lock --upgrade
uv sync

### Docker & Containerization
docker build -t netflow2traces:latest .
docker run --rm -p 2055:2055/udp netflow2traces:latest
cd demo && docker-compose up -d
docker-compose logs -f netflow2traces
docker-compose down

### Testing with Sample Data
python test_netflow_sender.py --host 127.0.0.1 --port 2055 --count 10

---

## Configuration

### Environment Variables

| Variable | Required | Default | Example |
|----------|----------|---------|---------|
| NETFLOW_LISTEN_HOST | No | 0.0.0.0 | 0.0.0.0 |
| NETFLOW_LISTEN_PORT | No | 2055 | 2055 |
| OTEL_EXPORTER_OTLP_ENDPOINT | YES | - | http://localhost:4317 |
| OTEL_EXPORTER_OTLP_PROTOCOL | No | grpc | grpc or http |
| OTEL_SERVICE_NAME | No | netflow-to-traces | custom-name |
| OTEL_SERVICE_VERSION | No | 0.1.0 | 1.0.0 |
| LOG_LEVEL | No | INFO | DEBUG, INFO, WARNING, ERROR, CRITICAL |

### Configuration Methods

1. Environment Variables (Direct)
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
python -m netflow2traces

2. .env File
cp .env.example .env
Edit .env with values
python -m netflow2traces

3. Docker Environment
docker run -e OTEL_EXPORTER_OTLP_ENDPOINT=http://tempo:4317 netflow2traces

4. Docker Compose
Set environment in demo/docker-compose.yml

### Example Configurations

Local Development (Tempo gRPC):
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
OTEL_EXPORTER_OTLP_PROTOCOL=grpc
LOG_LEVEL=DEBUG

Docker Compose (Internal Service):
OTEL_EXPORTER_OTLP_ENDPOINT=http://tempo:4317
OTEL_EXPORTER_OTLP_PROTOCOL=grpc
LOG_LEVEL=INFO
NETFLOW_LISTEN_HOST=0.0.0.0

Grafana Cloud (HTTPS):
OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp-gateway-prod-us-central-0.grafana.net/otlp
OTEL_EXPORTER_OTLP_PROTOCOL=http
LOG_LEVEL=INFO

Jaeger (HTTP):
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger.example.com:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http
LOG_LEVEL=INFO

---

## Special Conventions & Architectural Decisions

1. One Trace Per Export Packet
Each NetFlow export packet becomes one trace. Groups all flows from a single packet.
Why: Maintains causality and temporal locality. Atomic exports.

2. Child Spans for Flow Records
Each flow record is a child span under netflow.process_flows.
Why: Allows querying by individual flow attributes while maintaining packet context.

3. OpenTelemetry Semantic Conventions - Dual Attribution
Network attributes follow OTEL standard conventions with both:
- Development status: source.*/destination.* (for packet/flow data)
- Stable status: client.*/server.* (inferred from ports)
- Network peer: network.peer.* (remote endpoint)
Why: Interoperability with standard OTEL tooling and future-proofing.

4. Client/Server Inference from Ports
Heuristic logic infers client/server roles:
- Destination port ≤ 1024 and source port > 1024 → client-to-server
- Common server ports (80, 443, 3306, etc.) → identifies server
- Both high ports or both low ports → no inference, only source/dest
Why: Provides stable semantic conventions for better querying and compatibility.

5. Generic flow.* Namespace for Custom Attributes
Vendor-neutral namespace (flow.*) for generic flow telemetry attributes.
Examples: flow.bytes, flow.packets, flow.duration_ms, flow.tcp.flags, flow.tos
Why: Aligns with OTEL guidance for custom attributes, works for sFlow/NetFlow/IPFIX.

6. NetFlow-Specific netflow.* Attributes
Namespace for NetFlow protocol-specific fields.
Examples: netflow.version, netflow.interface.input, netflow.src_as
Why: Distinguishes NetFlow-specific metadata from generic flow data.

7. Span Kind INTERNAL for Flow Observations
All spans use SpanKind.INTERNAL (not CLIENT/SERVER).
Why: Flow observations are passive monitoring, not active client/server operations per OTEL conventions.

8. Descriptive Span Naming with Cardinality Management
Flow spans named: "ipflow {protocol} {src}:{port} → {dst}:{port}"
Examples: "ipflow tcp 10.1.2.3:51528 → 10.9.8.7:443" or "ipflow icmp 10.1.2.3 → 10.9.8.7"
Why: Better observability and debugging while managing cardinality (ports only for TCP/UDP).

9. Network Type Detection (Stable)
Auto-detects and sets network.type = "ipv4" or "ipv6" from address format.
Why: Provides stable OTEL attribute for network layer type.

10. Transport Protocol Restrictions
network.transport ONLY set for actual transport protocols: tcp (6), udp (17), sctp (132).
NOT set for ICMP, IGMP, ESP, etc. (those only get network.protocol.name).
Why: Follows OTEL semantic conventions strictly - transport ≠ all protocols.

11. Network Interface Naming
Maps NetFlow interface indices to network.interface.name = "if{index}".
Why: Provides Development-status OTEL attribute for interface observation point.

12. Scapy for Parsing
Uses Scapy instead of custom binary parsing.
Why: Automatic v9/IPFIX template caching, version detection, well-maintained.

13. Automatic Field Name Normalization
safe_get_field() tries multiple field name variations.
Why: Handles Scapy version differences.

14. Graceful Shutdown
Signal handlers flush spans before exit.
Why: Prevents loss of in-flight traces.

15. BatchSpanProcessor
Groups spans into batches before export.
Why: Reduces endpoint requests, better performance, production standard.

16. Resource Attributes
All spans include service metadata (service.name, service.version only).
Collector-specific attributes are on spans for better query flexibility.
Why: Enables filtering by service, better cardinality management.

17. Error Handling & Status Codes
Spans have OK/ERROR status with messages.
Why: Identifies problematic packets for debugging.

18. Version Detection Fallback
Defaults to v5 if version unknown.
Why: Robustness - v5 is most common.

19. UDP Only (No Retransmission)
Collector is UDP-only.
Why: NetFlow standard, high-volume data tolerates loss.

20. Non-Root Docker Container
Runs as user netflow:1000.
Why: Security best practice.

21. Multi-Stage Docker Build
Separates builder from runtime.
Why: Reduces final image size.

22. Bytes/Packets as Span Attributes (Not Ideal)
flow.bytes and flow.packets are included as span attributes for correlation.
Note: Per OTEL guidance, these should ideally be metrics (hw.network.io, hw.network.packets).
Why: Provides immediate value while acknowledging metrics would be more scalable long-term.

---

## Span Lifecycle Example

When a NetFlow v5 packet with 2 TCP flows arrives:

1. _listen_loop() receives UDP data
   Creates Trace: netflow.export (kind: INTERNAL)
   Sets: exporter address/port, packet size, collector info

2. _process_packet() parses packet
   Creates span: netflow.parse_packet (kind: INTERNAL)
   Adds: netflow.version=5
   Export span adds: netflow.flow.count=2

3. _extract_flows() gets flow records via Scapy layer iteration
   _process_flows() creates spans for each:

   Span: "ipflow tcp 10.1.2.3:51528 → 10.9.8.7:443" (kind: INTERNAL, record 0)
   - source.address="10.1.2.3", source.port=51528
   - destination.address="10.9.8.7", destination.port=443
   - network.type="ipv4" (Stable)
   - network.transport="tcp" (Stable, only for transport protocols)
   - network.protocol.name="tcp", network.protocol.number=6
   - client.address="10.1.2.3", server.address="10.9.8.7" (inferred from ports)
   - network.peer.address="10.9.8.7"
   - network.interface.name="if0"
   - flow.bytes=12345, flow.packets=11 (custom namespace)
   - flow.duration_ms=1500
   - flow.index=0
   - netflow.version=5, netflow.interface.input=0

   Span: "ipflow tcp 192.168.1.10:443 → 192.168.1.20:52001" (kind: INTERNAL, record 1)
   - [same structure, different values]

4. All spans batch via BatchSpanProcessor and export to OTLP endpoint
5. Tempo backend receives, indexes by high-cardinality attributes, makes queryable

---

## Key Integration Points

### With OTLP Backends

1. Grafana Tempo - Excellent fit
   - High-cardinality design
   - gRPC/HTTP OTLP support
   - Built-in Grafana integration
   - Pushes metrics to Prometheus via remote write

2. Jaeger - Supported
   - Older but still OTLP compatible
   - Less suited for high-cardinality

3. Grafana Cloud - Production-ready
   - HTTPS endpoint
   - HTTP protocol recommended
   - otlp-gateway-prod-*.grafana.net/otlp

4. OpenTelemetry Collector
   - Central aggregation point
   - Routes to multiple backends
   - Sampling, filtering, transformations

### With NetFlow Exporters

1. Cisco IOS/IOS-XE
   flow exporter netflow-to-traces
    destination <host> 2055
    transport udp

2. Junos
   set services flow-monitoring version9 netflow-to-traces host <host>
   set services flow-monitoring version9 netflow-to-traces port 2055

3. Linux softflowd
   softflowd -i eth0 -n <host>:2055 -v 9

4. Any compatible NetFlow tool sending to configured host/port

---

## Common Troubleshooting Patterns

### Port Already in Use
OSError: [Errno 48] Address already in use

Solution:
lsof -i :2055
export NETFLOW_LISTEN_PORT=2056

### OTLP Endpoint Unreachable
Application starts but no spans appear.

Solution:
curl http://localhost:4317  # Test connectivity
LOG_LEVEL=DEBUG python -m netflow2traces  # Check logs

### Template Not Found (v9/IPFIX)
Normal\! NetFlow v9/IPFIX exporters send templates periodically.
Wait for template packets, then data packets. Scapy caches them.

### No Traces Appearing
Checklist:
1. Verify OTEL_EXPORTER_OTLP_ENDPOINT is set and reachable
2. Check NetFlow packets are being sent
3. Verify firewall allows UDP 2055
4. Check OTEL exporter can reach endpoint
5. Review DEBUG logs: LOG_LEVEL=DEBUG

---

## Performance Considerations

### High-Volume Deployments

1. Sampling - Consider for >1000 flows/sec
2. Batch Size - Default usually adequate
3. Memory - Scapy caches v9/IPFIX templates
4. Threading - Single-threaded collector, adequate for most
5. Network - gRPC more efficient than HTTP

### Optimization Tips

1. Use gRPC protocol
2. Ensure network-close OTEL endpoint
3. Monitor packet loss (logged on shutdown)
4. Pre-filter flows in exporter for very high volume

---

## Testing Strategy

### Unit Tests Location
tests/
  test_config.py
  test_tracer.py
  test_collector.py
  test_utils.py
  conftest.py

### Example Test Pattern
import pytest
from netflow2traces.utils import get_protocol_name

def test_protocol_mapping():
    assert get_protocol_name(6) == "tcp"
    assert get_protocol_name(17) == "udp"

### Integration Testing
cd demo && docker-compose up -d
python ../test_netflow_sender.py --count 10
curl http://localhost:3200/api/search

---

## Contributing Guidelines

1. Setup: uv sync --extra dev
2. Code Style: ruff check/format
3. Type Hints: Required
4. Tests: Include for new features
5. Logging: Use logger.debug()
6. Docstrings: Document public classes/functions

---

## References

- NetFlow v5 Format
- NetFlow v9 RFC 3954
- IPFIX RFC 7011
- OpenTelemetry Spec
- OpenTelemetry Semantic Conventions
- IANA Protocol Numbers
- Scapy Documentation
- Grafana Tempo Documentation
