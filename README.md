# NetFlow to OpenTelemetry Traces

A Python application that listens for NetFlow/IPFIX data and converts it to OpenTelemetry traces, enabling network flow observability in modern tracing systems.

## Overview

This application addresses the high cardinality challenge of NetFlow data by converting network flows into OpenTelemetry traces instead of metrics. This approach allows you to:

- Send NetFlow data to any OTLP-compatible backend (Jaeger, Tempo, Grafana Cloud, etc.)
- Bypass metric cardinality limits with trace-based analysis
- Leverage existing observability infrastructure for network monitoring
- Use resource attributes for efficient querying and filtering

### Architecture

```
NetFlow Exporter (Router/Switch)
         │ UDP NetFlow v1/v5/v9/IPFIX
         ▼
  netflow2traces (this app)
         │ Parses with Scapy
         │ Creates OTEL traces
         ▼
  OTLP Exporter (gRPC/HTTP)
         ▼
  OTLP Collector / Backend
  (Jaeger, Tempo, Grafana Cloud)
```

### Trace Structure

- **One trace per NetFlow export packet**
- Each flow record becomes a child span
- Spans include attributes: source/destination IPs, ports, protocols, bytes, packets
- Resource attributes identify the collector service

```
Trace: netflow.export
├─ Span: netflow.parse_packet
└─ Span: netflow.process_flows
   ├─ Span: netflow.flow (record 1)
   ├─ Span: netflow.flow (record 2)
   └─ Span: netflow.flow (record N)
```

## Features

- **Multi-version NetFlow support**: v1, v5, v9, IPFIX (v10)
- **Automatic template handling**: Scapy manages v9/IPFIX template caching
- **Configurable OTLP export**: gRPC or HTTP protocols
- **Semantic conventions**: Follows OpenTelemetry network conventions
- **Comprehensive logging**: DEBUG/INFO/WARNING/ERROR levels
- **Docker support**: Ready-to-run container with Tempo and Mimir for testing
- **Graceful shutdown**: Properly flushes pending spans on SIGTERM/SIGINT

## Requirements

- Python 3.13+ (targeting 3.14 in pyproject.toml)
- [uv](https://github.com/astral-sh/uv) for dependency management
- Docker and Docker Compose (for containerized deployment)

## Installation

### Using uv (recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/netflow2traces.git
cd netflow2traces

# Install dependencies from lockfile
uv sync

# Activate virtual environment (optional - uv commands work without activation)
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

**Note**: This project uses `uv.lock` for reproducible dependency installation. The `uv sync` command creates a virtual environment and installs all dependencies based on the lockfile.

### Using Docker

```bash
# Build the Docker image
docker build -t netflow2traces .

# Or use docker-compose
docker-compose up -d
```

## Configuration

All configuration is done via environment variables. Copy `.env.example` to `.env` and adjust as needed:

```bash
cp .env.example .env
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NETFLOW_LISTEN_HOST` | No | `0.0.0.0` | Host to bind UDP listener |
| `NETFLOW_LISTEN_PORT` | No | `2055` | UDP port for NetFlow packets |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | **Yes** | - | OTLP collector endpoint |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | No | `grpc` | Protocol: `grpc` or `http` |
| `OTEL_SERVICE_NAME` | No | `netflow-to-traces` | Service name in traces |
| `OTEL_SERVICE_VERSION` | No | `0.1.0` | Service version in traces |
| `LOG_LEVEL` | No | `INFO` | Logging level |

### Example Configurations

#### Local Development with Tempo

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
export LOG_LEVEL=DEBUG
```

#### Grafana Cloud

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp-gateway-prod-us-central-0.grafana.net/otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=http
export LOG_LEVEL=INFO
```

## Usage

### Running Directly

```bash
# Activate virtual environment
source .venv/bin/activate

# Set required environment variables
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317

# Run the application
python -m netflow2traces
```

### Running with Docker Compose

```bash
# Start netflow2traces, Tempo, and Mimir
docker-compose up -d

# View logs
docker-compose logs -f netflow2traces

# Access Tempo API
curl http://localhost:3200/api/search

# Stop services
docker-compose down
```

### Running as a Python Package

```bash
# After installation with pip/uv
netflow2traces
```

## Testing

### Generate Test NetFlow Data

#### Using softflowd

```bash
# Install softflowd (example for Ubuntu)
sudo apt-get install softflowd

# Generate NetFlow v9 data from an interface
sudo softflowd -i eth0 -n 127.0.0.1:2055 -v 9
```

#### Using nflow-generator

```bash
# Install nflow-generator
npm install -g nflow-generator

# Generate sample NetFlow v5 data
nflow-generator -t 127.0.0.1 -p 2055 -v 5
```

#### Using Python Scapy

```python
from scapy.all import *
from scapy.layers.netflow import *

# Create a simple NetFlow v5 packet
nf = NetflowHeaderV5(
    version=5,
    count=1,
    sysUptime=1000,
    unixSecs=int(time.time()),
    unixNanoSeconds=0,
    flowSequence=1
)

flow = NetflowRecordV5(
    src="192.168.1.100",
    dst="10.0.0.50",
    srcport=443,
    dstport=52341,
    prot=6,  # TCP
    dPkts=100,
    dOctets=150000
)

# Send to collector
send(IP(dst="127.0.0.1")/UDP(dport=2055)/(nf/flow))
```

## Viewing Traces

### Tempo (Local)

1. Start services: `docker-compose up -d`
2. Access Tempo API: http://localhost:3200
3. Query traces using the Tempo API:
   ```bash
   # Search for traces
   curl http://localhost:3200/api/search?tags=service.name=netflow-to-traces

   # Get a specific trace (replace TRACE_ID)
   curl http://localhost:3200/api/traces/TRACE_ID
   ```
4. Tempo metrics are pushed to Mimir at http://localhost:9009
5. For visualization, connect Grafana to Tempo and Mimir data sources

### Grafana Cloud

1. Configure `OTEL_EXPORTER_OTLP_ENDPOINT` with your Grafana Cloud endpoint
2. Navigate to Grafana → Explore → Tempo
3. Query by service name: `netflow-to-traces`

## Span Attributes

Each flow span includes the following attributes:

| Attribute | Description | Example |
|-----------|-------------|---------|
| `netflow.version` | NetFlow version | `9` |
| `source.address` | Source IP address | `192.168.1.100` |
| `source.port` | Source port | `443` |
| `destination.address` | Destination IP | `10.0.0.50` |
| `destination.port` | Destination port | `52341` |
| `network.transport` | Protocol name | `tcp` |
| `network.protocol.number` | IANA protocol number | `6` |
| `netflow.flow.bytes` | Bytes transferred | `150000` |
| `netflow.flow.packets` | Packets transferred | `100` |
| `netflow.nexthop` | Next hop router | `192.168.1.1` |
| `netflow.interface.input` | Input interface index | `2` |
| `netflow.interface.output` | Output interface index | `5` |
| `netflow.src_as` | Source AS number | `65001` |
| `netflow.dst_as` | Destination AS number | `65002` |

## Troubleshooting

### Port Already in Use

```
OSError: [Errno 48] Address already in use
```

**Solution**: Check if another process is using port 2055:

```bash
# Linux/Mac
sudo lsof -i :2055
sudo netstat -tulpn | grep 2055

# Change port in environment
export NETFLOW_LISTEN_PORT=2056
```

### No Traces Appearing

1. **Check NetFlow exporter configuration**: Ensure it's sending to the correct IP and port
2. **Verify OTLP endpoint**: Test with curl:
   ```bash
   curl http://localhost:4317
   ```
3. **Check logs**: Run with `LOG_LEVEL=DEBUG` to see detailed flow parsing
4. **Firewall**: Ensure UDP port 2055 is open

### Template Errors (v9/IPFIX)

```
Error parsing NetFlow packet: Template not found
```

**Solution**: This is normal for the first few packets. NetFlow v9/IPFIX exporters send templates periodically. The collector caches them automatically via Scapy's `NetflowSession`.

### Permission Denied

```
OSError: [Errno 13] Permission denied
```

**Solution**: Ports below 1024 require root/admin privileges:

```bash
# Use port above 1024
export NETFLOW_LISTEN_PORT=2055

# Or run with sudo (not recommended)
sudo -E python -m netflow2traces
```

## Development

### Running Tests

```bash
# Install with dev dependencies
uv sync --extra dev

# Run tests with coverage
pytest --cov=netflow2traces

# Run linter
ruff check src/
```

### Managing Dependencies

This project uses `uv` with a lockfile (`uv.lock`) for reproducible builds.

```bash
# Add a new dependency
uv add <package-name>

# Add a dev dependency
uv add --dev <package-name>

# Update all dependencies
uv lock --upgrade

# Update a specific package
uv lock --upgrade-package <package-name>

# Sync your environment after pulling changes
uv sync
```

The lockfile is committed to version control to ensure all developers and CI/CD use identical dependency versions.

### Code Style

This project uses:
- [Ruff](https://github.com/astral-sh/ruff) for linting and formatting
- Type hints throughout
- Python 3.14+ features

## Project Structure

```
netflow2traces/
├── src/netflow2traces/
│   ├── __init__.py       # Package initialization
│   ├── __main__.py       # Entry point with signal handling
│   ├── config.py         # Environment variable configuration
│   ├── tracer.py         # OpenTelemetry setup
│   ├── collector.py      # NetFlow listener and parser
│   └── utils.py          # Protocol mappings and helpers
├── pyproject.toml        # Project metadata and dependencies
├── Dockerfile            # Multi-stage Docker build
├── docker-compose.yml    # Docker Compose with Tempo and Mimir
├── tempo.yaml            # Tempo configuration
├── mimir.yaml            # Mimir configuration
├── .env.example          # Example configuration
├── .dockerignore         # Docker build exclusions
├── todo.txt              # Task tracking
└── README.md             # This file
```

## Performance Considerations

- **High volume deployments**: Consider sampling if processing thousands of flows per second
- **Batch processing**: Uses OpenTelemetry's `BatchSpanProcessor` for efficient export
- **Memory usage**: Scapy caches templates in memory for v9/IPFIX
- **UDP packet loss**: Normal for UDP; no retransmission mechanism

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run `ruff check` and `pytest`
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Acknowledgments

- [Scapy](https://scapy.net/) for NetFlow parsing
- [OpenTelemetry Python](https://github.com/open-telemetry/opentelemetry-python) for tracing
- [uv](https://github.com/astral-sh/uv) for fast dependency management

## References

- [NetFlow v5 Specification](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html)
- [NetFlow v9 Specification](https://tools.ietf.org/html/rfc3954)
- [IPFIX Specification](https://tools.ietf.org/html/rfc7011)
- [OpenTelemetry Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/)
- [IANA Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/)
