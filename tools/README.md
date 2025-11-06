# NetFlow Testing Tools

This directory contains tools for testing the netflow2traces application with various NetFlow data sources.

## Tools Overview

### 1. netflow_generator.py - Enhanced NetFlow Generator

A comprehensive Python script using Scapy to generate NetFlow v5, v9, and IPFIX packets with realistic traffic patterns.

**Features:**
- Supports NetFlow v5, v9, and IPFIX (v10)
- Multiple traffic patterns: HTTP, HTTPS, DNS, SSH, mixed
- Configurable flows per packet
- Rate limiting for controlled traffic generation
- Progress indicators and statistics
- Realistic IP addresses, ports, and traffic characteristics

**Requirements:**
- Python 3.8+
- Scapy (already installed with netflow2traces dependencies)

**Basic Usage:**

```bash
# Send 10 NetFlow v5 packets with HTTP traffic
python tools/netflow_generator.py --version 5 --pattern http --count 10

# Continuous HTTPS traffic at 2 packets/sec
python tools/netflow_generator.py --version 5 --pattern https --count 100 --rate 2

# Mixed traffic with 5 flows per packet
python tools/netflow_generator.py --version 5 --pattern mixed --flows 5 --count 20

# Send to custom host/port
python tools/netflow_generator.py --host 192.168.1.100 --port 9999 --version 5
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | 127.0.0.1 | Target collector host |
| `--port` | 2055 | Target UDP port |
| `--version` | 5 | NetFlow version (5, 9, or 10) |
| `--pattern` | mixed | Traffic pattern (http, https, dns, ssh, mixed) |
| `--count` | 10 | Number of packets to send |
| `--flows` | 3 | Number of flows per packet (1-30) |
| `--rate` | 1.0 | Packets per second |

**Traffic Patterns:**

- **http**: Web traffic on port 80
- **https**: Encrypted web traffic on port 443
- **dns**: DNS queries on port 53
- **ssh**: SSH connections on port 22
- **mixed**: Combination of HTTP, HTTPS, DNS, SSH, MySQL, PostgreSQL

**Examples:**

```bash
# Quick test with 5 packets
python tools/netflow_generator.py --count 5

# Simulate web server traffic (lots of HTTP/HTTPS)
python tools/netflow_generator.py --pattern mixed --count 50 --flows 10 --rate 5

# DNS-heavy traffic
python tools/netflow_generator.py --pattern dns --count 100 --rate 10

# Long-running demo traffic
python tools/netflow_generator.py --pattern mixed --count 1000 --rate 2
```

### 2. Docker NetFlow Generator (via docker-compose)

The demo environment includes an optional NetFlow generator service based on `networkstatic/nflow-generator`.

**Features:**
- Pre-built Docker container
- Continuous NetFlow v5 traffic generation
- Diverse traffic patterns (HTTP, SSH, SNMP, DNS, MySQL, etc.)
- Zero configuration required

**Usage:**

```bash
# Start demo environment WITH traffic generator
cd demo/
docker-compose --profile demo up -d

# Start demo environment WITHOUT generator (default)
docker-compose up -d

# View generator logs
docker-compose logs -f netflow-generator

# Stop generator only
docker-compose stop netflow-generator

# Restart generator
docker-compose restart netflow-generator
```

**Notes:**
- The generator is configured with the `demo` profile, so it's opt-in
- Automatically targets the netflow2traces service
- Generates traffic continuously until stopped
- Great for dashboard demos and long-running tests

## Testing Workflows

### Quick Smoke Test

Test that netflow2traces can receive and process NetFlow packets:

```bash
# 1. Start the demo environment
cd demo/
docker-compose up -d

# 2. Send a few test packets
cd ..
python tools/netflow_generator.py --count 5 --pattern http

# 3. Check logs for processing
docker-compose -f demo/docker-compose.yml logs netflow2traces | tail -20

# 4. View traces in Grafana
# Open http://localhost:3000 and explore Tempo
```

### Comprehensive Protocol Testing

Test all supported NetFlow versions:

```bash
# NetFlow v5
python tools/netflow_generator.py --version 5 --pattern mixed --count 10

# NetFlow v9 (note: requires template support)
python tools/netflow_generator.py --version 9 --pattern mixed --count 10

# IPFIX (NetFlow v10)
python tools/netflow_generator.py --version 10 --pattern mixed --count 10
```

### Performance Testing

Test with high-volume traffic:

```bash
# Sustained load: 10 flows/packet at 10 packets/sec for 5 minutes
python tools/netflow_generator.py \
  --pattern mixed \
  --flows 10 \
  --rate 10 \
  --count 3000

# Monitor collector stats in logs
docker-compose -f demo/docker-compose.yml logs -f netflow2traces
```

### Demo/Visualization Testing

Generate continuous traffic for dashboard demos:

```bash
# Option 1: Use Docker generator (easiest)
cd demo/
docker-compose --profile demo up -d

# Option 2: Use Python generator in background
python tools/netflow_generator.py --pattern mixed --count 1000 --rate 2 &

# Open Grafana and explore traces
open http://localhost:3000
```

### Pattern-Specific Testing

Test specific traffic scenarios:

```bash
# HTTP-only traffic (web server simulation)
python tools/netflow_generator.py --pattern http --count 20 --flows 8

# DNS traffic (DNS server simulation)
python tools/netflow_generator.py --pattern dns --count 50 --flows 5 --rate 5

# SSH connections (bastion host simulation)
python tools/netflow_generator.py --pattern ssh --count 15 --flows 2
```

## Verifying Results

### Check Collector Logs

```bash
# View recent logs
docker-compose -f demo/docker-compose.yml logs netflow2traces | tail -50

# Follow logs in real-time
docker-compose -f demo/docker-compose.yml logs -f netflow2traces

# Look for these indicators:
# - "Parsed NetFlow v5 packet from X.X.X.X: N flow(s)"
# - Packet count increasing
# - No error messages
```

### Query Tempo API

```bash
# Check Tempo is receiving traces
curl -s http://localhost:3200/api/search | jq .

# Search for recent traces (requires jq)
curl -s 'http://localhost:3200/api/search?limit=10' | jq '.traces[] | {traceID, spanSet}'
```

### Explore in Grafana

1. Open http://localhost:3000 (admin/admin)
2. Navigate to Explore
3. Select Tempo data source
4. Search for traces with:
   - Service Name: `netflow-to-traces`
   - Span Name: `netflow.export`
5. Examine span attributes:
   - `netflow.version`
   - `source.address`, `destination.address`
   - `network.transport`, `network.protocol.number`
   - `netflow.flow.bytes`, `netflow.flow.packets`

## Troubleshooting

### No Packets Received

```bash
# Check netflow2traces is listening
docker-compose -f demo/docker-compose.yml ps netflow2traces

# Check port is accessible
nc -zvu 127.0.0.1 2055

# Check firewall rules
# macOS: System Preferences > Security & Privacy > Firewall
# Linux: sudo ufw status
```

### Scapy Import Errors

```bash
# Install Scapy (should already be installed)
pip install scapy

# Or with uv
uv pip install scapy
```

### Template Errors (v9/IPFIX)

NetFlow v9 and IPFIX require template exchange before data records. The current generator has limited v9/IPFIX support:

- For comprehensive v9/IPFIX testing, use real NetFlow exporters like:
  - `softflowd`: Captures real traffic and exports as NetFlow
  - Cisco/Juniper routers: Production-grade exporters
  - `nfgen`: Specialized NetFlow generator

### Docker Generator Not Starting

```bash
# Check it's in the demo profile
docker-compose --profile demo ps

# Pull the image manually
docker pull networkstatic/nflow-generator

# Check logs for errors
docker-compose logs netflow-generator
```

## Advanced Usage

### Using with Remote Collectors

```bash
# Send to production collector
python tools/netflow_generator.py \
  --host netflow.prod.example.com \
  --port 9995 \
  --version 5 \
  --pattern mixed \
  --count 100

# Send to Grafana Cloud (via netflow2traces)
# Configure netflow2traces with Grafana Cloud OTLP endpoint
python tools/netflow_generator.py --pattern mixed --count 50
```

### Integration with CI/CD

```bash
#!/bin/bash
# test_integration.sh - Simple integration test

set -e

echo "Starting services..."
docker-compose -f demo/docker-compose.yml up -d
sleep 10  # Wait for services to be ready

echo "Sending test packets..."
python tools/netflow_generator.py --count 5 --pattern http

echo "Checking for traces..."
sleep 5  # Wait for processing
TRACES=$(curl -s http://localhost:3200/api/search?limit=1 | jq '.traces | length')

if [ "$TRACES" -gt 0 ]; then
    echo "✓ Integration test passed: Found $TRACES traces"
    exit 0
else
    echo "✗ Integration test failed: No traces found"
    exit 1
fi
```

### Custom Traffic Patterns

To add custom patterns, edit `netflow_generator.py`:

```python
TRAFFIC_PATTERNS = {
    # ... existing patterns ...
    "custom": [
        {"sport": (1024, 65535), "dport": 8080, "proto": 6, "desc": "Custom service"},
        {"sport": (1024, 65535), "dport": 9090, "proto": 17, "desc": "Custom UDP"},
    ],
}
```

Then use with:
```bash
python tools/netflow_generator.py --pattern custom --count 10
```

## See Also

- [Main README](../README.md) - Project overview and setup
- [CLAUDE.md](../CLAUDE.md) - Architecture and development guide
- [Docker Compose](../demo/docker-compose.yml) - Demo environment configuration
- [NetFlow v5 Specification](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html)
- [NetFlow v9 RFC 3954](https://www.ietf.org/rfc/rfc3954.txt)
- [IPFIX RFC 7011](https://www.ietf.org/rfc/rfc7011.txt)
