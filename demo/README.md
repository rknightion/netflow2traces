# NetFlow to Traces Demo - Full LGTM Stack

This demo provides a complete observability stack for NetFlow monitoring with Loki, Grafana, Tempo, and Mimir (LGTM). It showcases how NetFlow data can be converted to OpenTelemetry traces and visualized alongside metrics and logs.

## Architecture

```
┌─────────────────┐
│ NetFlow Exporter│ (Router/Switch/softflowd)
│  (UDP packets)  │
└────────┬────────┘
         │ UDP:2055
         ▼
┌─────────────────┐
│ netflow2traces  │ Converts NetFlow → OTLP Traces
└────────┬────────┘
         │ OTLP gRPC:4317
         ▼
┌─────────────────┐
│  Grafana Tempo  │ Distributed Tracing Backend
│                 │ • Stores traces locally
│                 │ • Generates span metrics
└────────┬────────┘
         │ Metrics → http://mimir:9009/otlp
         ▼
┌─────────────────────────────────────────┐
│         Observability Stack             │
│  ┌──────────┐  ┌──────┐  ┌──────────┐  │
│  │  Mimir   │  │ Loki │  │ Grafana  │  │
│  │ (Metrics)│  │(Logs)│  │   (UI)   │  │
│  └──────────┘  └──────┘  └──────────┘  │
└─────────────────────────────────────────┘
```

### Components

- **netflow2traces**: Listens for NetFlow packets and converts them to OpenTelemetry traces
- **Tempo**: Distributed tracing backend that stores traces and generates span metrics
- **Mimir**: Prometheus-compatible metrics storage for span metrics and service graphs
- **Loki**: Log aggregation system for application logs
- **Grafana**: Unified observability UI with pre-configured dashboards
- **OpenTelemetry Collector**: Telemetry pipeline for processing and routing observability data

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Python 3.14+ (for test script)
- NetFlow exporter (router, switch, or softflowd) - optional

### 1. Start the Stack

```bash
cd demo/
docker-compose up -d
```

This will start all services:
- Grafana UI: http://localhost:3000
- Tempo API: http://localhost:3200
- Loki API: http://localhost:3100
- Mimir API: http://localhost:9009
- OTEL Collector: localhost:4317 (gRPC), localhost:4318 (HTTP)
- NetFlow Listener: localhost:2055 (UDP)

### 2. Access Grafana

Open http://localhost:3000 in your browser.

- **Username**: `admin`
- **Password**: `admin`

The dashboards are pre-configured and will appear in the "Demo" folder.

### 3. Send Test NetFlow Data

From the project root directory:

```bash
python test_netflow_sender.py --host 127.0.0.1 --port 2055 --count 10
```

This sends 10 NetFlow v5 packets with sample flow data.

### 4. View Traces and Metrics

Navigate to the **NetFlow Observability** dashboard in Grafana to see:
- Flow packet rates
- Protocol distribution
- Top source/destination IPs
- Flow processing latency
- Recent trace activity

## Available Dashboards

The demo includes 9 pre-configured Grafana dashboards:

### NetFlow-Specific
1. **NetFlow Observability** (NEW) - Comprehensive NetFlow monitoring dashboard
   - Flow packet rate and totals
   - Protocol distribution pie chart
   - Top 10 source and destination IPs
   - Flow processing latency (p50, p95)
   - Recent trace viewer

### General Observability
2. **APM Dashboard** - Application performance monitoring with service graphs
3. **Demo Dashboard** - Overview of the demo environment
4. **Exemplars Dashboard** - Metrics-to-traces correlation examples
5. **Linux Dashboard** - Host metrics (CPU, memory, disk, network)
6. **NGINX Metrics** - NGINX web server monitoring
7. **OpenTelemetry Collector** - OTEL Collector internal metrics
8. **PostgreSQL Dashboard** - Database performance metrics
9. **Span Metrics Dashboard** - RED metrics from traces (Rate, Errors, Duration)

## Sending Real NetFlow Data

### From a Router/Switch

Configure your network device to export NetFlow to the host running this demo:

**Cisco IOS Example:**
```
ip flow-export version 5
ip flow-export destination <host-ip> 2055
interface GigabitEthernet0/0
 ip flow ingress
 ip flow egress
```

**Cisco NXOS Example:**
```
flow exporter netflow-exporter
  destination <host-ip> use-vrf management
  transport udp 2055
  version 9
```

### Using softflowd (Linux/macOS)

Generate NetFlow from local network traffic:

```bash
# Install softflowd
# Ubuntu/Debian:
sudo apt-get install softflowd

# macOS:
brew install softflowd

# Start capturing on an interface
sudo softflowd -i en0 -n 127.0.0.1:2055 -v 9

# Options:
#   -i: Network interface to capture
#   -n: NetFlow collector address:port
#   -v: NetFlow version (5, 9, or 10 for IPFIX)
```

### Using nflow-generator (Node.js)

Generate synthetic NetFlow data for testing:

```bash
# Install
npm install -g nflow-generator

# Generate NetFlow v5 data
nflow-generator -t 127.0.0.1 -p 2055 -v 5 -c 100

# Options:
#   -t: Target host
#   -p: Target port
#   -v: NetFlow version
#   -c: Number of flows to generate
```

## Architecture Details

### Data Flow

1. **NetFlow Ingestion**: netflow2traces listens on UDP port 2055 for NetFlow packets
2. **Trace Creation**: Each NetFlow export packet becomes an OTLP trace with child spans for each flow record
3. **Direct to Tempo**: Traces are sent directly to Tempo via gRPC (port 4317)
4. **Metrics Generation**: Tempo's metrics generator creates span metrics (RED metrics, service graphs)
5. **Metrics to Mimir**: Span metrics are sent to Mimir via OTLP (port 9009)
6. **Visualization**: Grafana queries Tempo for traces and Mimir for metrics

### Trace Structure

```
Trace: netflow.export
├─ Span: netflow.parse_packet
└─ Span: netflow.process_flows
   ├─ Span: netflow.flow (record 1)
   │  ├─ Attributes:
   │  │  ├─ source.address: 192.168.1.100
   │  │  ├─ destination.address: 10.0.0.50
   │  │  ├─ network.transport: tcp
   │  │  ├─ netflow.flow.bytes: 150000
   │  │  └─ netflow.flow.packets: 100
   ├─ Span: netflow.flow (record 2)
   └─ Span: netflow.flow (record N)
```

### Span Metrics Generated by Tempo

Tempo automatically generates these metrics from traces:

- **calls_total**: Total number of spans (flow records)
- **duration_bucket**: Histogram of span durations for latency percentiles
- **traces_spanmetrics_calls_total**: Service-level span counts
- **traces_service_graph_request_total**: Service graph edges

These metrics are queried in the NetFlow dashboard to show:
- Flow packet rate: `rate(calls_total{span_name="netflow.flow"}[5m])`
- Protocol distribution: `sum by (network_transport) (calls_total{span_name="netflow.flow"})`
- Top IPs: `topk(10, sum by (source_address) (calls_total{span_name="netflow.flow"}))`
- Latency: `histogram_quantile(0.95, rate(duration_bucket[5m]))`

## Configuration

### Environment Variables

Edit `.env` to customize:

```bash
# OTEL Collector Image
COLLECTOR_CONTRIB_IMAGE=ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib:0.136.0

# Ports
OTEL_COLLECTOR_PORT_GRPC=4317
OTEL_COLLECTOR_PORT_HTTP=4318
NETFLOW_LISTEN_PORT=2055
GRAFANA_PORT=3000

# Logging
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR
```

### Modifying Configurations

The following configurations can be customized:

- **Tempo**: `tempo/tempo.yaml` - Adjust trace retention, metrics generator settings
- **Loki**: `loki/loki-config.yaml` - Configure log retention, ingestion limits
- **Mimir**: Configured via CLI flags in `docker-compose.yml` - Adjust memory limits, storage
- **Grafana**: `grafana/grafana.ini` - Change admin password, plugins, UI settings
- **OTEL Collector**: `otel-collector/otelcol-config.yml` - Add receivers, processors, exporters
- **Datasources**: `grafana/provisioning/datasources/datasources.yaml` - Modify correlations

## Viewing Data

### Explore Tempo (Traces)

1. Navigate to **Explore** in Grafana
2. Select **Tempo** datasource
3. Use TraceQL queries:
   ```
   { name="netflow.export" }
   { span.source.address="192.168.1.100" }
   { span.network.transport="tcp" }
   ```

### Explore Mimir (Metrics)

1. Navigate to **Explore** in Grafana
2. Select **Mimir** datasource
3. Use PromQL queries:
   ```
   rate(calls_total{service_name="netflow-to-traces"}[5m])
   histogram_quantile(0.95, rate(duration_bucket[5m]))
   ```

### Explore Loki (Logs)

1. Navigate to **Explore** in Grafana
2. Select **Loki** datasource
3. Use LogQL queries:
   ```
   {service_name="netflow-to-traces"}
   {service_name="netflow-to-traces"} |= "error"
   ```

## Troubleshooting

### No traces appearing

1. Check if netflow2traces is receiving packets:
   ```bash
   docker-compose logs netflow2traces
   ```

2. Verify NetFlow exporter is sending to the correct host/port:
   ```bash
   # On the Docker host
   sudo tcpdump -i any -n udp port 2055
   ```

3. Check Tempo is receiving traces:
   ```bash
   curl http://localhost:3200/api/search?tags=service.name=netflow-to-traces
   ```

### Dashboards show "No Data"

1. Wait 1-2 minutes after sending NetFlow data for metrics to be generated
2. Adjust the time range in Grafana (default is last 15 minutes)
3. Check if Tempo metrics generator is working:
   ```bash
   docker-compose logs tempo | grep metrics_generator
   ```

### High memory usage

Adjust resource limits in `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      memory: 400M  # Increase as needed
```

### Services won't start

Check Docker resource availability:
```bash
docker system df
docker system prune  # Clean up if needed
```

## Stopping the Demo

```bash
# Stop services but keep data
docker-compose down

# Stop services and remove all data volumes
docker-compose down -v
```

## Development

### Rebuild netflow2traces

```bash
# After making changes to ../src/ or ../Dockerfile
docker-compose build netflow2traces
docker-compose up -d netflow2traces
```

**Note**: The demo uses the root `Dockerfile` (located at `../Dockerfile`) which:
- Builds with Python 3.14
- Uses modern `uv sync` pattern with lockfile (`uv.lock`) for reproducible builds
- Implements cache mounts for faster subsequent builds
- Separates dependency installation from code copy for optimal layer caching

If you update `uv.lock` (by adding/updating dependencies), rebuild the Docker image to pick up the changes.

### View Real-Time Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f netflow2traces
docker-compose logs -f tempo
```

## Performance Considerations

- **High Volume Deployments**: For >1000 flows/sec, consider:
  - Increasing memory limits on Tempo and Mimir
  - Reducing trace retention (currently 1 hour)
  - Using external storage backends (S3, GCS)
  - Sampling traces

- **Resource Usage**: Default limits:
  - Tempo: 400MB
  - Mimir: 300MB
  - Grafana: 300MB
  - Loki: 200MB
  - OTEL Collector: 200MB

## References

- [Grafana Tempo Documentation](https://grafana.com/docs/tempo/latest/)
- [Grafana Mimir Documentation](https://grafana.com/docs/mimir/latest/)
- [Grafana Loki Documentation](https://grafana.com/docs/loki/latest/)
- [OpenTelemetry Collector Documentation](https://opentelemetry.io/docs/collector/)
- [NetFlow v5 Specification](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html)
- [NetFlow v9 Specification](https://tools.ietf.org/html/rfc3954)
- [IPFIX Specification](https://tools.ietf.org/html/rfc7011)

## License

MIT License - see parent directory LICENSE file for details
