# Telemetry Dashboard Example

Demonstrates real-time metrics collection and visualization for monitoring RawrXD inference performance and system health.

## Features

- **Real-time Metrics**: Live updates every second
- **Performance Monitoring**: Throughput, latency (P50/P99), queue depth
- **Resource Tracking**: Memory, GPU utilization, CPU usage
- **Session Metrics**: Active sessions, total sessions, error count
- **Web Dashboard**: Optional HTTP server for browser-based visualization
- **Console Dashboard**: Terminal-based real-time display

## Building

```bash
cd examples/telemetry_dashboard
mkdir build && cd build
cmake ..
cmake --build .
```

## Running

### Console Dashboard (Default)

```bash
./telemetry_dashboard
```

Displays a real-time ASCII dashboard in the terminal:

```
╔════════════════════════════════════════════════════════════════╗
║           RawrXD Real-Time Telemetry Dashboard                 ║
╠════════════════════════════════════════════════════════════════╣
║ PERFORMANCE                                                      ║
╠════════════════════════════════════════════════════════════════╣
║  Throughput:     547.3 tokens/s                    ║
║  Latency P50:    23.4 ms                              ║
║  Latency P99:    43.2 ms                              ║
║  Queue Depth:    3                                 ║
╠════════════════════════════════════════════════════════════════╣
║ RESOURCES                                                        ║
╠════════════════════════════════════════════════════════════════╣
║  Memory Used:    8.45 GB / 64.00 GB         ║
║  GPU Memory:     6.20 GB / 24.00 GB         ║
║  GPU Util:      87.3 %                             ║
║  CPU Util:      45.2 %                             ║
╠════════════════════════════════════════════════════════════════╣
║ SESSIONS                                                         ║
╠════════════════════════════════════════════════════════════════╣
║  Active:        12                                 ║
║  Total:         156                                ║
║  Errors:        0                                  ║
╠════════════════════════════════════════════════════════════════╣
║ STATUS: 🟢 HEALTHY                                      ║
╚════════════════════════════════════════════════════════════════╝
```

### Web Dashboard

```bash
./telemetry_dashboard --web --port 8080
```

Then open http://localhost:8080 in your browser.

## Metrics Collected

| Metric | Description | Unit |
|--------|-------------|------|
| `tokensPerSecond` | Inference throughput | tokens/s |
| `latencyP50` | Median response latency | ms |
| `latencyP99` | 99th percentile latency | ms |
| `queueDepth` | Pending inference requests | count |
| `memoryUsedMB` | System memory usage | MB |
| `gpuUtilization` | GPU compute utilization | % |
| `activeSessions` | Currently active inference sessions | count |
| `errorCount` | Cumulative error count | count |

## Configuration

```cpp
TelemetryConfig config;
config.enabled = true;
config.metricsInterval = 1s;           // Collection interval
config.exportEndpoint = "";            // Optional: export to external system
config.enableConsoleOutput = false;    // Disable default logging
```

## Integration

```cpp
// Get telemetry collector
auto telemetry = runtime->GetTelemetryCollector();

// Get current snapshot
auto snapshot = telemetry->GetSnapshot();

// Access metrics
std::cout << "TPS: " << snapshot.tokensPerSecond << std::endl;
std::cout << "P99 Latency: " << snapshot.latencyP99 << "ms" << std::endl;
```

## Exporting Metrics

To export to external systems (Prometheus, Grafana, etc.):

```cpp
config.exportEndpoint = "http://prometheus:9090/metrics";
config.exportFormat = TelemetryFormat::Prometheus;
```

## See Also

- [Telemetry API](../../include/rawrxd/telemetry/)
- [Performance Tuning](../../docs/FAQ.md#performance)
- [Monitoring Guide](../../docs/Architecture.md#observability)
