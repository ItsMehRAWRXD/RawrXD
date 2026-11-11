# Phase D.4 Batch 4/5 — Observability & Operations

## Overview

This batch implements a comprehensive observability and operations layer for the RawrXD sovereign runtime, providing metrics collection, health monitoring, performance profiling, log aggregation, telemetry export, and operational commands. This enables production monitoring, debugging, and operational control.

## Architecture

```
SovereignObservability (Singleton)
├── MetricCollector
│   ├── Counter metrics (monotonically increasing)
│   ├── Gauge metrics (can go up/down)
│   ├── Histogram metrics (distribution tracking)
│   ├── Prometheus export
│   ├── JSON export
│   └── CSV export
├── HealthMonitor
│   ├── Health check registration
│   ├── Background monitoring
│   ├── Overall health calculation
│   └── Health endpoint response
├── PerformanceProfiler
│   ├── Scoped profiling
│   ├── Manual profiling
│   ├── Operation statistics
│   ├── Trace export
│   └── Flame graph export
├── LogAggregator
│   ├── Structured logging
│   ├── Log querying
│   ├── Log search
│   ├── Export to file
│   └── Statistics
├── TelemetryExporter
│   ├── Endpoint configuration
│   ├── Batch export
│   ├── Automatic flush
│   └── Background export
├── OperationalCommands
│   ├── Command registration
│   ├── Built-in commands
│   └── Command execution
└── Built-in Metrics
    ├── System metrics (CPU, memory, disk, network)
    ├── Inference metrics (requests, latency, tokens, errors)
    ├── Agent metrics (active, created, tasks, latency)
    ├── Swarm metrics (active, agents, consensus time)
    └── Runtime metrics (uptime, goroutines, GC)
```

## Components

### 1. Metric Collection

The `MetricCollector` provides comprehensive metrics tracking:

```cpp
// Register a metric
MetricDefinition def;
def.name = "sovereign_inference_latency";
def.description = "Inference request latency";
def.type = MetricType::HISTOGRAM;
def.unit = MetricUnit::SECONDS;
def.buckets = {0.001, 0.005, 0.01, 0.025, 0.05, 0.1};
observability.GetMetrics().RegisterMetric(def);

// Record values
observability.GetMetrics().RecordCounter("sovereign_inference_requests", 1.0,
    {{"model", "phi-4"}, {"status", "success"}});

observability.GetMetrics().RecordGauge("sovereign_cpu_usage", 45.5);

observability.GetMetrics().RecordHistogram("sovereign_inference_latency", 0.025);

// Query statistics
auto stats = observability.GetMetrics().GetStatistics(
    "sovereign_inference_latency", std::chrono::seconds(3600));
if (stats) {
    std::cout << "Mean latency: " << stats->mean << "s\n";
    std::cout << "P95 latency: " << stats->p95 << "s\n";
}

// Export
std::string prometheus = observability.GetMetrics().ExportPrometheus();
std::string json = observability.GetMetrics().ExportJSON();
std::string csv = observability.GetMetrics().ExportCSV();
```

### 2. Health Monitoring

The `HealthMonitor` provides system health tracking:

```cpp
// Register health checks
observability.GetHealth().RegisterCheck("database", []() {
    HealthCheckResult result;
    result.component = "database";
    // Check database connectivity
    result.status = HealthStatus::HEALTHY;
    result.message = "Database connection OK";
    return result;
});

observability.GetHealth().RegisterCheck("inference_engine", []() {
    HealthCheckResult result;
    result.component = "inference_engine";
    // Check inference engine
    result.status = HealthStatus::HEALTHY;
    result.message = "Inference engine ready";
    return result;
});

// Start background monitoring
observability.GetHealth().StartMonitoring(std::chrono::seconds(30));

// Check overall health
HealthStatus overall = observability.GetHealth().GetOverallHealth();
if (overall == HealthStatus::HEALTHY) {
    std::cout << "System is healthy\n";
} else if (overall == HealthStatus::DEGRADED) {
    auto unhealthy = observability.GetHealth().GetUnhealthyComponents();
    for (const auto& comp : unhealthy) {
        std::cout << "Component degraded: " << comp << "\n";
    }
}

// Get health endpoint response (for HTTP health checks)
std::string health_json = observability.GetHealth().GetHealthEndpointResponse();
```

### 3. Performance Profiling

The `PerformanceProfiler` provides operation profiling:

```cpp
// Enable profiling
observability.GetProfiler().Enable();

// Scoped profiling
void ProcessRequest() {
    auto scope = observability.GetProfiler().ProfileScope("process_request");
    
    // Do work...
    
    scope.AddAttribute("model", "phi-4");
    scope.AddAttribute("tokens", "512");
}

// Manual profiling
observability.GetProfiler().StartOperation("inference");
// ... do inference ...
observability.GetProfiler().EndOperation("inference");

// Get statistics
auto stats = observability.GetProfiler().GetOperationStats(std::chrono::hours(1));
for (const auto& op : stats) {
    std::cout << op.operation << ":\n";
    std::cout << "  Count: " << op.count << "\n";
    std::cout << "  Avg: " << op.avg_time.count() << "ns\n";
    std::cout << "  P95: " << op.p95_time.count() << "ns\n";
}

// Export traces
std::string traces = observability.GetProfiler().ExportTrace();
std::string flamegraph = observability.GetProfiler().ExportFlameGraph();
```

### 4. Log Aggregation

The `LogAggregator` provides structured logging:

```cpp
// Configure
observability.GetLogs().SetMinLevel(LogLevel::INFO);
observability.GetLogs().SetBufferSize(10000);
observability.GetLogs().SetOutputPath("sovereign.log");

// Log messages
observability.GetLogs().Info("inference", "Request processed successfully",
    {{"model", "phi-4"}, {"tokens", "512"}});

observability.GetLogs().Error("agent", "Agent execution failed",
    {{"agent_id", "agent_123"}, {"error", "timeout"}});

// Convenience methods
observability.LogInfo("component", "Message");
observability.LogError("component", "Error message");

// Query logs
auto logs = observability.GetLogs().Query(
    LogLevel::WARN,                    // Minimum level
    std::nullopt,                       // Any component
    std::chrono::system_clock::now() - std::chrono::hours(1),  // Last hour
    std::nullopt,                       // No end time
    1000                                // Limit
);

// Search logs
auto results = observability.GetLogs().Search("error", 100);

// Get statistics
auto stats = observability.GetLogs().GetStatistics();
std::cout << "Total entries: " << stats.total_entries << "\n";
std::cout << "Errors: " << stats.error_count << "\n";
std::cout << "Warnings: " << stats.warn_count << "\n";

// Export
observability.GetLogs().ExportToFile("export.log", LogLevel::INFO);
```

### 5. Telemetry Export

The `TelemetryExporter` sends data to external systems:

```cpp
// Configure
observability.GetExporter().SetEndpoint("https://telemetry.example.com/v1/metrics");
observability.GetExporter().SetAPIKey("api_key_here");
observability.GetExporter().SetBatchSize(100);
observability.GetExporter().SetFlushInterval(std::chrono::seconds(60));

// Start exporter
observability.GetExporter().Start();

// Export data
observability.GetExporter().ExportMetrics(observability.GetMetrics());
observability.GetExporter().ExportLogs(observability.GetLogs());
observability.GetExporter().ExportTraces(observability.GetProfiler());

// Manual flush
observability.GetExporter().Flush();

// Stop exporter
observability.GetExporter().Stop();
```

### 6. Operational Commands

The `OperationalCommands` provides runtime control:

```cpp
// Register custom commands
observability.GetCommands().RegisterCommand("status", "Get system status",
    [](const std::vector<std::string>& args) {
        return "System running normally";
    });

// Execute commands
std::string result = observability.GetCommands().Execute("health", {});
std::string metrics = observability.GetCommands().Execute("metrics", {});
std::string stats = observability.GetCommands().Execute("stats", {});

// List available commands
auto commands = observability.GetCommands().ListCommands();
for (const auto& [name, desc] : commands) {
    std::cout << name << ": " << desc << "\n";
}
```

**Built-in Commands:**
- `health` — Get system health status
- `metrics` — Export metrics in Prometheus format
- `stats` — Get system statistics
- `profile` — Get performance profile
- `logs [limit]` — Get recent log entries

### 7. Main Observability Layer

The `SovereignObservability` singleton provides unified access:

```cpp
// Initialize
SovereignObservability& obs = SovereignObservability::GetInstance();
obs.Initialize("observability.conf");

// Quick metrics
obs.RecordMetric("custom_metric", 42.0);

// Quick logging
obs.LogInfo("component", "Application started");
obs.LogError("component", "Something went wrong");

// Health check
if (obs.IsHealthy()) {
    std::cout << "System is healthy\n";
}

std::string health = obs.GetHealthStatus();

// Get status
auto status = obs.GetStatus();
std::cout << "Metrics: " << status.metrics_count << "\n";
std::cout << "Monitoring: " << (status.monitoring_active ? "yes" : "no") << "\n";

// Shutdown
obs.Shutdown();
```

## Built-in Metrics

### System Metrics
| Metric | Type | Description |
|--------|------|-------------|
| `sovereign_cpu_usage_percent` | Gauge | CPU usage percentage |
| `sovereign_memory_usage_bytes` | Gauge | Memory usage in bytes |
| `sovereign_memory_usage_percent` | Gauge | Memory usage percentage |
| `sovereign_disk_usage_bytes` | Gauge | Disk usage in bytes |
| `sovereign_network_bytes_in` | Counter | Network bytes received |
| `sovereign_network_bytes_out` | Counter | Network bytes sent |

### Inference Metrics
| Metric | Type | Description |
|--------|------|-------------|
| `sovereign_inference_requests_total` | Counter | Total inference requests |
| `sovereign_inference_latency_seconds` | Histogram | Inference latency |
| `sovereign_inference_tokens_total` | Counter | Total tokens processed |
| `sovereign_inference_errors_total` | Counter | Total inference errors |

### Agent Metrics
| Metric | Type | Description |
|--------|------|-------------|
| `sovereign_agents_active` | Gauge | Number of active agents |
| `sovereign_agents_created_total` | Counter | Total agents created |
| `sovereign_agent_tasks_total` | Counter | Total agent tasks |
| `sovereign_agent_latency_seconds` | Histogram | Agent task latency |

### Swarm Metrics
| Metric | Type | Description |
|--------|------|-------------|
| `sovereign_swarms_active` | Gauge | Number of active swarms |
| `sovereign_swarm_agents_total` | Gauge | Total agents in swarms |
| `sovereign_swarm_consensus_seconds` | Histogram | Consensus time |

### Runtime Metrics
| Metric | Type | Description |
|--------|------|-------------|
| `sovereign_uptime_seconds` | Counter | System uptime |
| `sovereign_goroutines` | Gauge | Number of goroutines (if applicable) |
| `sovereign_gc_duration_seconds` | Histogram | GC duration |

## Files Created

1. `SovereignObservability.hpp` (~700 lines) — Complete header
2. `SovereignObservability.cpp` (~1100 lines) — Full implementation
3. `PHASE_D4_BATCH4_OBSERVABILITY.md` — This documentation

## Integration

The observability layer integrates with:
- **SovereignUnifiedRuntime** (Batch 1/5) — Runtime metrics
- **SovereignSecurityLayer** (Batch 3/5) — Security event logging
- **Benchmark Framework** (Batch 2/5) — Performance profiling
- **External monitoring systems** — Prometheus, Grafana, etc.

## Production Checklist

✅ Counter, gauge, and histogram metrics
✅ Prometheus format export
✅ JSON and CSV export
✅ Health check framework
✅ Background health monitoring
✅ Performance profiling with scopes
✅ Trace and flame graph export
✅ Structured logging
✅ Log querying and search
✅ Telemetry export to external systems
✅ Operational commands
✅ Built-in metrics for all subsystems

## Usage Example

```cpp
#include "SovereignObservability.hpp"
using namespace Sovereign;

int main() {
    // Initialize observability
    auto& obs = SovereignObservability::GetInstance();
    obs.Initialize();
    
    // Register a custom metric
    MetricDefinition def;
    def.name = "app_requests_total";
    def.description = "Total application requests";
    def.type = MetricType::COUNTER;
    obs.GetMetrics().RegisterMetric(def);
    
    // Register health check
    obs.GetHealth().RegisterCheck("app", []() {
        HealthCheckResult r;
        r.component = "app";
        r.status = HealthStatus::HEALTHY;
        r.message = "OK";
        return r;
    });
    
    // Start monitoring
    obs.GetHealth().StartMonitoring(std::chrono::seconds(30));
    
    // Simulate work
    for (int i = 0; i < 100; ++i) {
        auto scope = obs.GetProfiler().ProfileScope("request");
        
        obs.GetMetrics().RecordCounter("app_requests_total", 1.0);
        obs.LogInfo("app", "Request processed", {{"id", std::to_string(i)}});
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Export metrics
    std::cout << obs.GetMetrics().ExportPrometheus() << std::endl;
    
    // Check health
    std::cout << obs.GetHealthStatus() << std::endl;
    
    // Execute command
    std::cout << obs.GetCommands().Execute("stats", {}) << std::endl;
    
    // Cleanup
    obs.Shutdown();
    
    return 0;
}
```

## Next Steps

After completing Batch 4/5:
1. **Batch 5/5**: Full System Qualification (`rawrxd qualify --full` command)

---

**Status**: ✅ Complete
**Date**: 2026-07-08
**Phase**: D.4 Batch 4/5
