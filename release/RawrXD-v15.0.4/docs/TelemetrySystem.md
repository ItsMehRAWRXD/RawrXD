# InfinitePerfectionEngine Telemetry System

## Overview

The Telemetry System provides comprehensive observability into the InfinitePerfectionEngine's Unity Cycle execution. It captures harmonic field data, Swarm execution metrics, and convergence statistics for real-time monitoring and historical analysis.

## Features

- **Real-time Telemetry**: Capture Unity Cycle fields (243-249) after each execution
- **Swarm Execution Tracking**: Record task execution with confidence scores
- **Multiple Export Formats**: JSON, SQLite, and WebSocket streaming
- **Convergence Detection**: Automatic detection when all metrics > 0.8
- **Dashboard Integration**: Live WebSocket server for visualization
- **Historical Analysis**: SQLite persistence for long-term trend analysis

## Quick Start

### Basic Usage

```cpp
#include "swarm/InfinitePerfectionTelemetry.hpp"

// Create telemetry bridge
InfinitePerfectionEngine engine;
InfinitePerfectionTelemetry telemetry(&engine);

// Capture current state
auto snapshot = telemetry.GetSnapshot();

// Export to JSON
std::string json = telemetry.ExportToJson();
```

### CLI Commands

```bash
# Show convergence status
rawrxd swarm --show-convergence

# Export to JSON
rawrxd swarm --export-telemetry --telemetry-output metrics.json

# Export to SQLite
rawrxd swarm --export-sqlite --sqlite-db telemetry.db

# Start dashboard server
rawrxd swarm --telemetry-dashboard --dashboard-port 8080
```

## Data Structures

### UnityCycleTelemetry

Captures all 7 Unity Cycle fields:

```cpp
struct UnityCycleTelemetry {
    // Batch 243: Unity
    double unityPotential;
    double cycleIntegration;
    double harmonicConvergence;
    
    // Batch 244: Integration
    double integrationCoherence;
    double crossCycleAlignment;
    double phaseLockStrength;
    
    // Batch 245: Synthesis
    double emergenceDensity;
    double patternNovelty;
    double crossCycleSynergy;
    
    // Batch 246: Convergence
    double focalPointDensity;
    double attractorStrength;
    double convergenceCoherence;
    
    // Batch 247: Coherence
    double coherenceStability;
    double unifiedPatternIndex;
    double harmonicConsistency;
    
    // Batch 248: Harmony
    double resonanceAmplitude;
    double harmonicStability;
    double sovereignHarmonyIndex;
    
    // Batch 249: Balance
    double equilibriumStrength;
    double stabilityIndex;
    double symmetryCoefficient;
    
    // Metadata
    int64_t timestamp;
    uint32_t cycleCount;
    bool isConverged;
};
```

### SwarmExecutionTelemetry

Records individual task execution:

```cpp
struct SwarmExecutionTelemetry {
    uint32_t agentId;
    std::string taskKind;
    std::string engineCycle;
    float confidence;
    int64_t executionTimeMs;
    bool success;
    int64_t timestamp;
};
```

## SQLite Schema

### unity_cycle_metrics Table

```sql
CREATE TABLE unity_cycle_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    cycle_count INTEGER NOT NULL,
    is_converged INTEGER NOT NULL,
    unity_potential REAL NOT NULL,
    cycle_integration REAL NOT NULL,
    harmonic_convergence REAL NOT NULL,
    -- ... (all 21 fields)
);
```

### swarm_executions Table

```sql
CREATE TABLE swarm_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    agent_id INTEGER NOT NULL,
    task_kind TEXT NOT NULL,
    engine_cycle TEXT NOT NULL,
    confidence REAL NOT NULL,
    execution_time_ms INTEGER NOT NULL,
    success INTEGER NOT NULL
);
```

### convergence_events Table

```sql
CREATE TABLE convergence_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    convergence_score REAL NOT NULL,
    is_converged INTEGER NOT NULL,
    total_executions INTEGER NOT NULL
);
```

## WebSocket Protocol

### Connection

```javascript
const ws = new WebSocket('ws://localhost:8080');

ws.onopen = () => {
    console.log('Connected to telemetry dashboard');
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
};
```

### Event Types

#### cycle_update

```json
{
    "event": "cycle_update",
    "timestamp": 1234567890000,
    "totalCyclesExecuted": 142,
    "averageConvergenceRate": 0.916,
    "unityCycle": {
        "unityPotential": 0.91,
        "cycleIntegration": 0.87,
        "harmonicConvergence": 0.93,
        "sovereignHarmonyIndex": 0.96,
        "equilibriumStrength": 0.94,
        "isConverged": true
    }
}
```

#### snapshot

```json
{
    "event": "snapshot",
    "timestamp": 1234567890000,
    "data": {
        // Full UnityCycleTelemetry object
    }
}
```

## Convergence Detection

The system automatically detects convergence when:

```cpp
bool IsConverged() {
    return unityPotential > 0.8 &&
           cycleIntegration > 0.8 &&
           harmonicConvergence > 0.8 &&
           integrationCoherence > 0.8 &&
           coherenceStability > 0.8 &&
           sovereignHarmonyIndex > 0.8 &&
           equilibriumStrength > 0.8;
}
```

## Integration with Swarm

The telemetry system is automatically integrated into Swarm execution:

```cpp
SwarmTaskResult SwarmAgent::Execute(const SwarmTask& task) {
    // Execute engine cycle
    ctx_.engine->RunUnityCycle();
    
    // Record in telemetry
    if (ctx_.infiniteTelemetry) {
        ctx_.infiniteTelemetry->RecordSwarmExecution(
            agentId_,
            TaskKindToString(task.kind),
            "UnityCycle",
            result.confidence,
            duration,
            result.success
        );
    }
    
    return result;
}
```

## Performance

- **Memory**: ~10KB per snapshot
- **SQLite Insert**: ~1ms per record
- **WebSocket Broadcast**: ~0.1ms per client
- **History Limit**: Last 10,000 executions (configurable)

## API Reference

### InfinitePerfectionTelemetry

| Method | Description |
|--------|-------------|
| `CaptureUnityCycle()` | Capture current Unity Cycle fields |
| `RecordSwarmExecution()` | Record task execution |
| `GetSnapshot()` | Get complete telemetry snapshot |
| `ExportToJson()` | Export to JSON string |
| `IsConverged()` | Check convergence status |
| `GetConvergenceScore()` | Get average convergence score |

### InfinitePerfectionTelemetrySQLite

| Method | Description |
|--------|-------------|
| `Initialize()` | Create tables and indexes |
| `StoreUnityCycle()` | Persist Unity Cycle metrics |
| `StoreSwarmExecution()` | Persist execution record |
| `QueryUnityCycles()` | Query historical cycles |
| `GetStatistics()` | Get aggregate statistics |
| `ExportToJson()` | Export database to JSON |

### TelemetryDashboardServer

| Method | Description |
|--------|-------------|
| `Start()` | Start WebSocket server |
| `Stop()` | Stop server |
| `BroadcastTelemetry()` | Send to all clients |
| `GetClientCount()` | Get connected clients |
| `GetStatusJson()` | Get server status |

## Examples

### Query Convergence History

```cpp
InfinitePerfectionTelemetrySQLite db("telemetry.db");
db.Initialize();

auto history = db.QueryConvergenceHistory(
    startTime,  // timestamp
    endTime     // timestamp
);

for (const auto& [timestamp, score] : history) {
    std::cout << timestamp << ": " << score << std::endl;
}
```

### Custom Dashboard Client

```javascript
class TelemetryDashboard {
    constructor(url) {
        this.ws = new WebSocket(url);
        this.metrics = [];
        
        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.event === 'cycle_update') {
                this.updateMetrics(data.unityCycle);
            }
        };
    }
    
    updateMetrics(cycle) {
        this.metrics.push(cycle);
        this.render();
    }
    
    render() {
        // Render to DOM
    }
}

const dashboard = new TelemetryDashboard('ws://localhost:8080');
```

## Troubleshooting

### SQLite Database Locked

- Check for concurrent access
- Ensure WAL mode is enabled
- Use connection pooling for multi-threaded access

### WebSocket Connection Failed

- Verify port is not in use
- Check firewall settings
- Ensure CORS is properly configured

### Missing Telemetry Data

- Verify engine is initialized
- Check telemetry bridge is connected
- Ensure Swarm context has infiniteTelemetry set

## See Also

- [Phase B.2 Architecture](Phase_B2_Architecture.md)
- [Swarm Integration Guide](../src/swarm/README.md)
- [Unity Cycle Documentation](../infinite/README.md)
