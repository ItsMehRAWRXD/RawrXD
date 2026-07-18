# Sovereign Runtime Specification

## Version 1.0.0 — Phase C.1 Qualification

## 1. Overview

The Sovereign Runtime is a unified execution environment that orchestrates the complete RawrXD stack: SEG → Engine → Swarm → Telemetry → Execution Graph → Adaptive Scheduler → Dashboard.

### 1.1 Design Principles

- **Deterministic Initialization**: Components initialize in strict order with explicit dependencies
- **Observable State**: All runtime state is exportable and introspectable
- **Recoverable**: Full checkpoint/restore capability at any execution boundary
- **Validatable**: Continuous validation hooks with configurable failure modes
- **Measurable**: Comprehensive performance baseline capture

## 2. Architecture

### 2.1 Component Hierarchy

```
SovereignRuntime (control plane)
├── SEG (Sovereign Execution Graph)
│   └── ExecutionPlanner
├── InfinitePerfectionEngine
│   └── Unity/Harmony Pipeline (Cycles 94-249)
├── SovereignSwarm
│   └── AdaptiveScheduler
├── InfinitePerfectionTelemetry
│   ├── SQLite Persistence
│   └── Dashboard Transport
└── CheckpointManager
    └── State Persistence
```

### 2.2 Initialization Order

Components MUST initialize in this exact sequence:

1. **SEG** - Creates execution graph builder
2. **Engine** - Initializes InfinitePerfectionEngine
3. **Swarm** - Sets up SovereignSwarm with adaptive scheduling
4. **Telemetry** - Configures InfinitePerfectionTelemetry
5. **Graph** - Builds execution graph (batches 92-256)
6. **Dashboard** - Launches WebSocket server (port 8080)
7. **Scheduler** - Activates adaptive scheduler

### 2.3 Subsystem Ownership

| Component | Owner | Lifecycle | Persistence |
|-----------|-------|-----------|-------------|
| SEG | Runtime | Runtime-scoped | Checkpoint |
| Engine | Runtime | Runtime-scoped | Checkpoint |
| Swarm | Runtime | Runtime-scoped | Checkpoint |
| Telemetry | Runtime | Runtime-scoped | SQLite + Checkpoint |
| Graph | SEG | Build-scoped | Regenerated |
| Dashboard | Telemetry | Runtime-scoped | None |
| Scheduler | Swarm | Runtime-scoped | Checkpoint |

## 3. API Contracts

### 3.1 SovereignRuntimeBootstrap

```cpp
class SovereignRuntimeBootstrap {
public:
    // Lifecycle
    bool Initialize(const BootstrapConfig& config);
    void Shutdown();
    bool IsRunning() const;
    
    // Execution
    bool ExecuteWorkflow();
    bool RunUntilConvergence(double target, int maxIterations);
    bool Validate();
    
    // Introspection
    BootstrapStatus GetStatus() const;
    std::string ExportStateToJson() const;
};
```

**Contract**: Initialize() returns true ONLY if all 7 initialization steps succeed. Shutdown() is idempotent.

### 3.2 IntegratedSovereignRuntime

```cpp
class IntegratedSovereignRuntime {
public:
    // Lifecycle
    bool Initialize(const IntegrationConfig& config);
    void Shutdown();
    bool IsRunning() const;
    
    // Execution
    bool ExecuteWorkflow();
    bool RunUntilConvergence(double target, int maxIterations);
    std::string CreateCheckpoint(const std::string& description);
    bool RestoreCheckpoint(const std::string& checkpointId);
    
    // Validation
    void RegisterValidationHook(const ValidationHook& hook);
    bool RunValidationHooks();
    
    // Introspection
    IntegrationStatus GetStatus() const;
    std::string ExportFullState() const;
    PerformanceBaseline& GetPerformanceBaseline();
    CheckpointManager& GetCheckpointManager();
};
```

**Contract**: ExecuteWorkflow() captures performance metrics automatically. RunUntilConvergence() creates checkpoint on success if configured.

### 3.3 CheckpointManager

```cpp
class CheckpointManager {
public:
    bool Initialize(const std::string& storagePath);
    std::string CreateCheckpoint(const std::string& description);
    bool RestoreCheckpoint(const std::string& checkpointId);
    std::vector<CheckpointMetadata> ListCheckpoints() const;
    bool DeleteCheckpoint(const std::string& checkpointId);
    void RegisterComponent(const std::string& name,
                          std::function<ComponentState()> serialize,
                          std::function<bool(const ComponentState&)> deserialize);
};
```

**Contract**: CreateCheckpoint() returns non-empty ID on success. RestoreCheckpoint() returns true only if ALL registered components deserialize successfully.

## 4. State Model

### 4.1 Runtime States

```
[UNINITIALIZED] → Initialize() → [INITIALIZING] → [RUNNING]
                                            ↓
[RUNNING] → Shutdown() → [SHUTTING_DOWN] → [SHUTDOWN]
     ↓
Checkpoint() → [CHECKPOINTING] → [RUNNING]
     ↓
Restore() → [RESTORING] → [RUNNING]
```

### 4.2 State Transitions

| From | To | Trigger | Preconditions |
|------|-----|---------|---------------|
| UNINITIALIZED | INITIALIZING | Initialize() | None |
| INITIALIZING | RUNNING | All components ready | SEG, Engine, Swarm, Telemetry initialized |
| RUNNING | CHECKPOINTING | CreateCheckpoint() | IsRunning() == true |
| CHECKPOINTING | RUNNING | Checkpoint complete | All components serialized |
| RUNNING | SHUTTING_DOWN | Shutdown() | IsRunning() == true |
| SHUTTING_DOWN | SHUTDOWN | All components stopped | None |

### 4.3 State Persistence

Runtime state is persisted at these boundaries:

1. **Initialization Complete** - Full state snapshot
2. **Pre-Shutdown** - Full state snapshot (if configured)
3. **Convergence Achieved** - Full state snapshot (if configured)
4. **Auto-Checkpoint** - Periodic snapshots (if configured)

## 5. Recovery Semantics

### 5.1 Checkpoint Format

Checkpoints are stored as JSON with binary component data:

```json
{
  "metadata": {
    "checkpointId": "cp-1234567890-0001",
    "timestamp": 1234567890000,
    "version": "1.0.0",
    "description": "convergence-achieved",
    "hasEngineState": true,
    "hasSwarmState": true,
    "hasTelemetryState": true,
    "hasGraphState": true,
    "totalCyclesExecuted": 42,
    "currentConvergenceScore": 0.9234,
    "isConverged": true
  },
  "components": {
    "engine": { "dataSize": 1024 },
    "swarm": { "dataSize": 512 },
    "telemetry": { "dataSize": 2048 }
  }
}
```

### 5.2 Restore Behavior

When restoring from checkpoint:

1. Runtime enters RESTORING state
2. Each registered component deserializes its state
3. If ANY component fails, restore aborts and runtime enters ERROR state
4. On success, runtime enters RUNNING state
5. Post-restore validation hooks execute

### 5.3 Failure Modes

| Failure | Behavior | Recovery |
|---------|----------|----------|
| Component init fail | Initialization aborts | Fix config, retry Initialize() |
| Validation fail | Depends on failOnValidationError | Review validation hooks |
| Checkpoint fail | Log error, continue | Check storage path permissions |
| Restore fail | Runtime enters ERROR state | Try earlier checkpoint |
| Convergence timeout | Log warning, continue | Adjust target/maxIterations |

## 6. Extension Points

### 6.1 Validation Hooks

```cpp
struct ValidationHook {
    std::string name;
    std::function<bool()> validateFunc;
    bool isCritical = false;
    int priority = 0;
};
```

Hooks execute in priority order (highest first). Critical hooks that fail can abort execution.

### 6.2 Performance Metrics

```cpp
struct MetricSample {
    std::string name;
    double value;
    std::string unit;
    int64_t timestampMs;
    std::map<std::string, std::string> tags;
};
```

Metrics are captured automatically for:
- Startup time
- Graph construction time
- Workflow execution time
- Convergence iterations
- Checkpoint save/restore time

### 6.3 Custom Components

New components can register for checkpointing:

```cpp
runtime.GetCheckpointManager().RegisterComponent(
    "my_component",
    []() -> ComponentState { /* serialize */ },
    [](const ComponentState& state) -> bool { /* deserialize */ }
);
```

## 7. Performance Contracts

### 7.1 Latency Budgets

| Operation | Target | Maximum |
|-----------|--------|---------|
| Initialization | < 500ms | < 2000ms |
| Graph Construction | < 100ms | < 500ms |
| Workflow Execution | < 50ms | < 200ms |
| Checkpoint Save | < 100ms | < 500ms |
| Checkpoint Restore | < 200ms | < 1000ms |
| Validation Hook | < 10ms | < 50ms |

### 7.2 Memory Budgets

| Component | Target | Maximum |
|-----------|--------|---------|
| Runtime Core | < 10 MB | < 50 MB |
| SEG (256 nodes) | < 5 MB | < 20 MB |
| Telemetry Buffer | < 50 MB | < 200 MB |
| Checkpoint (full) | < 100 MB | < 500 MB |

### 7.3 Convergence Targets

| Metric | Target |
|--------|--------|
| Convergence Rate | > 0.85 |
| Iterations to Converge | < 50 |
| Validation Pass Rate | 100% |
| Checkpoint Success Rate | > 99% |

## 8. CLI Interface

### 8.1 Commands

```bash
# Basic run
sovereign-runtime

# With validation
sovereign-runtime --validate

# Run until convergence
sovereign-runtime --convergence 0.90 --max-iterations 50

# With checkpointing
sovereign-runtime --checkpoint-path ./checkpoints --auto-checkpoint 30

# Export baseline
sovereign-runtime --baseline performance.json

# Qualification mode
sovereign-runtime --qualification
```

### 8.2 Qualification Output

```json
{
  "runtime": "PASS",
  "seg": {
    "nodes": 256,
    "validated": true
  },
  "engine": {
    "cycles": 149,
    "executed": 149
  },
  "swarm": {
    "tasks": 7,
    "completed": 7
  },
  "telemetry": {
    "events": 0,
    "persistence": true
  },
  "checkpoint": {
    "save": true,
    "restore": true
  },
  "performance": {
    "startupMs": 245,
    "graphBuildMs": 45,
    "workflowMs": 23,
    "checkpointMs": 67
  },
  "overall": "PASS"
}
```

## 9. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-13 | Initial specification — Phase C.1 Qualification |

## 10. References

- `docs/SOVEREIGN_RUNTIME_GUIDE.md` — Implementation guide
- `src/runtime/RuntimeValidationTest.cpp` — Validation test suite
- `src/runtime/SovereignRuntimeBootstrap.hpp` — Bootstrap API
- `src/runtime/RuntimeIntegration.hpp` — Integration API
