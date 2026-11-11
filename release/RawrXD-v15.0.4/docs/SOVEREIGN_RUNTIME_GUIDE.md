# Sovereign Runtime Guide

## Phase B.5: Unified Sovereign Runtime

The Unified Sovereign Runtime is a single bootstrap executable that initializes the complete stack: SEG → Engine → Swarm → Telemetry → Execution Graph → Adaptive Scheduler → Dashboard.

## Overview

The Sovereign Runtime provides:
- **Unified Initialization**: Single entry point for all components
- **Performance Baseline Capture**: Comprehensive metrics tracking
- **Checkpoint/Restore**: State persistence and recovery
- **Continuous Validation**: Runtime health monitoring
- **Integration Hooks**: Pre/post startup/shutdown customization

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    IntegratedSovereignRuntime                │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌───────────────┐ │
│  │ CheckpointManager│  │PerformanceCapture│  │ValidationHooks│ │
│  └────────┬────────┘  └────────┬────────┘  └───────┬───────┘ │
│           │                    │                   │         │
│           └────────────────────┼───────────────────┘         │
│                                │                             │
│                    ┌───────────▼────────────┐                │
│                    │ SovereignRuntimeBootstrap│                │
│                    └───────────┬────────────┘                │
│                                │                             │
│  ┌─────────┬─────────┬─────────┼─────────┬─────────┬────────┐│
│  │   SEG   │ Engine  │  Swarm  │Telemetry│  Graph  │Dashboard││
│  └─────────┴─────────┴─────────┴─────────┴─────────┴────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. SovereignRuntimeBootstrap

The core bootstrap component that initializes the stack in 7 steps:

1. **SEG Initialization**: Creates the execution graph builder
2. **Engine Initialization**: Initializes InfinitePerfectionEngine
3. **Swarm Initialization**: Sets up SovereignSwarm with adaptive scheduling
4. **Telemetry Initialization**: Configures InfinitePerfectionTelemetry
5. **Graph Construction**: Builds the execution graph
6. **Dashboard Startup**: Launches the WebSocket dashboard server
7. **Scheduler Activation**: Starts the adaptive scheduler

### 2. PerformanceBaseline

Captures and tracks performance metrics:

- **MetricSample**: Individual measurement with timestamp and tags
- **MetricStats**: Aggregated statistics (min, max, mean, median, P95, P99, stddev)
- **PhaseBaseline**: Metrics for a specific phase
- **RuntimePerformanceCapture**: Pre-configured capture for runtime phases

### 3. CheckpointManager

Provides state persistence:

- **CheckpointMetadata**: Information about each checkpoint
- **ComponentState**: Serialized component data
- **CheckpointPolicy**: Configuration for auto-checkpointing
- **CheckpointableRuntime**: Wrapper for easy integration

### 4. IntegratedSovereignRuntime

Combines all components with:

- 4-step initialization
- Continuous validation
- Automatic checkpointing on convergence
- Performance baseline export
- Full state introspection

## Usage

### Basic Usage

```cpp
#include "runtime/RuntimeIntegration.hpp"

// Create and initialize
Sovereign::IntegratedSovereignRuntime runtime;
Sovereign::IntegrationConfig config;

if (!runtime.Initialize(config)) {
    std::cerr << "Initialization failed\n";
    return 1;
}

// Execute workflow
runtime.ExecuteWorkflow();

// Run until convergence
runtime.RunUntilConvergence(0.90, 100);

// Create checkpoint
std::string checkpointId = runtime.CreateCheckpoint("manual");

// Shutdown
runtime.Shutdown();
```

### CLI Usage

```bash
# Basic run
./integrated-runtime

# With validation
./integrated-runtime --validate

# Run until convergence
./integrated-runtime --convergence 0.90 --max-iterations 50

# With auto-checkpointing
./integrated-runtime --auto-checkpoint 30

# Export performance baseline
./integrated-runtime --baseline performance.json

# Output JSON status
./integrated-runtime --json
```

### Configuration

```cpp
Sovereign::IntegrationConfig config;

// Bootstrap settings
config.bootstrap.enableSEG = true;
config.bootstrap.enableEngine = true;
config.bootstrap.enableSwarm = true;
config.bootstrap.enableTelemetry = true;
config.bootstrap.enableDashboard = true;
config.bootstrap.targetConvergenceRate = 0.85;

// Checkpoint policy
config.checkpointPolicy.enableAutoCheckpoint = true;
config.checkpointPolicy.autoCheckpointIntervalMinutes = 30;
config.checkpointPolicy.checkpointOnConvergence = true;
config.checkpointPolicy.checkpointOnShutdown = true;
config.checkpointPolicy.maxCheckpoints = 10;

// Validation settings
config.enableContinuousValidation = true;
config.validationIntervalMs = 5000;
config.failOnValidationError = false;

// Performance tracking
config.enablePerformanceTracking = true;
config.autoSaveBaseline = true;
config.baselineOutputPath = "performance_baseline.json";
```

## Validation Hooks

Register custom validation hooks:

```cpp
Sovereign::ValidationHook hook;
hook.name = "custom_validation";
hook.validateFunc = []() -> bool {
    // Perform validation
    return true;
};
hook.isCritical = true;
hook.priority = 100;

runtime.RegisterValidationHook(hook);
```

## Performance Baseline

Access and export performance data:

```cpp
// Get baseline
auto& baseline = runtime.GetPerformanceBaseline();

// Print summary
baseline.PrintSummary();

// Export to JSON
std::string json = baseline.ExportToJson();

// Save to file
baseline.SaveToFile("performance.json");
```

## Checkpoint Management

Manage checkpoints programmatically:

```cpp
// List checkpoints
auto checkpoints = runtime.GetCheckpointManager().ListCheckpoints();

// Create checkpoint
std::string id = runtime.CreateCheckpoint("description");

// Restore checkpoint
runtime.RestoreCheckpoint(id);

// Delete checkpoint
runtime.GetCheckpointManager().DeleteCheckpoint(id);

// Prune old checkpoints
runtime.GetCheckpointManager().PruneCheckpoints(5);
```

## File Structure

```
src/runtime/
├── SovereignRuntimeBootstrap.hpp    # Core bootstrap interface
├── SovereignRuntimeBootstrap.cpp    # Bootstrap implementation
├── PerformanceBaseline.hpp         # Performance tracking interface
├── PerformanceBaseline.cpp         # Performance tracking implementation
├── CheckpointManager.hpp           # Checkpoint interface
├── CheckpointManager.cpp           # Checkpoint implementation
├── RuntimeIntegration.hpp          # Full integration interface
├── RuntimeIntegration.cpp          # Full integration implementation
├── main_bootstrap.cpp              # Bootstrap entry point
└── SovereignRuntime.hpp            # Legacy runtime interface
```

## Build Integration

Add to CMakeLists.txt:

```cmake
set(RUNTIME_SOURCES
    src/runtime/SovereignRuntimeBootstrap.cpp
    src/runtime/PerformanceBaseline.cpp
    src/runtime/CheckpointManager.cpp
    src/runtime/RuntimeIntegration.cpp
)

add_executable(sovereign-runtime
    src/runtime/main_bootstrap.cpp
    ${RUNTIME_SOURCES}
)

target_link_libraries(sovereign-runtime
    seg_lib
    swarm_lib
    infinite_lib
)
```

## API Reference

### SovereignRuntimeBootstrap

| Method | Description |
|--------|-------------|
| `Initialize(config)` | Initialize with configuration |
| `Shutdown()` | Graceful shutdown |
| `IsRunning()` | Check if running |
| `ExecuteWorkflow()` | Execute full workflow |
| `RunUntilConvergence(target, maxIter)` | Run until convergence |
| `Validate()` | Run validation suite |
| `GetStatus()` | Get runtime status |
| `ExportStateToJson()` | Export state as JSON |

### IntegratedSovereignRuntime

| Method | Description |
|--------|-------------|
| `Initialize(config)` | Initialize with full integration |
| `Shutdown()` | Graceful shutdown with hooks |
| `ExecuteWorkflow()` | Execute with tracking |
| `RunUntilConvergence(target, maxIter)` | Run with checkpointing |
| `CreateCheckpoint(desc)` | Create checkpoint |
| `RestoreCheckpoint(id)` | Restore from checkpoint |
| `RegisterValidationHook(hook)` | Add validation hook |
| `ExportFullState()` | Export complete state |

## Troubleshooting

### Initialization Failures

1. Check component dependencies
2. Verify configuration settings
3. Review logs for specific failure points

### Checkpoint Issues

1. Verify storage path exists and is writable
2. Check disk space
3. Review checkpoint policy settings

### Performance Tracking

1. Ensure `enablePerformanceTracking` is true
2. Check baseline output path
3. Verify file permissions

## Phase Completion Status

- ✅ Phase B.2: Swarm Integration (22/22 batches)
- ✅ Phase B.4: SEG Validation (5/5 batches)
- ✅ Phase B.5: Unified Sovereign Runtime (5/5 batches)
  - ✅ Batch 1/5: SovereignRuntimeBootstrap
  - ✅ Batch 2/5: PerformanceBaseline
  - ✅ Batch 3/5: CheckpointManager
  - ✅ Batch 4/5: RuntimeIntegration
  - ✅ Batch 5/5: Documentation

## Next Steps

1. Build and test the runtime
2. Run validation suite
3. Capture performance baselines
4. Test checkpoint/restore functionality
5. Deploy to production environment
