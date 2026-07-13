# Phase C.4 Batch 3/5: Autonomous Rollback Engine

## Overview

The Autonomous Rollback Engine is the self-healing layer of the sovereign runtime. It provides the ability to reverse autonomous mutations, restore stable state, and recover from instability without human intervention.

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                    RollbackManager                         │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │   Trigger   │  │    Engine    │  │   Validation    │  │
│  │   Monitor   │──│   Executor   │──│    & Verify     │  │
│  └─────────────┘  └──────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────┐      ┌──────────────┐      ┌─────────────────┐
│  Mutation   │      │   Rollback   │      │   Stability     │
│   Journal   │      │    Steps     │      │    Envelope     │
└─────────────┘      └──────────────┘      └─────────────────┘
```

### Component Responsibilities

1. **MutationJournal**: Records all mutations with before/after snapshots
2. **RollbackEngine**: Generates and executes rollback plans
3. **RollbackManager**: Monitors triggers and coordinates autonomous rollbacks

## Rollback Triggers

| Trigger | Condition | Severity |
|---------|-----------|----------|
| MANUAL | Operator initiated | INFO |
| OSCILLATION_SEVERE | Severe oscillation detected | SEVERE |
| OSCILLATION_CRITICAL | Critical oscillation detected | CRITICAL |
| CONVERGENCE_DROP | Convergence below threshold | WARNING |
| MEMORY_PRESSURE | Resource exhaustion | WARNING |
| TIMEOUT | Operation timeout | WARNING |
| SAFETY_VIOLATION | Safety envelope breach | CRITICAL |
| AUTONOMOUS_DECISION | System decision | INFO |

## Rollback Plans

### Partial Rollback
Reverts specific failed mutations:
```cpp
steps = [
    REVERT_MUTATION(id=5),
    REVERT_MUTATION(id=4),
    REVERT_MUTATION(id=3),
    VALIDATE_STABILITY
]
```

### Full Rollback
Restores complete system state:
```cpp
steps = [
    PAUSE_MUTATIONS,
    RESTORE_CHECKPOINT(id=42),
    RESTORE_GRAPH_TOPOLOGY,
    RESET_SCHEDULER_WEIGHTS,
    RESTORE_ROLE_ASSIGNMENTS,
    REINITIALIZE_SUBSYSTEMS,
    VALIDATE_STABILITY
]
```

## Rollback Steps

| Step Type | Description | Critical |
|-----------|-------------|----------|
| REVERT_MUTATION | Undo specific mutation | No |
| RESTORE_GRAPH_NODE | Restore graph topology | Yes |
| RESET_SCHEDULER_WEIGHTS | Reset scheduler config | No |
| RESTORE_ROLE_ASSIGNMENTS | Restore agent roles | No |
| RESTORE_INTENT_STRENGTHS | Restore intent values | No |
| RESTORE_CHECKPOINT | Restore from checkpoint | Yes |
| REINITIALIZE_SUBSYSTEM | Restart subsystem | Yes |
| CLEAR_MUTATION_HISTORY | Clear history | No |
| NOTIFY_OBSERVERS | Send notifications | No |

## Configuration

```cpp
struct RollbackConfig {
    bool enableAutoRollback = true;        // Enable autonomous rollback
    bool enablePartialRollback = true;     // Enable partial rollback
    bool enableFullRollback = true;        // Enable full rollback
    int maxRollbackSteps = 100;            // Max steps per rollback
    int rollbackTimeoutMs = 30000;         // Timeout for rollback
    int stabilityCheckDelayMs = 1000;    // Delay before stability check
    double minStabilityThreshold = 0.5;    // Minimum stability after rollback
    double minConvergenceThreshold = 0.6;  // Minimum convergence after rollback
    bool requireCheckpointValidation = true;
    bool notifyOnRollback = true;
    int maxRetries = 3;
};
```

## Usage

### Basic Rollback
```cpp
#include "autonomy/RollbackEngine.hpp"

using namespace Autonomy;

// Initialize components
MutationJournal journal;
StabilityEnvelope envelope;
RollbackEngine engine;

RollbackConfig config;
engine.Initialize(config, &journal, &envelope);

// Execute quick rollback
RollbackResult result = engine.QuickRollback();
if (result.success) {
    std::cout << "Rollback successful\n";
    std::cout << "Duration: " << result.durationMs << "ms\n";
    std::cout << "Stability: " << result.postRollbackStability << "\n";
}
```

### Triggered Rollback
```cpp
// Rollback due to oscillation
RollbackResult result = engine.Execute(
    RollbackTrigger::OSCILLATION_SEVERE,
    "Severe oscillation detected in decision patterns"
);
```

### Custom Rollback Plan
```cpp
// Generate plan for specific mutations
std::vector<uint64_t> mutations = {10, 11, 12};
RollbackPlan plan = engine.GeneratePlanForMutations(
    mutations,
    "Revert failed optimizations"
);

// Execute plan
RollbackResult result = engine.Execute(plan);
```

### Autonomous Rollback Manager
```cpp
RollbackManager manager;
manager.Initialize(config, &journal, &envelope, &oscillationManager);

// In main loop
while (running) {
    // Update checks triggers and executes rollbacks if needed
    manager.Update();
    
    // Other system updates...
}
```

## Mutation Reversal

Each mutation type has a reversible counterpart:

| Mutation | Reversal |
|----------|----------|
| ADD_PARALLEL_PATH | REMOVE_PARALLEL_PATH |
| MERGE_NODES | SPLIT_NODES |
| ADJUST_WEIGHTS | RESTORE_WEIGHTS (stored) |
| CHANGE_PRIORITY | RESTORE_PRIORITY (stored) |
| INSERT_ISOLATION | REMOVE_ISOLATION |
| REMOVE_REDUNDANCY | RESTORE_REDUNDANCY |

## Rollback Telemetry

Each rollback provides:
- Rollback reason
- Rollback severity
- Duration (ms)
- Steps completed/failed
- Post-rollback stability
- Post-rollback convergence
- Success/failure status

## Integration Points

### With Stability Envelope
```cpp
// Rollback validates against stability envelope
if (envelope->IsSafeToRollback()) {
    engine.Execute(plan);
}
```

### With Oscillation Manager
```cpp
// Severe oscillations trigger automatic rollback
if (oscillation.severity >= OscillationSeverity::SEVERE) {
    manager.TriggeredRollback(
        RollbackTrigger::OSCILLATION_SEVERE,
        "Severe oscillation detected"
    );
}
```

### With Mutation Journal
```cpp
// All mutations recorded for potential rollback
uint64_t mutationId = journal.BeginMutation(type, beforeSnapshot, decision);
// ... execute mutation ...
journal.CompleteMutation(mutationId, afterSnapshot, delta);
journal.CommitMutation(mutationId);
```

## Safety Features

1. **Atomic Execution**: Rollback steps are atomic
2. **Reversible Actions**: All rollback actions can be reversed
3. **Idempotent Operations**: Multiple executions produce same result
4. **Concurrency Safety**: Thread-safe execution
5. **Validation Gates**: Post-rollback stability validation
6. **Timeout Protection**: Rollback timeout prevents hanging
7. **Critical Step Handling**: Critical step failures abort rollback

## Performance Considerations

- Rollback plans are generated on-demand
- Mutation journal prunes old entries automatically
- Snapshots can be compressed for storage efficiency
- Rollback execution is parallelized where safe
- Validation uses configurable timeouts

## Testing

### Smoke Tests
1. Single mutation rollback
2. Multiple sequential mutations
3. Nested rollback scenarios
4. Interrupted rollback
5. Checkpoint restoration
6. Mutation journal replay
7. Convergence recovery
8. Oscillation-triggered rollback
9. Resource-triggered rollback
10. Deterministic replay

### Run Tests
```bash
./rollback-engine --interactive
```

Commands:
- `status` - Show current status
- `rollback` - Execute quick rollback
- `plan` - Show rollback plan
- `history` - Show rollback history
- `quit` - Exit

## Future Enhancements

1. Predictive rollback (before failure occurs)
2. Machine learning for optimal rollback points
3. Distributed rollback coordination
4. Incremental checkpoint restoration
5. Rollback simulation (dry-run)
6. Custom rollback step plugins

## References

- Phase C.4 Batch 1/5: Stability Envelope Specification
- Phase C.4 Batch 2/5: Oscillation Detection & Dampening
- Phase C.4 Batch 4/5: Safety-Gated Decision Engine (upcoming)
- Phase C.4 Batch 5/5: Autonomous Stability Validator (upcoming)
