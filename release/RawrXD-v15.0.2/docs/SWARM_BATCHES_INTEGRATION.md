# Swarm Batches Integration Guide

## Overview

This document describes the integration between **SovereignSwarm** (Batches 250-256) and **InfinitePerfectionEngine** (Batches 243-249), enabling the full Unity Cycle execution pipeline.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SovereignSwarm Layer                        │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐             │
│  │  Order  │ │Resonance│ │Amplify  │ │Integrate│             │
│  │(Batch 250)│ │(Batch 251)│ │(Batch 252)│ │(Batch 253)│             │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘             │
│       │           │           │           │                    │
│  ┌────┴────┐ ┌────┴────┐ ┌────┴────┐ ┌────┴────┐             │
│  │Converge │ │Coherence│ │ Harmony │ │Balance  │             │
│  │(Batch 254)│ │(Batch 255)│ │(Batch 256)│ │(Batch 249)│             │
│  └────┬────┘ └────┬────┘ └────┬────┘ └─────────┘             │
│       │           │           │                              │
└───────┼───────────┼───────────┼──────────────────────────────┘
        │           │           │
        ▼           ▼           ▼
┌─────────────────────────────────────────────────────────────────┐
│              InfinitePerfectionEngine Layer                     │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐             │
│  │  Unity  │ │Integrate│ │Synthesis│ │Converge │             │
│  │(Batch 243)│ │(Batch 244)│ │(Batch 245)│ │(Batch 246)│             │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘             │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐                         │
│  │Coherence│ │ Harmony │ │ Balance │                         │
│  │(Batch 247)│ │(Batch 248)│ │(Batch 249)│                         │
│  └─────────┘ └─────────┘ └─────────┘                         │
└─────────────────────────────────────────────────────────────────┘
```

## Mapping: Swarm Tasks → Engine Cycles

| Swarm Batch | Swarm TaskKind | Engine Batch | Engine Cycle | Compute Method |
|-------------|----------------|--------------|--------------|----------------|
| 250 | Order | 243 | `RunUnityCycle()` | `ComputeCycleIntegration()` |
| 251 | Resonance | 244 | `RunIntegrationCycle()` | `ComputeHarmonicLock()` |
| 252 | Amplification | 245 | `RunSynthesisCycle()` | `ComputeCrossCycleSynergy()` |
| 253 | Integration | 246 | `RunConvergenceCycle()` | `ComputeConvergenceCoherence()` |
| 254 | Convergence | 247 | `RunCoherenceCycle()` | `ComputePhaseLockStrength()` |
| 255 | Coherence | 248 | `RunHarmonyCycle()` | `ComputeSovereignHarmonyIndex()` |
| 256 | Harmony | 249 | `RunBalanceCycle()` | `ComputeEquilibriumStrength()` |

## Usage

### CLI Commands

Execute the full Unity Sequence:
```bash
rawrxd swarm --unity-sequence
```

With detailed logging:
```bash
rawrxd swarm --unity-sequence --unity-sequence-log
```

Export results to JSON:
```bash
rawrxd swarm --unity-sequence --unity-sequence-output results.json
```

### Programmatic API

```cpp
#include "SovereignSwarm.hpp"
#include "InfinitePerfectionEngine.hpp"

// Create context
Sovereign::SwarmAgentContext ctx;
ctx.engine = &InfinitePerfection::InfinitePerfectionEngine::GetInstance();

// Create swarm
Sovereign::SovereignSwarm swarm(ctx);

// Execute Unity Sequence
auto& engine = InfinitePerfection::InfinitePerfectionEngine::GetInstance();
engine.Initialize();

auto result = swarm.ExecuteUnitySequence(engine);

// Access results
std::cout << "Harmony Index: " << result.finalHarmonyIndex << std::endl;
std::cout << "Equilibrium: " << result.finalEquilibriumStrength << std::endl;
std::cout << "Execution Time: " << result.totalExecutionTimeMs << "ms" << std::endl;

// Log metrics
swarm.LogUnitySequenceMetrics(result);

engine.Shutdown();
```

## Implementation Phases

### Phase 1: Engine Cycle Invocation ✅
- Modified `SwarmAgent::Execute()` to call appropriate `Run*Cycle()` methods
- Returns engine-derived metrics instead of simulated values
- Handles exceptions and records failures in SelfModelRegistry

### Phase 2: CLI Integration ✅
- Added `--unity-sequence` flag to SwarmCommand
- Added `--unity-sequence-log` for detailed metrics
- Added `--unity-sequence-output` for JSON export
- Engine initialization/shutdown handled automatically

### Phase 3: Telemetry Integration ✅
- Records each Unity Sequence step execution
- Tracks cycle integration, harmonic lock, cross-cycle synergy
- Enables real-time monitoring of convergence

### Phase 4: Smoke Test ✅
- End-to-end validation of full pipeline
- Checks all 7 steps execute successfully
- Validates metrics in range [0.0-1.0]
- Verifies convergence achieved (harmony > 0.5)
- Ensures execution time < 60 seconds

## Validation Criteria

A successful Unity Sequence execution must:

1. **Execute All Steps**: All 7 cycles (Order→Harmony) complete without exception
2. **Valid Metrics**: All returned metrics in range [0.0, 1.0]
3. **Convergence**: Final harmony index > 0.5
4. **Performance**: Total execution time < 60 seconds
5. **Telemetry**: Execution data captured for analysis

## Files Modified

| File | Changes |
|------|---------|
| `src/swarm/SovereignSwarm.cpp` | Engine cycle invocation, UnitySequence implementation |
| `src/swarm/SovereignSwarm.hpp` | UnitySequenceResult struct, method declarations |
| `src/cli/SwarmCommand.cpp` | CLI flags for Unity Sequence |
| `src/cli/SwarmCommand.hpp` | Option struct additions |
| `src/swarm/InfinitePerfectionTelemetry.cpp` | Telemetry recording |
| `src/swarm/UnitySequenceSmokeTest.cpp` | End-to-end validation test |

## Testing

Run the smoke test:
```bash
# Compile
g++ -std=c++20 -I. src/swarm/UnitySequenceSmokeTest.cpp -o unity_smoke_test

# Run
./unity_smoke_test
```

Expected output:
```
╔══════════════════════════════════════════════════════════════╗
║     Phase 4: Unity Sequence Smoke Test                       ║
║     Validating Order→Harmony Pipeline                        ║
╚══════════════════════════════════════════════════════════════╝

[SmokeTest] Executing Unity Sequence...
[UnitySequence] Step 1/7: ORDER (Unity Cycle 243)...
  → Cycle Integration: 0.XXXX
...
[UnitySequence] Step 7/7: HARMONY (Balance Cycle 249)...
  → Equilibrium Strength: 0.XXXX

╔══════════════════════════════════════════════════════════════╗
║     Smoke Test Result: ✓ PASSED                              ║
╠══════════════════════════════════════════════════════════════╣
║  Total Time: XXXXms                                          ║
║  Final Harmony Index: 0.XXXX                                 ║
║  Final Equilibrium: 0.XXXX                                   ║
╚══════════════════════════════════════════════════════════════╝
```

## Future Enhancements

- **Phase 5**: Parallel execution of independent cycles
- **Phase 6**: Dynamic cycle ordering based on convergence state
- **Phase 7**: Integration with external monitoring dashboards
- **Phase 8**: Automatic retry on cycle failure

## References

- `InfinitePerfectionEngine.hpp`: Engine cycle declarations (Batches 243-249)
- `SovereignSwarm.hpp`: Swarm task kinds (Batches 250-256)
- `InfinitePerfectionTelemetry.hpp`: Telemetry bridge documentation
