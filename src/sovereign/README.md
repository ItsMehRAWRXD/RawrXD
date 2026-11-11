# Sovereign Coordination System

## Overview

The Sovereign Coordination System transforms RawrXD from a collection of tools into a unified autonomous execution organism through 10 coordination primitives.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    EXECUTION CAPSULE                           │
│         (Unifies all 10 primitives into coherent system)       │
└─────────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│   EXECUTION   │      │    AGENT    │      │    BUILD     │
│    SPINE      │      │    LEASE    │      │ STATE GRAPH  │
│  (Primitive 1)│      │ (Primitive 4)│      │ (Primitive 3)│
└───────────────┘      └───────────────┘      └───────────────┘
        │                       │                       │
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│   TERMINAL    │      │    BEACON    │      │    INTENT    │
│  OWNERSHIP    │      │    EVENT     │      │ COMPRESSION  │
│  (Primitive 2)│      │     BUS      │      │ (Primitive 6)│
└───────────────┘      │ (Primitive 5)│      └───────────────┘
                       └───────────────┘              │
                              │                       │
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│    SYSTEM     │      │    REALITY   │      │   AUTONOMOUS  │
│   AWARENESS   │      │   VALIDATOR  │      │    RECOVERY   │
│ (Primitive 7) │      │ (Primitive 8)│      │  (Primitive 9)│
└───────────────┘      └───────────────┘      └───────────────┘
                                                       │
                                              ┌───────────────┐
                                              │   SOVEREIGN   │
                                              │ CONTROL PLANE │
                                              │(Primitive 10) │
                                              └───────────────┘
```

## The 10 Coordination Primitives

### 1. Execution Spine Hardening (`spine/`)
**Purpose**: Structured execution pipeline, never free-form tool loops
**Flow**: Intent → Plan → Capability Claim → Execution → Validation → Commit
**Key Files**: `ExecutionSpine.hpp/cpp`

### 2. Terminal Ownership Kernel (`terminal/`)
**Purpose**: Explicit terminal ownership with lease semantics
**Features**: Lease tokens, capability-based access, event subscription
**Key Files**: `TerminalOwnership.hpp` (existing)

### 3. Build State Graph (`build/`)
**Purpose**: Explicit build state machine with causal edges
**States**: IDLE → CONFIGURING → GENERATING → COMPILING → LINKING → SUCCEEDED/FAILED
**Key Files**: `BuildStateGraph.hpp/cpp`

### 4. Agent Lease System (`agent/`)
**Purpose**: Agents lease existence with heartbeat
**Features**: Tier-based capabilities, automatic expiry, parent-child relationships
**Key Files**: `AgentLease.hpp`

### 5. Beacon Event Bus (`bus/`)
**Purpose**: No polling - agents emit beacons, others subscribe
**Features**: Priority levels, request/response pattern, history
**Key Files**: `BeaconBus.hpp`

### 6. Intent Compression Protocol (`compression/`)
**Purpose**: Compress full conversation to ~200 bytes
**Features**: Classification, evidence extraction, similarity matching
**Key Files**: `IntentCompression.hpp`

### 7. Self-Awareness Layer (`awareness/`)
**Purpose**: System knows its own state, health, limitations
**Features**: Component health tracking, self-diagnostics
**Key Files**: `SystemAwareness.hpp`

### 8. Reality Validator (`validator/`)
**Purpose**: Verify expected state matches actual state
**Features**: Pluggable validation checks, file/symbol verification
**Key Files**: `RealityValidator.hpp`

### 9. Autonomous Recovery Loop (`recovery/`)
**Purpose**: Detect failures and attempt recovery without human intervention
**Features**: Recovery strategies, escalation handling
**Key Files**: `AutonomousRecovery.hpp`

### 10. Sovereign Control Plane UI (`control/`)
**Purpose**: Central dashboard for system visibility and control
**Features**: Panel management, action execution
**Key Files**: `SovereignControlPlane.hpp`

## Execution Capsule (`capsule/`)

The Execution Capsule binds all 10 primitives into a unified organism:

```cpp
ExecutionCapsule& capsule = ExecutionCapsule::Instance();
capsule.Initialize();

// Execute with full coordination
auto result = capsule.ExecuteIntent(intent);

// Spawn managed agents
auto agent_id = capsule.SpawnAgent(descriptor);

// Build with state tracking
capsule.ExecuteBuild("target", config);
```

## IDE Integration (`ide/`)

Connects the Sovereign system to the RawrXD Win32 IDE:

```cpp
IDEWindowHandles handles;
handles.main_window = hWnd;
// ... set other handles

SovereignIDEIntegration::Instance().Initialize(handles);

// Now IDE commands use the coordination system
SovereignIDEIntegration::Instance().SpawnEditorAgent("Edit file.cpp");
SovereignIDEIntegration::Instance().TriggerBuild("all");
```

## Directory Structure

```
sovereign/
├── spine/              # Execution Spine Hardening
├── terminal/           # Terminal Ownership Kernel
├── build/              # Build State Graph
├── agent/              # Agent Lease System
├── bus/                # Beacon Event Bus
├── compression/        # Intent Compression Protocol
├── awareness/         # Self-Awareness Layer
├── validator/          # Reality Validator
├── recovery/           # Autonomous Recovery Loop
├── control/            # Sovereign Control Plane UI
├── capsule/            # Execution Capsule (unification)
└── ide/                # RawrXD IDE Integration
```

## Integration Points

### With RawrXD IDE
- `SovereignIDEIntegration` bridges IDE commands to coordination primitives
- UI panels updated via beacon subscriptions
- Terminal ownership enforced for all IDE terminal operations

### With Build System
- `BuildStateGraph` tracks CMake/Ninja build progress
- State transitions emit beacons for UI updates
- Automatic retry on failure via Recovery Loop

### With Agent System
- All agents must hold valid lease
- Heartbeats required for lease renewal
- Parent-child relationships tracked

## Usage Example

```cpp
#include "sovereign/capsule/ExecutionCapsule.hpp"
#include "sovereign/ide/SovereignIDEIntegration.hpp"

using namespace Sovereign;

// Initialize the capsule
CapsuleConfig config;
config.enable_recovery = true;
config.enable_awareness = true;

ExecutionCapsule::Instance().Initialize(config);

// Create an intent
FullIntent intent;
intent.original_prompt = "Fix the bug in main.cpp";
intent.interpreted_goal = "Fix bug";
intent.target_file = "main.cpp";
intent.type = IntentType::FILE_EDIT;

// Execute through the spine
auto result = ExecutionCapsule::Instance().ExecuteIntent(intent);

// The capsule handles:
// - Intent compression (~200 bytes)
// - Agent lease acquisition
// - Terminal ownership
// - Build state tracking
// - Beacon emission
// - Validation
// - Recovery on failure
```

## Status

✅ All 10 coordination primitives implemented
✅ Execution Capsule integration complete
✅ RawrXD IDE integration complete

The system now behaves as a unified organism rather than a collection of tools.
