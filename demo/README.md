# Sovereign Substrate Demo

## Overview

This demo application showcases the complete Sovereign Substrate architecture working together. It demonstrates:

1. **Security Hardening** - Rate limiting, input validation, audit logging
2. **Repository Memory Graph** - Project understanding persistence
3. **Model Adapter** - Interchangeable AI backends (Kimi, Moonshot, GGUF)
4. **Agent Kernel** - Resource scheduling and multi-agent coordination
5. **Intent Execution Pipeline** - End-to-end intent processing
6. **Control Plane UI** - Live monitoring and status
7. **Persistence** - Save/load project state

## Building

```bash
# From project root
mkdir build && cd build
cmake ..
make demo_sovereign_substrate
```

## Running

```bash
./demo_sovereign_substrate
```

## Demo Scenarios

### Scenario 1: Simple Intent Execution
Shows the complete flow from model response → intent → execution:
- Model generates an intent to optimize code
- Intent is validated through security checks
- Pipeline executes the intent
- Result is logged to audit trail

### Scenario 2: Rate Limiting
Demonstrates abuse prevention:
- Rapidly submits 10 intents
- Shows rate limiting kicking in
- Displays which intents were allowed vs blocked

### Scenario 3: Security Violation Detection
Shows security guardrails in action:
- Attempts path traversal attack (`../../../etc/passwd`)
- System detects and blocks the violation
- Logs security event to audit trail

### Scenario 4: Persistence
Demonstrates save/load functionality:
- Saves repository graph to disk
- Shows file size and contents
- Reloads and verifies integrity

### Scenario 5: Multi-Agent Coordination
Shows resource scheduling:
- 5 agents compete for build slots
- Demonstrates lease acquisition and release
- Shows contention statistics

## Architecture Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        DEMO FLOW                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. INITIALIZATION                                              │
│     ├── Security Manager (STANDARD level)                       │
│     ├── Repository Graph (scan demo project)                    │
│     ├── Model Adapter (register Kimi + Moonshot)              │
│     ├── Agent Kernel (resource scheduler)                     │
│     ├── Intent Pipeline (register handlers)                   │
│     └── Control Plane UI (port 18080)                         │
│                                                                 │
│  2. SCENARIO EXECUTION                                          │
│     ├── Model generates intent                                  │
│     ├── Security pre-check (rate limits, validation)          │
│     ├── Pipeline execution (firewall → transaction)           │
│     ├── Security post-log (audit trail)                       │
│     └── Statistics display                                      │
│                                                                 │
│  3. SHUTDOWN                                                    │
│     ├── Graceful component shutdown                           │
│     ├── Resource cleanup                                        │
│     └── Demo project cleanup                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Expected Output

```
╔═══════════════════════════════════════════════════════════════════╗
║                    SOVEREIGN SUBSTRATE DEMO                       ║
╚═══════════════════════════════════════════════════════════════════╝

Initializing all systems...

┌─ Security Hardening ──────────────────────────────────────────────┐
  ✓ Security manager initialized at STANDARD level
  ℹ Audit logging: ENABLED
  ℹ Rate limiting: ENABLED
  ℹ Input validation: ENABLED

┌─ Repository Memory Graph ───────────────────────────────────────┐
  ✓ Repository graph initialized
  ℹ Files scanned: 4
  ℹ Symbols indexed: 0

┌─ Model Adapter ─────────────────────────────────────────────────┐
  ✓ Kimi backend registered
  ✓ Moonshot backend registered
  ℹ Available backends: 2

┌─ Agent Kernel ──────────────────────────────────────────────────┐
  ✓ Agent kernel initialized
  ℹ Resource scheduler: ACTIVE
  ℹ Beacon bus: ACTIVE

┌─ Intent Execution Pipeline ─────────────────────────────────────┐
  ✓ Pipeline initialized
  ℹ Handlers registered: MODIFY_FUNCTION, BUILD_PROJECT, ...

┌─ Control Plane UI ────────────────────────────────────────────┐
  ✓ Control plane UI initialized on port 18080
  ℹ Dashboard: http://localhost:18080

└─────────────────────────────────────────────────────────────────────┘
✓ All systems initialized successfully!

[Press Enter to start Scenario 1...]
```

## Interactive Elements

The demo pauses between scenarios, allowing you to:
- Read the output
- Check the Control Plane UI at http://localhost:18080
- Observe the system state

Press **Enter** to advance to the next scenario.

## Troubleshooting

### Port Already in Use
If port 18080 is taken, the Control Plane will show a warning but the demo continues.

### Model Backends
The demo uses stub backends that simulate API responses. In production, you would:
1. Set API keys via environment variables
2. Configure endpoints in `backends/*.json`
3. Enable real HTTP clients

### Security Level
The demo runs at `STANDARD` security level. For stricter testing:
```cpp
SecurityManager::Instance().Initialize(SecurityLevel::HIGH);
```

## Extending the Demo

### Add New Scenarios

```cpp
void RunScenario6_Custom() {
    PrintBanner("SCENARIO 6: Custom Demo");
    // Your custom logic here
}
```

### Use Real Model Backends

```cpp
// In Initialize()
BackendConfig kimiConfig;
kimiConfig.api_key = std::getenv("KIMI_API_KEY");
kimiConfig.endpoint = "https://api.moonshot.cn";
auto kimiBackend = std::make_shared<KimiBackend>(kimiConfig);
ModelAdapter::Instance().RegisterBackend(kimiBackend);
```

### Connect to Real Repository

```cpp
// Change the repo path
demo.Initialize("/path/to/your/project");
```

## The Constitution in Action

> **The model proposes. The IDE decides. The Agent evolves.**

This demo shows that principle:
- **Model proposes**: Generates intents via ModelAdapter
- **IDE decides**: Guardrails validate and security approves
- **Agent evolves**: Pipeline executes and learns from results

---

**Part of:** Sovereign Substrate v1.0  
**Total Lines:** ~19,000
