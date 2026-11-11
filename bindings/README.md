# OMEGA-1 Engine & Sovereign SDK Bindings

This directory contains official language bindings for the OMEGA-1 Self-Mutating Engine (IAT slots 64-75) and Sovereign SDK.

## OMEGA-1 Engine Bindings

### Supported Languages

| Language | File/Package | Status |
|----------|-------------|--------|
| C# | `csharp/Omega1Engine.cs` | ✅ Ready |
| Rust | `rust/omega1_engine/` | ✅ Ready |
| Python | `python/omega1_engine.py` | ✅ Ready |
| Go | `go/omega1/` | ✅ Ready |

### Quick Start

**C#:**
```csharp
using var engine = new Omega1Engine();
engine.Initialize(Omega1Flags.None);
string result = engine.ExecutePowerShell("Get-Date");
```

**Rust:**
```rust
let mut engine = Omega1Engine::new();
engine.initialize_simple()?;
let output = engine.execute_powershell("Get-Date")?;
```

**Python:**
```python
engine = Omega1Engine()
engine.initialize_simple()
result = engine.execute_powershell("Get-Date")
```

**Go:**
```go
engine := omega1.New()
engine.InitializeSimple()
result, _ := engine.ExecutePowerShell("Get-Date")
```

### IAT Slot Reference

| Slot | Function | Description |
|------|----------|-------------|
| 64 | `Omega1_Initialize` | Initialize engine context |
| 65 | `Omega1_Shutdown` | Cleanup resources |
| 66 | `Omega1_GetModuleCount` | Get loaded module count |
| 67 | `Omega1_IsMutant` | Check mutant status |
| 68 | `Omega1_GetMutationCount` | Get mutation count |
| 69 | `Omega1_ExecuteReflective` | Execute reflective payload |
| 70 | `Omega1_ValidateIntegrity` | Validate binary integrity |
| 71 | `Omega1_TriggerMutation` | Trigger mutation event |
| 72 | `Omega1_GetManifestJson` | Get JSON manifest |
| 73 | `Omega1_ExecutePowerShell` | Execute PowerShell command |
| 74 | `Omega1_LoadModule` | Load PowerShell module |
| 75 | `Omega1_InvokeModule` | Invoke module function |

## Sovereign SDK Bindings

### Python

File: `bindings/python/sovereign_sdk.py`

- Uses ctypes only (no extra dependency)
- Wires lifecycle and status calls

### Node.js

File: `bindings/nodejs/sovereign_sdk.js`

- Scaffold for ffi-napi/ref-napi integration
- Keeps ABI stable while SDK evolves

## Contract Rule

Do not add engine logic in bindings.
Bindings must only call exported C ABI functions.
