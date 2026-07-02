# Sovereign SDK v1.0.0

## Overview

The **Sovereign SDK** exposes the RawrXD 18-component framework as a Windows x64 DLL.
Any C/C++/C# or Rust application can `LoadLibrary("sovereign.dll")` and render
predictive ghost text, install hooks, stream AI tokens, and collect sub-millisecond
telemetry without writing a single line of assembly.

## Files

| File | Purpose |
|------|---------|
| `sovereign.dll` | The framework DLL (no CRT dependency) |
| `sovereign.lib` | Import library for static linking |
| `sovereign.h`   | C/C++ header with all typedefs and prototypes |
| `sovereign.def` | Export definitions (for custom linking) |
| `test_sdk.exe`  | Smoke test — validates all 27 exports |

## Quick Start (C)

```c
#include "sovereign.h"
#include <windows.h>
#include <stdio.h>

int main(void) {
    HMODULE h = LoadLibraryA("sovereign.dll");
    if (!h) { printf("Failed to load DLL\n"); return 1; }

    // One-shot init
    typedef int (*fn_init)(void);
    fn_init init = (fn_init)GetProcAddress(h, "SovereignInitAll");
    if (init) init();

    // Push a prediction
    typedef int (*fn_push)(const char*, size_t, unsigned int);
    fn_push push = (fn_push)GetProcAddress(h, "PushGhostPrediction");
    if (push) push("Hello World", 11, 0x3F733333); // 0.95f as bits

    // Render to HWND (0 = test mode)
    typedef int (*fn_render)(void*);
    fn_render render = (fn_render)GetProcAddress(h, "RenderGhostPredictive");
    if (render) render(NULL);

    // Shutdown
    typedef void (*fn_shutdown)(void);
    fn_shutdown shutdown = (fn_shutdown)GetProcAddress(h, "SovereignShutdown");
    if (shutdown) shutdown();

    FreeLibrary(h);
    return 0;
}
```

## API Surface (27 Exports)

### Ghost Engine
- `InitGhostBuffer()` — Initialize ring buffer
- `PushGhostPrediction(text, len, confidenceBits)` — Push prediction
- `RenderGhostPredictive(hWnd)` — Render next pending prediction
- `FlushGhostBuffer()` — Clear all predictions
- `GhostHeartbeat(hWnd)` — Periodic UI maintenance
- `GetGhostLatency()` → cycles
- `GetGhostStats(out)` → statistics
- `SetConfidenceThreshold(bits)` / `GetConfidenceThreshold()`

### Model Streamer
- `StreamerInit()` — Initialize bridge
- `StreamerPushToken(token, confidenceBits)` — Push single token
- `StreamerFlush()` — Flush buffer to Ghost Engine
- `StreamerSetConfidence(bits)`

### Hook Simulator
- `InstallHook(target, handler)` — 5-byte JMP detour
- `UninstallHook()` — Restore original bytes
- `GetHookLatencyStats(out)` — Timing statistics

### Symbolic Validator
- `ValidateTokenSIMD(token, len)` — AVX2 validation
- `FNV1A_64(data, len)` — 64-bit hash
- `BuildSymbolHashTable(hModule)` — PE symbol table
- `ResolveSymbolFromPE(hModule, hash)` → symbol address

### Telemetry
- `TelemetryPush(cycles)` — Push latency sample
- `TelemetryRead()` → cycles (0 if empty)
- `RunTelemetryStress(iterations)` → average cycles

### Lifecycle
- `SovereignVersion()` → "1.0.0"
- `SovereignInitAll()` — One-shot init all subsystems
- `SovereignShutdown()` — Graceful cleanup
- `PinThreadToCore(coreIndex)` — Thread affinity

## Important: Float Parameter ABI

The MASM functions expect **float parameters as raw IEEE-754 bit patterns**
(`unsigned int`), not `float` values. This avoids XMM0/RCX ABI mismatches.

```c
// WRONG: float goes in XMM0, MASM expects it in RDX
push("text", 4, 0.95f);

// CORRECT: pass raw bits
push("text", 4, 0x3F733333); // 0.95f
```

In C++, use `std::bit_cast<unsigned int>(0.95f)` (C++20) or a union.

## Build

```powershell
# Assemble all MASM components
.\build_complete.ps1

# Build the DLL
.\build_dll.ps1

# Compile smoke test
cl.exe /O2 /TC /W3 /nologo /Fe:test_sdk.exe test_sdk.c
```

## Architecture

- **No CRT dependency** — `/NODEFAULTLIB`, minimal `DllMain` stub
- **Fixed base address** — `0x10000000` for ADDR32 compatibility
- **x64 ABI compliant** — All non-volatile registers preserved
- **Thread-safe** — `LOCK XADD` on ring buffer indices
- **Latency budget** — 0.5ms (1.5M cycles @ 3GHz)

## License

Proprietary / Commercial — See INTEGRATION_HANDOFF.md
