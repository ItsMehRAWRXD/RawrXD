# Integration Framework — Quick Reference Card

## TL;DR
- **Header-only**, opt-in integration for observability without touching core logic
- All features gated by **environment variables** (zero cost when disabled)
- Used in: Stub widget macro, VersionControlWidget, BuildSystemWidget

## Modules at a Glance

| Module | Purpose | Key Class/Function |
|--------|---------|-------------------|
| `ProdIntegration.h` | Config + core primitives | `Config`, `ScopedTimer`, `logInfo()`, `recordMetric()`, `traceEvent()` |
| `InitializationTracker.h` | Startup tracking | `InitializationTracker`, `ScopedInitTimer` |
| `Logger.h` | Structured logging | `Logger::info()/.debug()/.warn()/.error()` |
| `Diagnostics.h` | Runtime introspection | `Diagnostics::initializationReport()`, `::initializationSummary()` |
| `ResourceGuards.h` | RAII resource cleanup | `ResourceGuard<T>`, `ScopedAction` |
| `examples.h` | Usage patterns (9 examples) | Various example classes |

## Environment Variables

```bash
RAWRXD_LOGGING_ENABLED=1        # Enable structured logging
RAWRXD_LOG_STUBS=1              # Log stub widget construction
RAWRXD_ENABLE_METRICS=1         # Emit metrics
RAWRXD_ENABLE_TRACING=1         # Emit trace events
```

All default to disabled ⟹ **zero overhead in production**.

## One-Line Usage Examples

```cpp
// Measure constructor latency
ScopedInitTimer init("MyWidget");

// Measure method latency
ScopedTimer timer("Component", "object", "operation");

// Log info event
logInfo("Component", "event", "Message");

// Record metric
recordMetric("metric_name");

// Trace event
traceEvent("Component", "event_name");

// Chain-style logging
Logger::info().component("X").event("Y").message("Z");

// Get startup report
auto report = Diagnostics::initializationReport();

// RAII resource guard
ResourceGuard<FilePtr> file(ptr, [](auto p) { delete p; });

// Scoped cleanup action
ScopedAction cleanup([](){ /* cleanup */ });
```

## File Locations

All in `src/qtapp/integration/`:
- `ProdIntegration.h` — Core config + ScopedTimer
- `InitializationTracker.h` — Startup tracking
- `Logger.h` — Chainable logging
- `Diagnostics.h` — JSON reports + summaries
- `ResourceGuards.h` — RAII wrappers
- `examples.h` — 9 practical patterns
- `INTEGRATION-GUIDE.md` — Comprehensive guide
- `README-Integration.md` — Module overview

## Instrumented Real Widgets

| Widget | Constructor | Key Methods |
|--------|-------------|-------------|
| Stub widgets (macro) | ✅ Logs + timer | — |
| VersionControlWidget | ✅ ScopedInitTimer | `refresh()` ✅ |
| BuildSystemWidget | ✅ ScopedInitTimer | `startBuild()` ✅ |

## Performance Checklist

- ✅ Header-only: Zero compilation overhead
- ✅ Environment gated: Zero cost when disabled
- ✅ RAII-based: No manual cleanup
- ✅ Zero copy: Strings use Qt's CoW
- ✅ Lazy initialized: No global state penalty

## Quick Start

1. **Enable in your code**:
   ```cpp
   #include "integration/ProdIntegration.h"
   void MyClass::MyClass() {
       RawrXD::Integration::ScopedInitTimer init("MyClass");
   }
   ```

2. **Run with env vars**:
   ```powershell
   $env:RAWRXD_LOGGING_ENABLED = "1"
   ./RawrXD-AgenticIDE.exe
   ```

3. **View output**: Check application log/console output

## Migration Path

| Phase | Task |
|-------|------|
| 1 | ✅ Add integration headers (done) |
| 2 | ✅ Instrument constructors + key methods (done) |
| 3 | Replace log stubs with Prometheus/OpenTelemetry backends |
| 4 | Add distributed tracing support |
| 5 | Integrate with ELK/Grafana stack |

## Production Deployment

```yaml
# Kubernetes Pod Spec
env:
  - name: RAWRXD_LOGGING_ENABLED
    value: "0"  # Disabled in production by default
  - name: RAWRXD_ENABLE_METRICS
    value: "1"  # Metrics only (no stdout spam)
  - name: RAWRXD_ENABLE_TRACING
    value: "1"  # Distributed tracing
```

## Common Patterns

### Measure Function Duration
```cpp
void expensiveFunction() {
    RawrXD::Integration::ScopedTimer timer("Module", "func", "expensive");
    // ... work ...
}  // Logs latency_ms on destruction
```

### Track Initialization Order
```cpp
ScopedInitTimer dbTimer("Database");
initDatabase();

ScopedInitTimer uiTimer("UI");
initUI();

// Print report
Diagnostics::dumpInitializationReport();
```

### Conditional Logging
```cpp
if (RawrXD::Integration::Config::loggingEnabled()) {
    logInfo("Component", "event", "Details");
}
```

### Resource Cleanup
```cpp
{
    ResourceGuard<FILE*> file(fopen(...), [](FILE* f) { fclose(f); });
    // Use file
}  // File automatically closed
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No output despite env var set | Verify Qt debug mode enabled, check console |
| Performance impact | Disable all env vars; use only metrics in production |
| Compilation errors | Ensure `src/qtapp/integration/` exists in CMakeLists.txt |
| Missing headers | Run CMake regenerate, rebuild |

## Links & References

- **Full Guide**: `INTEGRATION-GUIDE.md`
- **Module Docs**: `README-Integration.md`
- **Code Examples**: `examples.h`
- **Instructions**: `/c:/.aitk/instructions/tools.instructions.md`

---

**Status**: All integration modules implemented and instrumented. Ready for production opt-in.

**Last Updated**: 2026-01-11
