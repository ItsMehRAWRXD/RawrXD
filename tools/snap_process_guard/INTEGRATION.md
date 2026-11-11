# SNAP Process Guard — Integration Guide

## Overview

This component adds stale-process detection and cleanup to the RawrXD Agent ESP. It uses native Windows APIs only — no third-party dependencies.

## Components

| File | Purpose |
|------|---------|
| `snap_process_guard.hpp` | Public API: enumeration, verification, job object, termination |
| `snap_process_guard_cli.cpp` | Command-line inspector and terminator |
| `snap_process_guard.hpp` | Include in any RawrXD component that needs process management |

## Build

```cmd
cmake -S F:\rawrxd\tools\snap_process_guard -B F:\rawrxd\build_snap_process_guard -G "Visual Studio 17 2022" -A x64
cmake --build F:\rawrxd\build_snap_process_guard --config Release
```

The CLI executable will be at:
`F:\rawrxd\build_snap_process_guard\Release\snap_process_guard_cli.exe`

## Integration into RawrXD

### 1. Add to CMake

```cmake
# In root CMakeLists.txt
add_subdirectory(tools/snap_process_guard)

# Link into targets that need process management
target_link_libraries(deep2_agentic_loop PRIVATE snap_process_guard)
```

### 2. Include the header

```cpp
#include "snap/process/snap_process_guard.hpp"

using namespace snap::process;
```

### 3. Scan for stale processes (in Agent ESP loop)

```cpp
StaleProcessScanner::Config cfg;
cfg.target_exe = L"F:\\rawrxd\\build_cmake\\bin\\Release\\deep2_agentic_loop.exe";
cfg.ram_warning_mb = 1024;
cfg.check_job_membership = true;
cfg.emit_esp_events = true;

StaleProcessScanner scanner(cfg);
auto report = scanner.scan();

if (report.contention_detected) {
    // Emit ESP warning event
    esp.publish(rawrxd::esp::Kind::ResourceContention, "stale processes detected", ...);
    for (auto& w : report.warnings) {
        esp.publish(rawrxd::esp::Kind::Warning, w, ...);
    }
}
```

### 4. Integrate Job Object for automatic child cleanup

```cpp
// In deep2_agentic_loop main(), before launching child processes:
JobObject job;
job.create(L"RawrXD_Agent_Job");
job.assign_self();  // Children inherit the job

// On shutdown, job automatically kills all assigned processes
```

### 4. Cooperative cancellation before forced termination

```cpp
// Before forced termination, attempt graceful shutdown
ProcessTerminator terminator;
bool graceful = terminator.try_graceful(pid, 5000);
if (!graceful) {
    auto result = terminator.terminate(pid, true /* confirmed */);
    // Log result
}
```

## CLI Usage

```cmd
# Scan for stale deep2_agentic_loop processes
snap_process_guard_cli.exe "F:\rawrxd\build_cmake\bin\Release\deep2_agentic_loop.exe" --scan

# Terminate a verified stale process (requires --confirm)
snap_process_guard_cli.exe "F:\rawrxd\build_cmake\bin\Release\deep2_agentic_loop.exe" --terminate-pid 12345 --confirm
```

## Security Boundaries

- **No model authority**: Process verification and termination are host-only operations. A model cannot trigger termination.
- **Path verification**: Every process is verified against the expected executable path before any action.
- **Confirmation required**: Termination requires explicit `--confirm` flag.
- **No arbitrary shell**: The terminator uses native APIs, never `system()` or `shell`.
- **Self-protection**: Policy defaults prevent self-termination.

## Agent ESP Events

The scanner emits these events when `emit_esp_events = true`:

| Event | Kind | Payload |
|-------|------|---------|
| Scan complete | `ScanComplete` | `{count: N, contention: true}` |
| Warning | `StaleProcessWarning` | `{pid, exe, working_set_mb, reason}` |
| Contention | `ResourceContention` | `{ram_mb, process_count}` |

These events flow through the existing Agent ESP publisher in `deep2_agentic_loop`.

## Limitations

- **GPU memory**: Reports RAM working set only. Per-process VRAM requires `DXGI`/`D3DKMT` queries.
- **Job assignment**: `is_job_assigned` is a best-effort check. Full implementation requires `IsProcessInJob`.
- **Graceful termination**: The `try_graceful` implementation is a placeholder. Full implementation needs console attach + `GenerateConsoleCtrlEvent`.

## Testing

```cmd
# Build
cmake --build build_snap_process_guard --config Release

# Run self-test
ctest --test-dir build_snap_process_guard -C Release --output-on-failure

# Manual scan
build_snap_process_guard\Release\snap_process_guard_cli.exe ^
  "F:\rawrxd\build_cmake\bin\Release\deep2_agentic_loop.exe" --scan
```

## Future Work

1. **GPU VRAM attribution**: Add D3DKMT queries for per-process VRAM.
2. **Cooperative protocol**: Define a shared-memory or named-pipe protocol for processes to self-report staleness.
3. **Automatic reaping**: Background thread that periodically scans and optionally terminates confirmed orphans.
4. **Cross-platform**: Linux `/proc` equivalent using `procfs`.