# RawrXD Missing-Source Batch 2

Authority baseline: GitHub `master` at `d6062ecc7a55476b86cd9569a2117b53083440bb`.

## Why this batch is required

The root `rawr_monolith` target no longer references the seven historical missing
translation units. The full `rawrxd/CMakeLists.txt` Win32IDE source list still does.

The full IDE build also contains compatibility/link-closure units. In strict production
mode those must not be allowed to provide fake symbol ownership.

## What this batch does

1. Installs `cmake/RawrXDStrictWin32IDESourceClosure.cmake`.
2. Includes it immediately before `add_executable(RawrXD-Win32IDE ...)`.
3. Removes these source-list entries *only when absent on disk*:
   - src/ai_completion_real.cpp
   - src/vulkan_kernel_bridge.cpp
   - src/gguf_d3d12_bridge.cpp
   - src/rdna3_bridge.cpp
   - src/agentic_engine.cpp
   - src/subagent_core.cpp
4. Requires the real `src/ANSIParser.cpp` from Batch 1.
5. Under `RAWRXD_PRODUCTION_STRIP_STUB_SOURCES=ON`, removes known stub/link closure TUs.
6. Fails configuration for any other missing concrete source file.
7. Runs a strict Release/NMake Win32IDE build.
8. Extracts real compile/link failures into `batch3_unresolved_symbols.txt`.

## Apply

```powershell
Expand-Archive F:\PATH\rawrxd_missing_source_batch2.zip F:\~dev\_batch2 -Force

& F:\~dev\_batch2\tools\apply_batch2_source_closure.ps1 `
    -Repo F:\~dev\rawrxd

& F:\~dev\_batch2\tools\audit_strict_ide_sources.ps1 `
    -Repo F:\~dev\rawrxd `
    -OutDir F:\~dev\evidence\STRICT_IDE_SOURCE_CLOSURE_002

& F:\~dev\_batch2\tools\configure_build_strict_win32ide.ps1 `
    -Repo F:\~dev\rawrxd `
    -Build F:\~dev\build_win32ide_strict_b2 `
    -Evidence F:\~dev\evidence\STRICT_IDE_SOURCE_CLOSURE_002
```

## Hard no-deps note

Current `rawrxd/CMakeLists.txt` performs `FetchContent` for nlohmann/json and links
`nlohmann_json::nlohmann_json` into the Win32 IDE. This violates a literal
offline/no-third-party-source policy. Batch 2 audits and records that dependency but does
not fake a JSON implementation or silently vendor somebody else's source.

Batch 3 should replace only the live JSON-consuming contracts with native RawrXD parsing,
or remove the feature if it is demonstrably dead. The strict build/link output determines
which work is actually required.

## Expected result

There are only two valid outcomes:

- PASS: RawrXD-Win32IDE builds without compatibility ownership.
- FAIL: the compiler/linker emits exact real contracts for Batch 3.

There is deliberately no timeout-as-success, empty implementation, unconditional success
return, or missing-handler fallback.
