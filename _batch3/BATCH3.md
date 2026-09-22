# RawrXD Batch 3 — Strict Offline Dependency Closure

## Scope

Batch 3 removes the stale unconditional nlohmann/json FetchContent dependency from
the strict Win32IDE production lane.

It intentionally does **not** invent a replacement JSON API before the compiler proves
which JSON contracts are actually part of the shipping target.

Current source evidence shows JSON usage exists in the wider tree, for example
`src/core/session_manager.cpp` and `src/core/settings_persistence.cpp`. Those files are
not currently listed in the active Win32IDE source closure found in CMake, so they are
not sufficient reason to import or recreate a third-party JSON dependency in the
shipping IDE.

## Files

- tools/apply_batch3_offline_dependency_closure.ps1
- tools/audit_batch3_external_dependencies.ps1
- tools/configure_build_batch3_offline.ps1
- tools/classify_batch4_contracts.ps1

## Apply

Run Batch 1 and Batch 2 first.

```powershell
Expand-Archive F:\PATH\rawrxd_missing_source_batch3.zip F:\~dev\_batch3 -Force

& F:\~dev\_batch3\tools\apply_batch3_offline_dependency_closure.ps1 `
  -Repo F:\~dev\rawrxd

& F:\~dev\_batch3\tools\audit_batch3_external_dependencies.ps1 `
  -Repo F:\~dev\rawrxd `
  -OutDir F:\~dev\evidence\STRICT_IDE_OFFLINE_003

& F:\~dev\_batch3\tools\configure_build_batch3_offline.ps1 `
  -Repo F:\~dev\rawrxd `
  -Build F:\~dev\build_win32ide_strict_b3 `
  -Evidence F:\~dev\evidence\STRICT_IDE_OFFLINE_003

& F:\~dev\_batch3\tools\classify_batch4_contracts.ps1 `
  -Contracts F:\~dev\evidence\STRICT_IDE_OFFLINE_003\batch4_contracts.txt
```

## Valid outcomes

### PASS
`RawrXD-Win32IDE` builds with FetchContent fully disconnected and no nlohmann target.

### FAIL
`batch4_contracts.txt` contains the exact active source/header/link contracts that must
be implemented in Batch 4.

A failure is authoritative evidence. Do not reintroduce FetchContent and do not add
empty compatibility files.

## Policy

Allowed:
- C++20 standard library
- Windows SDK
- Vulkan SDK already required by Deep2

Disallowed in strict source ownership:
- FetchContent downloads
- package downloads during configure/build
- stub/mock/shim symbol authority
- timeout-as-success
- empty compatibility translation units
- invented source files without a live declaration/caller/link contract
