# RAWRXD_IDE_STUB_CLOSURE_RECOVERY_001

This is a **fail-closed recovery/closure source drop** for the interrupted RawrXD Win32IDE stub-removal pass.

## What it contains

- 37 exact historical `win32app` source bodies extracted from the retained `Win32_IDE_Complete.cpp` corpus.
- 33 production apply candidates after excluding explicit test/harness/stub-named recovery sources.
- Standalone copies restore include directives that were commented by the historical source consolidator.
- A guarded apply script that **only replaces a current file when its first nonblank line is `// STUB`**, unless `-Force` is deliberately supplied.
- A strict stub audit and a build/runtime closure gate.
- A context collector for any pure stubs that remain after the recovered bodies are exhausted.

## Why the apply is guarded

The current September 24 transcript shows several files were already edited after the historical source corpus was produced. A historical body must not silently overwrite newer work. The default path is therefore:

```powershell
pwsh -File .\scripts\apply_recovered_win32app.ps1 -RepoRoot 'F:\~dev\rawrxd'
pwsh -File .\scripts\audit_ide_stubs.ps1 -RepoRoot 'F:\~dev\rawrxd' -NoFail
```

Any already-real/current implementation is reported as `SKIP_NONSTUB`.

## Strict closure

```powershell
pwsh -File .\scripts\verify_ide_closure.ps1 `
  -RepoRoot 'F:\~dev\rawrxd' `
  -BuildDir 'F:\~dev\rawrxd\win32ide_strict\build_v4' `
  -Config Release
```

`VERDICT=PASS` is only emitted when:

1. `PURE_STUB_FILES=0`, and
2. the shipping `RawrXD-Win32IDE` target builds successfully, and
3. if `-RunRuntime` is requested, the launched shipping binary exits successfully.

No historical audit, source body, or compile-only result is treated as product completion.

## Remaining stubs

If the audit still reports pure stubs, capture their exact current source plus the current `Win32IDE.h`/CMake surface with:

```powershell
pwsh -File .\scripts\collect_remaining_stub_context.ps1 -RepoRoot 'F:\~dev\rawrxd'
```

That output is the authoritative continuation set. The original 213-stub count is **not** assumed to still be current after the interrupted edits.

## Recovery provenance

The recovered files come from the retained consolidated RawrXD production-source corpus. `recovered_reference/` preserves the exact extracted historical text. `recovered_apply/` changes only consolidator comments back into normal `#include` directives; no behavior is otherwise rewritten.
