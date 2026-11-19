# S016 — IDE GGUF probe parameterization

Date: 2026-11-19  
Baseline: `16267bead5`

## Implementation

`src/win32app/Win32IDE_lifecycle.cpp` now resolves the probe model in this
order:

1. `RAWRXD_DEEP2_PROBE_MODEL`
2. `RAWRXD_MODEL_PATH`

If neither variable is set, the probe fails closed with
`MODEL_PATH_UNSET`. The former hardcoded `F:\rawrxd\bench_min.gguf` fallback
was removed because that path is not guaranteed to exist and could produce a
misleading probe failure.

## Verification

- `git diff --check`: pass.
- CMake/MSBuild compiled the modified `Win32IDE_lifecycle.cpp` successfully.
- Link was blocked by the existing executable being locked:

```text
LINK : fatal error LNK1104: cannot open file
'F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe'
```

No executable SHA or runtime result is claimed for this source change.

## Disposition

```ini
IDE_PROBE_MODEL_PATH=CONFIGURABLE
MISSING_PATH_FALLBACK=REMOVED
UNSET_PATH=FAIL_CLOSED
SOURCE_COMPILE=PASS
NATIVE_IDE_LINK=BLOCKED_FILE_LOCK
RUNTIME_RETEST=PENDING
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
