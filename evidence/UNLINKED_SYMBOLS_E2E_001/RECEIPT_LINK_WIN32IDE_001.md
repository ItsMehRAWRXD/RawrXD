# RECEIPT — LINK_WIN32IDE_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
LINK=FAIL
WORKSPACE=G:\~dev\rawrxd
BUILD_DIR=G:\~dev\rawrxd\build_win32ide_link001
DATE=2026-10-28
LOCAL_ONLY=1
OLLAMA_HTTP=0
```

## Overlay verify (pre-build)

| Fix | Status |
|-----|--------|
| `IsAgentBridgeHealthy` → local `m_agentBridgeReady` | OK on disk |
| tooltip / layout → `item.screenRect` | OK on disk |
| `AnnotationOverlay.cpp.obj` compile | OK (no C2039) |

## Build commands + exit codes

```text
# Pass 1 (default parallelism) — C1060 heap; link not reached
cmake --build "G:\~dev\rawrxd\build_win32ide_link001" --target RawrXD-Win32IDE --config Release
EXIT_CODE=2
LOG=_link_win32ide_001_build.log

# Pass 2 (-j2) — compile OK; link FAIL LNK1120
cmake --build "G:\~dev\rawrxd\build_win32ide_link001" --target RawrXD-Win32IDE --config Release -j 2
EXIT_CODE=-1          # PowerShell Tee pipeline LASTEXITCODE
LINK_EXIT=1120        # link.exe (authoritative)
EXE_EXISTS=0
LOG=_link_win32ide_001_build_j2.log
```

Machine-readable twin: `LINK_WIN32IDE_001.txt`

## LNK / C summary

| Class | Count | Notes |
|-------|-------|-------|
| C2039 | 0 | Overlay field mismatch cleared |
| C1060 | pass1 only | Mitigated with `-j 2` |
| LNK4006 | 1 warn | `SkipValue` (r25 MASM vs `MASMKernelStubs`) |
| LNK2001 | 10 unique | → LNK1120 |
| LNK2005 | 0 | No CMake omit this run |

### Unresolved (next gaps)

1. **`handleAIStopGeneration`** — owner `src/core/command_handlers_comprehensive.cpp` not in Win32IDE objs
2. **`SettingsManager::{Instance,Initialize,Shutdown,Get/SetWindowState}`** — owner `src/settings/settings_manager.cpp` not in Win32IDE objs
3. **`ModelConversionDialog::{ctor,dtor,showModal}`** — owner `src/gui/ModelConversionDialog.cpp` not in Win32IDE objs
4. **`CRDTBuffer::CRDTBuffer`** — `src/collab/crdt_buffer.cpp.obj` linked but ctor body missing

These are **LNK2001 include/incomplete-TU** gaps, not cheap LNK2005 omit. No MagBuf reopen. No Camellia XOR rewrite. No PROMOTE flip.

## Fail-closed

```
LINK=FAIL
NOT_RUN != PASS
SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS
CERTIFIED=0 · PROMOTE=0 · TIP_CLIMB=HOLD
```
