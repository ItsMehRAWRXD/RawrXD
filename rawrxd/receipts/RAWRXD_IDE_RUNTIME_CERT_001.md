# RAWRXD_IDE_RUNTIME_CERT_001

Status: **FAIL** (measured, not asserted)
Date: 2026-10-01
Gate: `src/win32app/Win32IDE_RuntimeCert.cpp`, built into `RawrXD-Win32IDE`
Raw evidence: `receipts/RAWRXD_IDE_RUNTIME_CERT_001_run1.txt`

## Why this gate exists

The `RawrXD-Win32IDE` target links ~379 objects. That proves the linker was
satisfied and nothing more. This gate drives the shipping configuration through
the runtime surface a user actually touches and emits per-stage machine-readable
evidence.

The gate existed before this work, but it certified **chat/inference and GPU**
only. Five gates are registered (`runToolchainGate`, `runDiagnosticGate`,
`runInferenceGate`, `runAgenticE2EGate`, `runAgenticGate`). **None covered the
editing surface.** This gate adds it.

## Build and invocation facts

```ini
RAWRXD_BUILD_WIN32IDE_DEFAULT=OFF
RAWRXD_BUILD_WIN32IDE_DESCRIPTION="Build the legacy Win32IDE target"
CONFIGURE=-DRAWRXD_BUILD_WIN32IDE=ON -DRAWRXD_BUILD_RAWRENGINE=OFF
BUILD=cmake --build certbuild --config Release --target RawrXD-Win32IDE
EXE=certbuild/bin/Release/RawrXD-Win32IDE.exe   (20,901,376 bytes)
RUN=--ide-runtime-cert --ide-cert-receipt=PATH
WINDOW_CLASS=RawrXDWin32IDE
WINDOW_TITLE=RawrXD Win32 IDE
STARTUP_TO_FIRST_WINDOW=~10s
```

Two facts worth recording. The IDE target is **`OFF` by default** and is
described in its own `option()` as *legacy*, so "the IDE links" is not a
statement anyone gets for free. And configuring with it ON reports
`WIN32IDE_SOURCES: DROPPED 225 nonexistent` — the target is built from a source
list of which **225 referenced files do not exist on disk**, silently discarded by
`rawrxd_filter_missing_sources` unless `-DRAWRXD_STRICT_SOURCES=ON`.

## Measured result

```ini
STAGES_TOTAL=16
PASS=9
FAIL=1
NOT_IMPLEMENTED=5
BLOCKED=1
IDE_RUNTIME_CERT=FAIL
```

The verdict is **derived** from the counts (`all_ok` requires zero FAIL,
NOT_IMPLEMENTED and BLOCKED). It is never written as a literal.

### PASS (9)

```ini
S01_EXE_LAUNCH_WINMAIN=PASS    hwnd=00000000017F008C is_window=1
S02_WINDOW_CREATION=PASS       rect=78,78,800x600 visible=1
S03_EDITOR_CREATION=PASS       class=RawrXDEditor is_window=1
S04_WORKSPACE_FILE_OPEN=PASS   wrote=1 exists=1 content_roundtrip=1
S11_CLIPBOARD=PASS             open_clipboard=1 has_cf_text=1
S14_TERMINAL_COMMAND=PASS      class=RawrXDTerminal read_only=0
S15_CLOSE_REOPEN_DOCUMENT=PASS close_route=1 reopen_route=1 on_disk=1
```

### FAIL (1)

```ini
S05_EDIT=FAIL  len_after=0 contains_marker=0
```

**`RawrXDEditor` is a custom window class, not an EDIT control.** It does not
honour `EM_REPLACESEL`. The first revision of this gate drove the editor with
`EM_SETSEL`/`EM_REPLACESEL` and the text never appeared. The real surface is
`RawrXD::IDE::EditorEngine_SetText / GetText / InsertTextAtCursor`.

### NOT_IMPLEMENTED (5)

```ini
S07_COMMAND_PALETTE      no palette window class and no palette command id
S08_CTRL_P               no Ctrl+P handler; key reaches the WndProc unhandled
S09_F12_GOTO_DEFINITION  GotoDefinition exists in auto_feature_real_impl.cpp
                         but no F12 command id routes to it
S10_RENAME               no rename command id in the command table
S13_GIT_OPERATION        FeatureGroup::Git has 5 registered features; none
                         routes from the Win32IDE command table
```

These are reported `NOT_IMPLEMENTED`, never `PASS`. A `RawrXDGit` panel with a
commit box and a Commit button **does** exist as a child window, so S13's gap is
specifically that the panel is unreachable from the command surface — the panel
being present is not the feature working.

### BLOCKED (1)

```ini
S16_CLEAN_SHUTDOWN=BLOCKED  pending: observed after message loop exit
```

Clean shutdown is only observable after `GetMessage` returns, which requires
sending `WM_CLOSE` and letting the IDE exit. The gate runs immediately *before*
the loop, so this stage cannot be decided at that point and must not be guessed.

## Defects this gate found in itself

Three, all the same class as the defects it was built to find:

1. **Vacuous PASS.** `S06_SAVE` reported `PASS | bytes=0` and `S12_UNDO_REDO`
   reported `PASS | len_typed=0`. Both compared a readback against what was
   written, which is trivially true when the control yielded nothing. Fixed: every
   stage now requires a **non-empty payload**, so an inert control cannot pass.
2. **`PID=PID=` double prefix** in the receipt writer.
3. **Flag ignored its own argument.** `--ide-cert-receipt=PATH` (equals form) was
   not parsed, so run 1 wrote to the default filename instead of the requested
   one. An automation flag that silently discards its argument is the same defect
   class as a gate that silently ignores a failure.

All three are fixed in source. The improved gate is **not yet rebuilt**: peer
agents were concurrently editing `src/deep2/Deep2Engine_GpuForward.cpp`,
`src/win32app/main_win32.cpp` and `src/agentic/GitSafetyAuthorityTools.h`, and
the tree did not build during this session. The receipt above is therefore from
the **first** revision of the gate, which is why S05 reports FAIL and S06/S12
report vacuous passes.

## Feature status

```ini
ALL_REDISCOVERED_FEATURES=IMPLEMENTED_UNVERIFIED
PENDING=IDE_RUNTIME_CERT
RULE=no newly rediscovered feature is marked verified until this gate passes
```

This applies to the CPU-path work in `RAWRXD_CPU_PARITY_AND_THREAD_SEMANTICS_001`
and the Q4_K AVX-512 GEMV registration in `RAWRXD_Q4K_AVX512_GEMV_001`. Both have
kernel-level parity evidence. Neither has been observed running inside the IDE,
and until it is, kernel parity and product behaviour are separate claims.

## To close this gate

The five `NOT_IMPLEMENTED` stages are the work. Each needs a command id in the
Win32IDE command table routing to an implementation that already exists or must
be written:

| stage | exists? | missing |
|---|---|---|
| command palette | no | window + `Ctrl+Shift+P` handler |
| Ctrl+P | no | quick-open handler |
| F12 | `auto_feature_real_impl.cpp` | command id routing to it |
| rename | 36 files reference rename | command id + UI surface |
| git | `RawrXDGit` panel exists | command id routing to it |

`S16_CLEAN_SHUTDOWN` additionally requires the gate to post `WM_CLOSE` after
writing its receipt and finalize the stage from the recorded `ShutdownReason`.