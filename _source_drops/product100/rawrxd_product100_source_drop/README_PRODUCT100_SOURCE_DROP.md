# RawrXD Product Finish 100 — no-deps x64 MASM source overlay

This overlay provides the remaining source for the 85% → 100% product lane without
adding third-party dependencies or reopening frozen certification work.

It is source-only.  The product claim is not 100% until the overlay is applied to
the real checkout, linked into `RawrXD-Win32IDE`, and the evidence gates below pass
on a physical GGUF run.

## Files

Copy these paths into the matching repo-relative locations:

```text
include/RawrXD_Product100.hpp
include/RawrXD_Product100_x64.hpp
src/win32app/RawrXD_Product100.cpp
src/asm/RawrXD_Product100_x64.asm
src/asm/RawrXD_Product100_x64.inc
```

## Build wiring

Add the C++ file to the existing `RawrXD-Win32IDE` source list and add the MASM
file to the existing x64 MASM source list.  Do not create a new subsystem.

Representative CMake fragment:

```cmake
target_sources(RawrXD-Win32IDE PRIVATE
  src/win32app/RawrXD_Product100.cpp
  src/asm/RawrXD_Product100_x64.asm
)
```

If the project uses a MASM object library, add `src/asm/RawrXD_Product100_x64.asm`
there instead.  The C++ module directly imports MASM symbols; missing MASM linkage
is a link failure or `P100_E_MASM_NOT_LINKED`, not a fake pass.

## Host integration points

Initialize once after workspace open:

```cpp
P100_Context p100 = {};
p100.size = sizeof(p100);
wcsncpy_s(p100.workspace, workspacePath.c_str(), _TRUNCATE);
wcsncpy_s(p100.evidence_dir, L"evidence\\IDE_PRODUCT_FINISH_BATCH_085", _TRUNCATE);
p100.capabilities =
    P100_CAP_READ | P100_CAP_SEARCH |
    P100_CAP_EDIT | P100_CAP_COMMAND |
    P100_CAP_GIT_READ | P100_CAP_GIT_WRITE |
    P100_CAP_SETTINGS | P100_CAP_PERSISTENCE |
    P100_CAP_TERMINAL;
p100.sink = AppendCommandOrDiagnosticsText;
P100_Init(&p100);
```

Wire Wave 3:

- Git product lane: call `P100_GitStatus`, `P100_GitDiff`, `P100_GitStage`,
  `P100_GitUnstage`, `P100_GitCommit`.
- Workspace/code search: call `P100_SearchWorkspaceLiteral` and
  `P100_SearchWorkspaceSymbol`; feed results into user UI and agent context.
- Conversation persistence: call `P100_SaveSession` on safe state changes and
  shutdown; call `P100_LoadSession` on launch before restoring model/mode/plan.
- Approval center: queue edit/destructive/command requests with `P100_AddApproval`,
  render `P100_ListApprovals`, and gate execution through `P100_DecideApproval`.
- Settings/model controls: call `P100_SaveSettings` from Engine controls and
  `P100_LoadSettings` on launch.

Wire Wave 4:

- Error/recovery UX: map subsystem failures through `P100_DescribeError`.
- Product smoke matrix: provide real callbacks in `P100_SmokeHostV1` and call
  `P100_RunSmokeMatrix`. Missing callbacks produce HOLD.
- Evidence/freeze: call `P100_WriteFreezeManifest` only after:
  - P1PRA physical E2E `FINALIZE=0`
  - `WAVE_1_VERDICT.txt` PASS
  - `WAVE_2_VERDICT.txt` PASS
  - `WAVE_3_VERDICT.txt` PASS
  - `WAVE_4_VERDICT.txt` PASS

## Frozen lanes

Do not reopen these unless evidence names them as fault owner:

```text
STREAMER_VRAM_APERTURE_001
AGENTIC_AUTONOMOUS_TEMPLATE_001
COMMAND_HOME_SMOKE_001
existing Deep2/K2 certification
existing MASM kernel certification
synthetic-fallback removal
CommandBroker(message, mode) contract
```

## 100% promotion rule

`PRODUCT_100_VERDICT.txt` may say PASS only when the clean-launch journey is
physically witnessed:

```text
Launch → workspace → Load GGUF → Ask → Plan checklist → Approve
→ Agent read/search → Build edits → diff → Apply
→ Terminal run → Agent reads failure → repair
→ Git diff/commit → Stop → Restart restores state
```

If `E2E.log` lacks `FINALIZE=0`, keep the program at HOLD even if this source
builds successfully.

