# RECEIPT — WIN32IDE_BRIDGE_SWEEP_002

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T08:36:29Z
RELINK=NO
EXE_SHA_HOLD=89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630
LIVE_TETRAD=unchanged (sealed SHA; not re-run; not invented)
```

## Verdict

Remaining Win32IDE bridge fake-success holes for Logpoint / Sidebar / LoRA
duplicate are **dispositioned fail-closed**. None were product-linked into
sealed `RawrXD-Win32IDE.exe` SHA `89BFD614…`. No relink.

## Dispositions

| Target | Disposition |
|--------|-------------|
| `Win32IDE_LogpointBridge.cpp` | **GATED_OMIT** + source wire to `native_debugger_conditional_bp` (owner TU also omit). `return true` only post-owner — not silent stub. |
| `Win32IDE_SidebarBridge.cpp` | **GATED_OMIT** + **GATED_STUB**: MASM WndProc → `-1`; Send/Receive → `false` + GateStub. Product owner remains `Win32IDE_Sidebar.cpp`. |
| LoRAKernel duplicate | **CROSS_CITE** `LORA_KERNEL_STUB_GATE_001` (AgenticFeatures `false`; both TUs omit). |

## Edits this mission

| Path | Change |
|------|--------|
| `src/win32app/Win32IDE_LogpointBridge.cpp` | GATED_OMIT / owner cite header |
| `src/win32app/Win32IDE_SidebarBridge.cpp` | GateStub; fail-closed IPC; drop missing BATCH2_CONTEXT.h |
| `src/win32app/Win32IDE_LoRAKernelBridge.h` | SWEEP_002 cross-cite |
| `CMakeLists.txt` | omit comments for Logpoint + SidebarBridge |

## Sibling cross-cites (landed)

- `evidence/IDE_BRIDGE_STUB_GATE_001/`
- `evidence/LORA_KERNEL_STUB_GATE_001/`

## Explicit non-claims

SOURCE_WIRED ≠ RUNTIME_REACHED · NOT_RUN ≠ PASS · PROMOTE=0 · CERTIFIED=0
