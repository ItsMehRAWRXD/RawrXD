# WIN32IDE_BRIDGE_SWEEP_002 — matrix

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T08:36:29Z
EXE_SHA_HOLD=89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630
RELINK=NO
```

| ID | Surface | Linked Win32IDE? | Disposition | Cite |
|----|---------|------------------|-------------|------|
| T01 | LogpointBridge → Debugger_* | NO | GATED_OMIT + SOURCE_WIRED_TO_OWNER | this LAW |
| T01b | native_debugger_conditional_bp | NO | OWNER_OMIT (same omit set) | this LAW |
| T02 | SidebarBridge MASM IPC bools | NO | GATED_OMIT + GATED_STUB | this LAW |
| T02b | Product Win32IDE_Sidebar.cpp | YES | KEEP (real owner) | product path |
| T03 | AgenticFeatures LoRAKernel_Initialize | NO | GATED_STUB false | LORA_KERNEL_STUB_GATE_001 |
| T03b | LoRAKernelBridge + ApplyLoRA | NO | GATED_OMIT | LORA_KERNEL_STUB_GATE_001 |
| X01 | ExtensionHostIpcBridge / NeuralBridge | NO | GATED | IDE_BRIDGE_STUB_GATE_001 |
| X02 | asm_kernel_bridge Camellia XOR | NO | GATED_OMIT | WIN32IDE_BRIDGE_XOR_LAW_001 |

No invent PASS. `NOT_RUN != PASS`. Sealed EXE untouched.
