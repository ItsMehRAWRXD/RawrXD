# MASTER_HIDDEN_GAP_REGISTER — A–D reconciled (Track C authority)

```
ASOF_UTC=2026-11-09T12:56:00Z
MOTD_ACK=1
AUTHORITY_H01_H60=HIDDEN_GAPS_H01_H60.md
AUTHORITY_H61_H120=HIDDEN_GAPS_H61_H120.md
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
CONTROLLING_TIP=CC79
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
PHASE_A=PENDING
PENDING_WORKER_H01_H60=0
CONFIRMED_BLOCKER_COUNT=12
```

## Rollup

| Scope | CONFIRMED | CONFIRMED_PRIOR | UNVERIFIED | INVESTIGATE | N_A | PENDING_WORKER |
|-------|-----------|-----------------|------------|-------------|-----|----------------|
| H01-H60 | 12 | 2 | 29 | 17 | 0 | 0 |
| H61-H120 | 0 | 0 | 19 | 38 | 3 | 0 |

CONFIRMED blockers: H01,H02,H03,H04,H21,H22,H41,H42,H43,H51,H56,H57
CONFIRMED_PRIOR (not new): H08,H27
HIGH_SIGNAL: H01,H21,H57,H43,H51,H42

## Register

| ID | Area | Status | Evidence | Dedupe_refs |
|----|------|--------|----------|-------------|
| H01 | Core TU excluded from Native CMake | CONFIRMED | Win32IDE_Core.cpp absent from RAWRXD_NATIVE_IDE_SOURCES | TRACK_C |
| H02 | Duplicate Problems/dispatch paths | CONFIRMED | lifecycle linked + Core unlinked; MenuHandlers empty | TRACK_C |
| H03 | Stub replacing production | CONFIRMED | MenuHandlers MinimalInit no-op; headless ExtHost stubs | TRACK_C |
| H04 | Feature flags gate release | CONFIRMED | RAWRXD_NATIVE_IDE_EXT default OFF | TRACK_C |
| H05 | Missing deps incremental | UNVERIFIED | Not demonstrated | TRACK_C |
| H06 | Stale objects false-green | UNVERIFIED | Not measured | TRACK_C |
| H07 | Debug/Release diverge | INVESTIGATE | ASan vs /O2 unproven | TRACK_C |
| H08 | Inherited env / VS_UNICODE | CONFIRMED_PRIOR | Historical — not new | H27 |
| H09 | Optional unresolved symbols | INVESTIGATE | hardening warn-continue | TRACK_C |
| H10 | Branch incompatible TUs | INVESTIGATE | F omits Core; PR76 | PR76 |
| H11 | Generated headers clean checkout | UNVERIFIED | Python generate fail not shown | TRACK_C |
| H12 | Non-reproducible binaries | UNVERIFIED | Dual-build ABSENT | TRACK_C |
| H13 | Menu wrong handlers | INVESTIGATE | routeCommand default false; invoke-all NOT_RUN | TRACK_C |
| H14 | Toolbar not executing | UNVERIFIED | ABSENT | TRACK_C |
| H15 | Shortcuts bypass path | UNVERIFIED | ABSENT | TRACK_C |
| H16 | Stale HWND after destroy | INVESTIGATE | Systematic stale-HWND NOT_RUN; see H22 | H22 |
| H17 | Worker threads touch UI | INVESTIGATE | PostMessage; audit incomplete | PR78 |
| H18 | Msgs after cancel | UNVERIFIED | PR78 NOT_RUN | PR78 |
| H19 | Reentrant WndProc | INVESTIGATE | Unproven | TRACK_C |
| H20 | Focus breaks keyboard | INVESTIGATE | Load break NOT_RUN | TRACK_C |
| H21 | DPI only in unlinked Core | CONFIRMED | WM_DPICHANGED only in Win32IDE_Core.cpp; absent lifecycle | TRACK_C HIGH_SIGNAL |
| H22 | OUTPUT_HWND unbound | CONFIRMED | tip006 id1604=-1 OUTPUT_HWND=FAIL | OUTPUT_PANEL_GATE |
| H23 | Modal blocks background | INVESTIGATE | NOT_RUN | TRACK_C |
| H24 | UI deadlock | UNVERIFIED | ABSENT | TRACK_C |
| H25 | Unhandled dispatch exceptions | INVESTIGATE | SEH unproven | TRACK_C |
| H26 | Window recreate loses state | UNVERIFIED | ABSENT | TRACK_C |
| H27 | Compiler inherits bad env | CONFIRMED_PRIOR | VS_UNICODE family — not new | H08 |
| H28 | Pipe backpressure | UNVERIFIED | ABSENT | TRACK_C |
| H29 | Child survives cancel | INVESTIGATE | No JobObject | TRACK_C |
| H30 | Timeout parent-only | INVESTIGATE | No job tree | TRACK_C |
| H31 | Spaced-path diagnostics | UNVERIFIED | ABSENT | TRACK_C |
| H32 | Unicode diag corrupt | UNVERIFIED | ABSENT | TRACK_C |
| H33 | Warnings as errors | UNVERIFIED | ABSENT | TRACK_C |
| H34 | Duplicate Problems | UNVERIFIED | ABSENT | TRACK_C |
| H35 | Stale diags after rebuild | UNVERIFIED | CC79 items=0; 47451 RECEIPT_ONLY EXE ABSENT | Phase A |
| H36 | Click-to-line | UNVERIFIED | 47451 RECEIPT_ONLY EXE ABSENT | Phase A |
| H37 | Line/col offsets | UNVERIFIED | ABSENT | TRACK_C |
| H38 | Multi-project ownership | UNVERIFIED | ABSENT | TRACK_C |
| H39 | Linker errors missing | UNVERIFIED | ABSENT | PR75 |
| H40 | False build success | INVESTIGATE | BuildEvidence not in Native | H57 |
| H41 | PE/COFF acceptance hole | CONFIRMED | PR75 16 native-linker unexecuted | PR75 |
| H42 | Adapter PASS != native complete | CONFIRMED | PR75 37 local + 16 linker NOT_EXECUTED | TRACK_C HIGH_SIGNAL |
| H43 | Ext activation SHA-split | CONFIRMED | tip001 NOT_RUN; tip002 PASS; Native excludes ExtHost | TRACK_C HIGH_SIGNAL |
| H44 | Worker IPC handshake | UNVERIFIED | ABSENT | PR79 |
| H45 | IPC framing | INVESTIGATE | No length-prefix found | PR79 |
| H46 | Ext wrong thread | INVESTIGATE | Affinity ABSENT | PR79 |
| H47 | Protocol version | UNVERIFIED | ABSENT | PR79 |
| H48 | Ext crash kills IDE | INVESTIGATE | Hard-crash NOT_RUN | PR79 |
| H49 | Unload leaves callbacks | UNVERIFIED | ABSENT | PR79 |
| H50 | Reload duplicates | UNVERIFIED | ABSENT | PR79 |
| H51 | Ext FORCE_KILL / survives quit | CONFIRMED | 47451 EXT_CLEANUP=FAIL FORCE_KILL=1 | TRACK_C HIGH_SIGNAL |
| H52 | Crashed worker restart | UNVERIFIED | ABSENT | PR79 |
| H53 | Ext FS permissions | INVESTIGATE | Unproven | H91 |
| H54 | Ext blocks UI | UNVERIFIED | ABSENT | PR79 |
| H55 | Ext state across projects | UNVERIFIED | ABSENT | PR79 |
| H56 | Test ext PASS / real FAIL | CONFIRMED | ext_hello != real matrix | TRACK_C |
| H57 | AgentSession not in Native | CONFIRMED | rawrxd_agentic_backend CLI only; 0 Native links | TRACK_C HIGH_SIGNAL |
| H58 | Cancelled agent continues | UNVERIFIED | PR78 NOT_RUN | PR78 |
| H59 | Old tool results newer convo | UNVERIFIED | ABSENT | PR78 |
| H60 | Tool-call parse errors | UNVERIFIED | ABSENT | PR78 |
| H61 | Tool permission bypass | INVESTIGATE | TRACK_D | PR78 |
| H62 | Wrong-file edits | INVESTIGATE | TRACK_D | PR78 |
| H63 | Partial write corruption | INVESTIGATE | TRACK_D | |
| H64 | Failed-edit rollback | UNVERIFIED | TRACK_D | #57 A15 |
| H65 | Agent false build success | INVESTIGATE | TRACK_D | |
| H66 | Agent infinite loops | INVESTIGATE | TRACK_D | |
| H67 | Tool blocks streaming | INVESTIGATE | TRACK_D | |
| H68 | Concurrent overwrite | INVESTIGATE | TRACK_D | |
| H69 | Unrestorable after restart | UNVERIFIED | TRACK_D | PR78 |
| H70 | Review without tests | UNVERIFIED | TRACK_D | #49 |
| H71 | Git unrelated commits | INVESTIGATE | TRACK_D | |
| H72 | Complete before FINAL_TESTS | UNVERIFIED | TRACK_D | H120 |
| H73 | Wrong model/backend | UNVERIFIED | TRACK_D | |
| H74 | Ollama fragmented JSON | UNVERIFIED | TRACK_D | |
| H75 | Cancel leaves GPU work | UNVERIFIED | TRACK_D | |
| H76 | Backend shutdown leaks | INVESTIGATE | TRACK_D | |
| H77 | Invalid inference output | UNVERIFIED | TRACK_D | |
| H78 | Offload counters | INVESTIGATE | TRACK_D | |
| H79 | Quant kernels incorrect | UNVERIFIED | TRACK_D | |
| H80 | KV rollback corruption | INVESTIGATE | TRACK_D | |
| H81 | Long-context exceed | INVESTIGATE | TRACK_D | |
| H82 | Multi-GPU placement | N_A_OUT_OF_SCOPE | TRACK_D | #57 C08 |
| H83 | Multi-device sync | N_A_OUT_OF_SCOPE | TRACK_D | #57 C09 |
| H84 | Silent CPU fallback | INVESTIGATE | TRACK_D | |
| H85 | Driver vs model | INVESTIGATE | TRACK_D | |
| H86 | Stale tokenizer | INVESTIGATE | TRACK_D | |
| H87 | GPU device-loss recovery | INVESTIGATE | TRACK_D (reject W4 CONFIRMED) | |
| H88 | Bench excludes prefill | INVESTIGATE | TRACK_D | |
| H89 | GGUF accepts corrupt | INVESTIGATE | TRACK_D | |
| H90 | Local-only external deps | UNVERIFIED | TRACK_D | |
| H91 | Path traversal | INVESTIGATE | TRACK_D | |
| H92 | Model bypasses tool auth | INVESTIGATE | TRACK_D | |
| H93 | Shell unintended exec | INVESTIGATE | TRACK_D | |
| H94 | Secrets in logs | INVESTIGATE | TRACK_D | |
| H95 | Ext IPC unauthorized | INVESTIGATE | TRACK_D | |
| H96 | Ext install validation | INVESTIGATE | TRACK_D | |
| H97 | Placeholder crypto | INVESTIGATE | TRACK_D | |
| H98 | Undeclared DLLs | UNVERIFIED | TRACK_D | |
| H99 | Installer outside dirs | INVESTIGATE | TRACK_D | |
| H100 | Uninstall destroys data | INVESTIGATE | TRACK_D | |
| H101 | Crash recovery unsafe | INVESTIGATE | TRACK_D | |
| H102 | Receipts no provenance | INVESTIGATE | TRACK_D | |
| H103 | CI green without tests | INVESTIGATE | TRACK_D (reject W4) | |
| H104 | LFS/branch incomplete | INVESTIGATE | TRACK_D | |
| H105 | Signed != tested | UNVERIFIED | TRACK_D | |
| H106 | Multi-SHA cert | INVESTIGATE | TRACK_D (reject W4) | |
| H107 | LSP diag/completion | UNVERIFIED | TRACK_D | |
| H108 | GhostText wrong range | UNVERIFIED | TRACK_D | |
| H109 | Browser origin isolation | UNVERIFIED | TRACK_D | |
| H110 | Git wrong repo | INVESTIGATE | TRACK_D | |
| H111 | Snapshot restore | UNVERIFIED | TRACK_D | |
| H112 | Settings not applied | INVESTIGATE | TRACK_D | |
| H113 | Registry stub backends | INVESTIGATE | TRACK_D (reject W4) | H03 |
| H114 | Cross-platform w/o native | N_A_OUT_OF_SCOPE | TRACK_D | #57 B13-B15 |
| H115 | Synthetic perf as decode | INVESTIGATE | TRACK_D | |
| H116 | Docs vs binary | INVESTIGATE | TRACK_D | |
| H117 | Acceptance omits negatives | UNVERIFIED | TRACK_D | |
| H118 | Fail when simultaneous | UNVERIFIED | TRACK_D | |
| H119 | Fixtures conceal env | INVESTIGATE | TRACK_D | |
| H120 | Product-final autonomous loop | UNVERIFIED | TRACK_D; #49 OPEN | #49 |

```
PENDING_WORKER_H01_H60=0
PHASE_A=PENDING
PROMOTE=0 CERTIFIED=0
ENGINEERING_MATURITY=82
```