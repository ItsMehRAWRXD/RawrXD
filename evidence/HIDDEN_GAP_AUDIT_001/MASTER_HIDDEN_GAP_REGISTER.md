# MASTER_HIDDEN_GAP_REGISTER — FINAL disposition authority (W5 reconcile)

```
ASOF_UTC=2026-11-09T17:50:00Z
AUTHORITATIVE_REGISTER=1
REGISTER_RACE=RESOLVED
AUTHORITY=FINAL_AUDIT_DISPOSITION.md
W3_EVIDENCE=W3_H01_H60.md;W3_COMPLETE.md
W4_EVIDENCE=W4_H61_H120.md;W4_COMPLETE.md
W5_EVIDENCE=FINAL_AUDIT_DISPOSITION.md;W5_COMPLETE.md;POST_MERGE_RECONCILE.md
TRACK_C_DRAFT_ARCHIVED=MASTER_HIDDEN_GAP_REGISTER_TRACK_C_DRAFT_ARCHIVED_20261109.md
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
CONTROLLING_TIP=CC79
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_CONFIRMED=0
NO_CROSS_SHA_PASS_INHERITANCE=1
A4F_IMMUTABLE=1
```

## Rollup (matches FINAL_AUDIT_DISPOSITION)

| Status | Count | IDs / notes |
|--------|------:|-------------|
| CONFIRMED | 8 | H01,H04,H16,H27,H51,H57,H87,H113 |
| UNVERIFIED | 56 | remainder |
| INVESTIGATE | 51 | incl. W5 demotions H10,H103,H106 |
| OUT_OF_SCOPE | 3 | H82,H83,H114 |
| DEDUPE | 2 | H08→H27, H35→H27 |

W5 demotions (no invented CONFIRMED): H08→DEDUPE(H27), H10→INVESTIGATE, H35→DEDUPE(H27), H82/H83→OUT_OF_SCOPE, H103→INVESTIGATE, H106→INVESTIGATE.

## SHA-scoped notes (≠ inheritance)

| Note | Binding |
|------|---------|
| H16 tip006 CONFIRMED | tip006 `5A71CA26…` OUTPUT_HWND FAIL `id1604=-1` — sealed; **not cleared** by tip_integ P1 PASS on `1046C2B8…` |
| tip_integ P1 HWND PASS | `1046C2B8…` only — annotate separately; no CONFIRMED clear |
| H51 EXT_CLEANUP | sealed on `47451F24…` — SHA-scoped |
| H87 DEVICE_LOSS | specialty receipt ≠ product GPU PASS |

## Register H01–H120

| ID | Area | Status | Evidence | Dedupe_refs |
|----|------|--------|----------|-------------|
| H01 | Core TU / orphans excluded from Native CMake | CONFIRMED | W3: Win32IDE_Core.cpp absent from RAWRXD_NATIVE_IDE_SOURCES; AgentSession not linked by Native-Ext | D014; W3_H01_H60.md |
| H02 | Duplicate slim/Ext / asm stub shadow | INVESTIGATE | W3: link-map stub-wins unproven | D011 |
| H03 | Stub replacing production | INVESTIGATE | W3: D001 debugger stub superseded at source; not re-CONFIRMED | D001(stale) |
| H04 | Feature flags gate release Ext | CONFIRMED | W3: RAWRXD_NATIVE_IDE_EXT default OFF | D002 |
| H05 | Missing deps incremental | UNVERIFIED | W3: clean-checkout fail not sealed | D003 |
| H06 | Stale objects false-green | UNVERIFIED | W3: not measured | D003 |
| H07 | Debug/Release diverge | UNVERIFIED | W3: not receipt-proven | — |
| H08 | Inherited env / VS_UNICODE | DEDUPE | W5 demote from W3 CONFIRMED → same family as H27 | H27; COMPILER_ROOT_CAUSE_001 |
| H09 | Optional unresolved symbols | INVESTIGATE | W3: optional hardening warn-continue | — |
| H10 | Branch incompatible TUs | INVESTIGATE | W5 demote from W3 CONFIRMED; F vs G:~dev HEAD diverge remains lead | D012 |
| H11 | Generated headers clean checkout | INVESTIGATE | W3: GeneratedChatRouteMenu.py step | — |
| H12 | Non-reproducible binaries | UNVERIFIED | W3: dual-build ABSENT | — |
| H13 | Menu wrong handlers | UNVERIFIED | W3: invoke-all NOT_RUN | — |
| H14 | Toolbar not executing | UNVERIFIED | W3: ABSENT | — |
| H15 | Shortcuts bypass path | UNVERIFIED | W3: ABSENT | — |
| H16 | Stale / unbound Build HWND | CONFIRMED | W3: tip006 OUTPUT_ID1604_BUILD_LEN=-1; TIP006_OUTPUT_PROBLEMS_HWND_RECEIPT; OUTPUT_PANEL_GATE | tip006 seal; NO_INHERIT_1046C2B8 |
| H17 | Worker threads touch UI | INVESTIGATE | W3: PostMessage marshaling; no sealed fail | — |
| H18 | Msgs after cancel | INVESTIGATE | W3: PR78 adjacent; not E2E-failed | PR78 |
| H19 | Reentrant WndProc | UNVERIFIED | W3: not measured | — |
| H20 | Focus breaks keyboard | UNVERIFIED | W3: not measured | — |
| H21 | DPI geometry | UNVERIFIED | W3: not measured (TRACK_C CONFIRMED rejected — not in FINAL 8) | — |
| H22 | Resize/destroy obscure | UNVERIFIED | W3: not measured (TRACK_C H22 HWND axis absorbed as H16 tip006) | H16 |
| H23 | Modal blocks background | UNVERIFIED | W3: NOT_RUN | — |
| H24 | UI deadlock | UNVERIFIED | W3: ABSENT | — |
| H25 | Unhandled dispatch exceptions | UNVERIFIED | W3: not measured | — |
| H26 | Window recreate loses state | UNVERIFIED | W3: ABSENT | — |
| H27 | Compiler inherits bad env (VS_UNICODE) | CONFIRMED | W3: COMPILER_ROOT_CAUSE_001; PROBLEMS_PANEL_GATE POISON vs SCRUB; CC79 Problems FAIL | H08 dedupe |
| H28 | Pipe backpressure | INVESTIGATE | W3: tip006 binding fail ≠ pipe-deadlock residual | — |
| H29 | Child survives cancel | UNVERIFIED | W3: not proven | — |
| H30 | Timeout parent-only | UNVERIFIED | W3: not proven | — |
| H31 | Spaced-path diagnostics | UNVERIFIED | W3: ABSENT | — |
| H32 | Unicode diag corrupt | UNVERIFIED | W3: beyond VS_UNICODE not separately sealed | — |
| H33 | Warnings as errors | UNVERIFIED | W3: ABSENT | — |
| H34 | Duplicate Problems | UNVERIFIED | W3: ABSENT | — |
| H35 | Stale diags after rebuild | DEDUPE | W5 demote; CC79 items=0 family overlaps H27 VS_UNICODE/Problems | H27 |
| H36 | Click-to-line | INVESTIGATE | W3: POSTED_NM_DBLCLK ≠ editor-navigated proof on CC79 | — |
| H37 | Line/col offsets | UNVERIFIED | W3: ABSENT | — |
| H38 | Multi-project ownership | UNVERIFIED | W3: ABSENT | — |
| H39 | Linker errors missing | UNVERIFIED | W3: ABSENT | PR75 |
| H40 | False build success | UNVERIFIED | W3: ABSENT | — |
| H41 | PE/COFF acceptance hole | UNVERIFIED | W3: PR75 native-16 NOT_RUN ≠ CONFIRMED | PR75 |
| H42 | Adapter PASS != native complete | UNVERIFIED | W3: incomplete ≠ proven functional fail (TRACK_C CONFIRMED rejected) | PR75 |
| H43 | Ext activation SHA-split | UNVERIFIED | W3: smoke activates; never-activates not shown | EXT gate |
| H44 | Worker IPC handshake | UNVERIFIED | W3: smoke only | PR79 |
| H45 | IPC framing | UNVERIFIED | W3: stress ABSENT | PR79 |
| H46 | Ext wrong thread | UNVERIFIED | W3: ABSENT | PR79 |
| H47 | Protocol version | UNVERIFIED | W3: ABSENT | PR79 |
| H48 | Ext crash kills IDE | UNVERIFIED | W3: FAULT_ISOLATED≠crash suite | PR79 |
| H49 | Unload leaves callbacks | INVESTIGATE | W3: DEACTIVATE_OK≠callback audit | PR79 |
| H50 | Reload duplicates | INVESTIGATE | W3: RELOAD_OK smoke only | PR79 |
| H51 | Ext FORCE_KILL / survives quit | CONFIRMED | W3: INTEG004_EXT_REVERIFY EXT_CLEANUP=FAIL FORCE_KILL=1 on 47451F24… (SHA-scoped) | INTEG004; PR79 |
| H52 | Crashed worker restart | UNVERIFIED | W3: ABSENT | — |
| H53 | Ext FS permissions | UNVERIFIED | W3: ABSENT | H91 |
| H54 | Ext blocks UI | UNVERIFIED | W3: ABSENT | — |
| H55 | Ext state across projects | UNVERIFIED | W3: ABSENT | — |
| H56 | Test ext PASS / real FAIL | INVESTIGATE | W3: hello fixture ≠ real matrix (TRACK_C CONFIRMED rejected) | — |
| H57 | AgentSession not in Native | CONFIRMED | W3: AgentSession in rawrxd_agentic_backend CLI only; IDE AgenticBridge dual-controller | PR78; #49 |
| H58 | Cancelled agent continues | INVESTIGATE | W3: cancel paths present; orphan tool not E2E-failed | — |
| H59 | Old tool results newer convo | UNVERIFIED | W3: ABSENT | — |
| H60 | Tool-call parse errors | UNVERIFIED | W3: ABSENT | — |
| H61 | Tool permission bypass | INVESTIGATE | W4: multi entry points; no runtime bypass CONFIRMED | PR78 |
| H62 | Wrong-file edits | INVESTIGATE | W4: ResolveInWorkspace; other writers unproven | PR78 |
| H63 | Partial write corruption | INVESTIGATE | W4: rollback sources; no durable E2E | — |
| H64 | Failed-edit rollback | UNVERIFIED | W4: #57 A15 NOT_RUN | #57 A15 |
| H65 | Agent false build success | INVESTIGATE | W4: SelfRepairLoop build.success | — |
| H66 | Agent infinite loops | INVESTIGATE | W4: #49 loop NOT_DEMONSTRATED | #49 |
| H67 | Tool blocks streaming | INVESTIGATE | W4: async APIs; product interleave unproven | — |
| H68 | Concurrent overwrite | INVESTIGATE | W4: no multi-agent E2E | — |
| H69 | Unrestorable after restart | UNVERIFIED | W4: PR78 kill/restore NOT_RUN | PR78 |
| H70 | Review without tests | UNVERIFIED | W4: #49 reviewer NOT_RUN | #49 |
| H71 | Git unrelated commits | INVESTIGATE | W4: no staging allowlist E2E | #49 |
| H72 | Complete before FINAL_TESTS | UNVERIFIED | W4: completion semantics unproven | H120 |
| H73 | Wrong model/backend | INVESTIGATE | W4: dual backends; selector identity ABSENT on CC79 | — |
| H74 | Ollama fragmented JSON | INVESTIGATE | W4: RobustOllamaParser; fault-injection ABSENT | — |
| H75 | Cancel leaves GPU work | UNVERIFIED | W4: specialty cancel ≠ product GPU drain seal | — |
| H76 | Backend shutdown leaks | INVESTIGATE | W4: no leak-trend product seal | — |
| H77 | Invalid inference output | UNVERIFIED | W4: specialty GENERATE ≠ full-model validity | D007 |
| H78 | Offload counters | INVESTIGATE | W4: #57 C04–C05 OPEN; no invented GPU PASS | — |
| H79 | Quant kernels incorrect | UNVERIFIED | W4: #57 C03 OPEN; PROMOTE=0 | — |
| H80 | KV rollback corruption | INVESTIGATE | W4: not product-sealed | — |
| H81 | Long-context exceed | INVESTIGATE | W4: #57 C06–C08 OPEN | — |
| H82 | Multi-GPU placement | OUT_OF_SCOPE | W5 demote from W4 INVESTIGATE; multi-GPU outside daily-driver unless approved | #57 C08 |
| H83 | Multi-device sync | OUT_OF_SCOPE | W5 demote; #57 C09 OPEN → OOS for daily-driver scope | #57 C09 |
| H84 | Silent CPU fallback | INVESTIGATE | W4: fallback machinery; silent misreport not CONFIRMED | — |
| H85 | Driver vs model | INVESTIGATE | W4: no differential receipt | — |
| H86 | Stale tokenizer | INVESTIGATE | W4: switch-isolation ABSENT | — |
| H87 | GPU device-loss recovery | CONFIRMED | W4: DEEP2_MULTIGPU_RESILIENCE DEVICE_LOSS_HANDLING=0 while VERDICT=PASS — specialty ≠ product GPU PASS | specialty receipt |
| H88 | Bench excludes prefill | INVESTIGATE | W4: #57 C12–C13 disclosure | — |
| H89 | GGUF accepts corrupt | INVESTIGATE | W4: conflicting specialty signals; #57 C10 OPEN | — |
| H90 | Local-only external deps | INVESTIGATE | W4: LocalOnlyPolicy; offline seal open | #57 C15 |
| H91 | Path traversal | INVESTIGATE | W4: alternate tool entries may omit check | — |
| H92 | Model bypasses tool auth | INVESTIGATE | W4: coupled H61 | — |
| H93 | Shell unintended exec | INVESTIGATE | W4: PR77 RUNTIME=NOT_RUN | PR77 |
| H94 | Secrets in logs | INVESTIGATE | W4: no redaction seal | — |
| H95 | Ext IPC unauthorized | INVESTIGATE | W4: PR79 OPEN | PR79 |
| H96 | Ext install validation | UNVERIFIED | W4: marketplace E2E ABSENT | — |
| H97 | Placeholder crypto | INVESTIGATE | W4: historical lead; not re-proven | — |
| H98 | Undeclared DLLs | UNVERIFIED | W4: clean-machine audit ABSENT | — |
| H99 | Installer outside dirs | UNVERIFIED | W4: D009; T24 installer NOT_RUN | D009 |
| H100 | Uninstall destroys data | UNVERIFIED | W4: ABSENT | — |
| H101 | Crash recovery unsafe | INVESTIGATE | W4: gates OPEN | — |
| H102 | Receipts no provenance | INVESTIGATE | W4: cross-tip narrative risk | H106 |
| H103 | CI green without tests | INVESTIGATE | W5 demote from W4 CONFIRMED; runner_id=0 / empty steps remain lead | #57 A01 |
| H104 | LFS/branch incomplete | INVESTIGATE | W4: PR76 CONFLICTING | D003 |
| H105 | Signed != tested | INVESTIGATE | W4: T24≠signed; T25 CERTIFIED=0 | T24/T25 |
| H106 | Multi-SHA cert | INVESTIGATE | W5 demote from W4 CONFIRMED; process risk remains lead under NO_CROSS_SHA_PASS_INHERITANCE | lineage |
| H107 | LSP diag/completion | UNVERIFIED | W4: #57 A11 NOT_RUN | — |
| H108 | GhostText wrong range | UNVERIFIED | W4: #57 A12 OPEN | — |
| H109 | Browser origin isolation | UNVERIFIED | W4: #57 A13 OPEN | — |
| H110 | Git wrong repo | INVESTIGATE | W4: coupled H71 | — |
| H111 | Snapshot restore | UNVERIFIED | W4: #57 A15 OPEN | — |
| H112 | Settings not applied | INVESTIGATE | W4: no settings-apply E2E on CC79 | — |
| H113 | Registry stub backends | CONFIRMED | W4: AutonomousAgenticPipelineCoordinator stub; tool_executor stub; sim backends in tree | D001; W4_H61_H120.md |
| H114 | Cross-platform w/o native | OUT_OF_SCOPE | W4: #57 B13–B15 multi-OS | #57 B13-B15 |
| H115 | Synthetic perf as decode | INVESTIGATE | W4: #57 C12 forbids synthetic TPS as product | — |
| H116 | Docs vs binary | INVESTIGATE | W4: capability matrix OPEN | #57 C14 |
| H117 | Acceptance omits negatives | INVESTIGATE | W4: many gates positive-only | — |
| H118 | Fail when simultaneous | UNVERIFIED | W4: four-panel / #49 integrated NOT_DEMONSTRATED | #49 |
| H119 | Fixtures conceal env | INVESTIGATE | W4: fixture≠agent project | #49 |
| H120 | Product-final autonomous loop | UNVERIFIED | W4: Issue #49 NOT_DEMONSTRATED on CC79/INTEG_004 | #49 |

```
HIDDEN_GAP_ENTRIES=120
CONFIRMED=8
UNVERIFIED=56
INVESTIGATE=51
OUT_OF_SCOPE=3
DEDUPE=2
CONFIRMED_IDS=H01,H04,H16,H27,H51,H57,H87,H113
AUTHORITATIVE_REGISTER=1
REGISTER_RACE=RESOLVED
EXHAUSTIVE_CLOSURE_BLOCKED=0
ENGINEERING_MATURITY=82
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
CONTROLLING_TIP=CC79
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
```
