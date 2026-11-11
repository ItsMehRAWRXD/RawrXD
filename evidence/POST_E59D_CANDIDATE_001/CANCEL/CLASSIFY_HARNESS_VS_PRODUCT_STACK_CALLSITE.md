# CLASSIFY_HARNESS_VS_PRODUCT_STACK_CALLSITE

ASOF_UTC=2026-11-03T13:25:00Z
GITHUB_COMMIT=70fe7cdaf7
CERT_EXE=F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe
CERT_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
REBUILD=HELD
REBUILD_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
CHATWINDOW_REOPEN=0
TOKEN64_REOPEN=0
GHOSTTEXT_REOPEN=0
DISASSEMBLY=COMPLETE
WINMAIN_IDENTIFIED=1
MESSAGE_LOOP_CALL_RESOLVED=1
FILESYSTEM_TOOL_SEARCH=ABORTED_REDUNDANT

## Controlling return

```
RESIDUAL_CLASS=MIXED_RESIDUAL
FAULT_ORIGIN_CLASS=C
HARNESS_RESIDUAL_A=SUSPECTED_NOT_PROVEN
PRODUCT_CLASS_B=NOT_PROVEN
HARNESS_SOLE=REFUTED
HARNESS_MULTI_NOTIFY_REQUIRED=0
CRASH_ROOT_CAUSE=NOT_PROVEN
PRODUCT_DEFECT=NOT_PROVEN
APP_WNDPROC=NOT_PROVEN
CONCRETE_CALLBACK=NOT_PROVEN
REBUILD=HELD
PROMOTE=0
NEXT_GATE=OPTIONAL_NARROW_CANCEL_MATRIX_OR_CDB_UNWIND
```

Sealed prior `HARNESS_VS_PRODUCT.md` (`CRASH_CLASSIFICATION=MIXED`, `HARNESS_SOLE=REFUTED`) is **not reopened**. This note is stack→callsite residual refinement only.

## Residual taxonomy (this gate)

| Class | Meaning | Verdict |
|-------|---------|---------|
| **A** | Harness-induced beyond multi-notify (Clear / dual SetEdit / arm-poll) | **SUSPECTED_NOT_PROVEN** |
| **B** | Actual Win32IDE message-handling defect (named WndProc/state) | **NOT_PROVEN** |
| **C** | Fault originates in comctl32 without proven product defect | **PROVEN as fault locus** |
| Combined | | **MIXED_RESIDUAL** |

```
RESIDUAL_CLASS=MIXED_RESIDUAL
```

Why not pure A/B/C:

- Pure **A** blocked: sealed single-BM Cancel still crashes same signature → multi-notify sole harness already **REFUTED**; Clear/SetEdit remains differential vs survivors but not isolated as causation on the Cancel path.
- Pure **B** blocked: no product `.text` callback between fault RIP and the resolved pump; `APP_WNDPROC=NOT_PROVEN`; WinMain/pump frames are **above** `DispatchMessageA`, not the faulting user callback.
- Pure **C** is the **fault origin** (`comctl32+0xBD02`) and is compatible with `PRODUCT_DEFECT=NOT_PROVEN`, but residual **A** differentials remain open → overall residual stays **MIXED_RESIDUAL**.

## 1) Exception context ↔ resolved callsite path

Authority: `logs\stack_parse_073409.txt`, `logs\stack_parse_070906.txt`,
`FUNC_26C0_CALLSITE_ANALYSIS.md`, `RESOLVE_CALLBACK_CALL_TARGETS.md`.

| Fact | Status |
|------|--------|
| RIP = `comctl32.dll+0xBD02` both dumps | **PROVEN** |
| Write AV via RCX (= ExceptionInformation[1]) | **PROVEN** |
| RDX=`0xFFFF`, R8=0, R9=`0x7FFEFFFF`, RBP=`0xF000` both | **PROVEN** (anomalous RBP; not mapped to product handler) |
| Shared product frames both dumps | `+0x12FB9C`, `+0x33F9` |
| `+0x12FB9C` identity | insn **after** `GetMessageA` inside `FUNC_RVA_0x12FB80` (`runMessageLoop`) |
| `+0x33F9` identity | insn **after** `call 0x12FB80` inside **WinMain** (`FUNC_26C0`) |
| Pump IAT quartet | GetMessageA → IsDialogMessageA → TranslateMessage → DispatchMessageA |

Resolved nesting (static + dump RSP class):

```
WinMain (0x26C0)
  call 0x12FB80                 ; RET lands +0x33F9  [both dumps]
    GetMessageA                 ; RET lands +0x12FB9C [both dumps]
    IsDialogMessageA(hwnd@obj+0x568, &msg)
    [else] TranslateMessage / DispatchMessageA
      → user32 / comctl32 …
         comctl32+0xBD02        ; FAULT RIP  [both dumps]
```

**Participation:** product owns the message loop that can deliver the crashing UI callback class.

**Causation:** product does **not** appear as the faulting callback body on the near-RSP path.

### Near-RSP product gap (fail-closed)

| Dump | Product `.text` between comctl32 fault and `+0x12FB9C`? |
|------|--------------------------------------------------------|
| 073409 (single BM) | **NONE** |
| 070906 (triple) | only `+0x1365D4` (multi-arg forwarder wrapper RET; **not** proven WndProc) |

```
APPLICATION_CAUSATION=NOT_PROVEN
COMCTL32_CALLBACK_LINK=STACK_NESTING_ONLY
FAULT_ORIGIN_CLASS=C
PRODUCT_CLASS_B=NOT_PROVEN
```

Exception CONTEXT registers are **not** owned by WinMain / `0x12FB80` (prior FUNC_26C0 gate). Do not treat message-loop ownership as WndProc defect.

## 2) Class A residual (beyond sealed multi-notify refute)

Preserved seal: `HARNESS_SOLE=REFUTED` · `HARNESS_MULTI_NOTIFY_REQUIRED=0`
(single BM_CLICK Cancel dump `073409` same `comctl32+0xBD02`).

Open residual differentials (same SHA; **not** causation proofs):

| Run | Clear | SetEdit | Click | Result |
|-----|-------|---------|-------|--------|
| Cancel sealed 070906 | yes | dual | triple | **CRASH** |
| Cancel sealed 073409 | yes | dual | single BM | **CRASH** |
| Hang HANG_*/BLOCK_* | no | timed/dual | single/triple | **NO_CRASH** 20–30s |
| `CLASSIFY_NOCLEAR_SINGLE` | no | WM_SETTEXT-only | single BM | **NO_CRASH_20S** |

```
HARNESS_RESIDUAL_A=SUSPECTED_NOT_PROVEN
```

Clear / dual-SetEdit / arm-poll **may** amplify or precondition the comctl32 fault versus minimal Request-A survivors, but this gate does **not** prove A as sole cause. Narrow Cancel matrix (no-Clear; WM_SETTEXT-only on full Cancel path) remains optional next work — does not authorize rebuild.

## 3) Class B (product WndProc/state) — fail-closed

| Required for B | Status |
|-----------------|--------|
| Named application WndProc / dialog / subclass on fault path | **NOT_PROVEN** |
| Concrete Cancel/Stop/ChatWindow callback at AV | **NOT_PROVEN** |
| Dump RET ↔ defective product handler | **NOT_PROVEN** |
| Rebuild-authorizing PRODUCT_DEFECT | **NOT_PROVEN** |

Source correlation (read-only, no rebuild) still nominates `Win32IDE::WindowProc` + Copilot `BN_CLICKED` → `HandleCopilotStop` as the **logical** UI owner for Stop/Cancel clicks, but sealed dumps do **not** place a WindowProc RVA on the faulting near-RSP chain. Nomination ≠ proof.

```
PRODUCT_CLASS_B=NOT_PROVEN
PRODUCT_DEFECT=NOT_PROVEN
```

## 4) Class C — fault origin

```
FAULT_MODULE=comctl32.dll
FAULT_RVA=0xBD02
EXIT_PROCESS=0xC000041D (STATUS_FATAL_USER_CALLBACK_EXCEPTION)
UNDERLYING=0xC0000005 write
FAULT_ORIGIN_CLASS=C
```

C means: fault **executes in** comctl32 without a proven product defective callback. It does **not** mean “OS-only / ignore product.” Product still supplies the live HWND/message loop. Rebuild remains **HELD** until B is proven or A is isolated as sole reproducible cause with a harness-only fix path.

## 5) Classification matrix (fail-closed)

| Claim | Status |
|-------|--------|
| Multi-notify sole harness | **REFUTED** (sealed; unchanged) |
| Fault locus comctl32+0xBD02 | **PROVEN** → class **C** origin |
| Product WinMain + pump on stack | **PROVEN** (participation) |
| Product WndProc defect (B) | **NOT_PROVEN** |
| Clear/SetEdit residual (A) | **SUSPECTED_NOT_PROVEN** |
| CRASH_ROOT_CAUSE | **NOT_PROVEN** |
| PRODUCT_DEFECT | **NOT_PROVEN** |
| Residual class | **MIXED_RESIDUAL** |

```
PRODUCT_DEFECT=NOT_PROVEN
REBUILD=HELD
REBUILD_AUTHORIZED=0
PROMOTE=0
```

## DISPOSITION

```
DISPOSITION=MIXED_RESIDUAL_COMCTL32_ORIGIN_NO_PRODUCT_CALLBACK
RESIDUAL_CLASS=MIXED_RESIDUAL
FAULT_ORIGIN_CLASS=C
HARNESS_RESIDUAL_A=SUSPECTED_NOT_PROVEN
PRODUCT_CLASS_B=NOT_PROVEN
HARNESS_SOLE=REFUTED
PRODUCT_DEFECT=NOT_PROVEN
CRASH_ROOT_CAUSE=NOT_PROVEN
REBUILD=HELD
PROMOTE=0
```

Sealed ChatWindow / Token64 / GhostText remain closed. Prior `HARNESS_VS_PRODUCT.md` sole-harness refute preserved.

## NEXT_ACTION

1. Optional same-SHA narrow Cancel matrix (no rebuild): Cancel **no-Clear**; **WM_SETTEXT-only** vs dual SetEdit — crash Y/N (shrinks A residual; does not prove B).
2. Or cdb/true unwind + PDB (if available later) to name callback — only path that can flip B / PRODUCT_DEFECT.
3. Authorize rebuild only after named defective product callback + deterministic fix spec + `REBUILD_AUTHORIZED=1`.

```
NEXT_GATE=OPTIONAL_NARROW_CANCEL_MATRIX_OR_CDB_UNWIND
```
