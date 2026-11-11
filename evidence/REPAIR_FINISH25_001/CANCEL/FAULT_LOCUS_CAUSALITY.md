# FAULT_LOCUS_CAUSALITY — Request A Cancel (additive; sealed dumps untouched)

ASOF_UTC=2026-11-08T22:39:39Z
AUTH=REPAIR_AUTHORIZATION=ALL_GRANTED
REBUILD_AUTHORIZED=1
BASELINE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD

## Controlling return

```
CRASH_ORIGIN=COMCTL32_RVA_0xBD02_SAME_PATH_FOUR_DUMPS
FAULT_INSN=comctl32+0xBD02
FAULT_WRITE=1
FAULT_RCX=TARGET_VA (write dest; ASLR-variant per dump)
REGS_COMMON=RBP=0xF000 RDX=0xFFFF R8=0 R9=0x7FFEFFFF pattern
FIRST_RAWRXD_FRAME_SHARED=+0x12FB9C (message pump after GetMessageA) then +0x33F9 (WinMain)
FIRST_RAWRXD_NEARER_172824=+0x11BB30 (GhostText subclass WndProc — kGhostTimer 0x5247)
CONCRETE_CANCEL_CALLBACK=NOT_PROVEN
HWND_LIFETIME_DEFECT=NOT_PROVEN
UI_THREAD=YES (exception TID owns user32/comctl32 dispatch)
DESTRUCTION_ORDER_DEFECT=NOT_PROVEN
PRODUCT_DEFECT_CANCEL=NOT_PROVEN
CAUSAL_CLOSURE=NOT_PROVEN
CANCEL_PRODUCT_FIX=NOT_APPLIED
```

## Four-dump compare (sealed triad + additive 172824)

| Dump | Code | Write | RIP | RCX/target | RBP | First shared product | Nearer product |
|------|------|-------|-----|------------|-----|----------------------|----------------|
| 070906 | C0000005 | 1 | comctl32+BD02 | 0x154AE8E0D0 | F000 | +12FB9C / +33F9 | +1365D4 (forwarder; not Cancel) |
| 073409 | C0000005 | 1 | comctl32+BD02 | (same class) | F000 | +12FB9C / +33F9 | none between comctl32 and pump |
| 092638 | C0000005 | 1 | comctl32+BD02 | (same class) | F000 | +12FB9C / +33F9 | (triad class) |
| 172824 | C0000005 | 1 | comctl32+BD02 | 0xBA8594E570 | F000 | +12FB9C / +33F9 | **+11BB30 GhostText** |

Sources: `CANCEL\logs\stack_parse_{070906,073409,092638,172824}.txt` (172824 parsed this turn; sealed dumps not overwritten).

```
SAME_PATH=YES
FAULT_SIGNATURE=PROVEN_COMCTL32_RVA_0xBD02
LIVE_REPRO_CANCEL_PATH=1
```

## Instruction / write / regs (fault locus)

- Exception: `STATUS_ACCESS_VIOLATION` write (ExceptionInformation[0]=1) at `comctl32.dll+0xBD02`.
- Process exit class: `0xC000041D` STATUS_FATAL_USER_CALLBACK_EXCEPTION (Request A survival harness).
- CONTEXT: RIP=comctl32+0xBD02; RCX=write target VA; RDX=0xFFFF; R8=0; R9=0x7FFEFFFF; RBP=0xF000 across dumps (register fingerprint stable; VA ASLR-variant).
- Dual `comctl32.dll` mappings persist (Win32 + comctl32 v6 class).

Exact comctl32 mnemonic at +0xBD02 remains OS-binary-local (no PDB this gate). Fault **locus** is proven; initiating product callback is not.

## Crash stack class

Near-fault: `comctl32+BD02 ← comctl32+17C1E ← comctl32+18EC8 family ← user32 dispatch ← product pump`.

Shared product frames (all four): `RawrXD+0x12FB9C` (GetMessageA return in pump `0x12FB80`) and `RawrXD+0x33F9` (WinMain `FUNC_26C0`). These are **above** `DispatchMessageA`, not the faulting user callback body.

## First RawrXD frame — identity

| RVA | Identity | Cancel causality |
|-----|----------|------------------|
| +0x12FB9C | Message pump (GetMessageA/IsDialogMessageA/TranslateMessage/DispatchMessageA) | Participation only |
| +0x33F9 | WinMain caller of pump | Participation only |
| +0x11BB30 (172824) | GhostText EDIT subclass: WM_TIMER wParam **0x5247** (=`kGhostTimer` in `Win32IDE_GhostText.cpp`), WM_KEYDOWN Tab/Esc | **Not** Cancel/Stop/ChatWindow click handler |
| +0x1365D4 (070906) | Multi-arg forwarder | Not proven Cancel WndProc |

## Request A cancel lifecycle (callbacks / HWND / UI thread / destruction)

- Harness: NO_CLEAR + WM_SETTEXT_ONLY + SINGLE_BM_CLICK Cancel submit (`harness_request_a_survival.ps1`).
- Crash ~0.6–3.4s after Send on UI thread; Stop/B never reached → `REQUEST_A_SURVIVES=0` on baseline SHA.
- No dump-proven Cancel button WndProc / BN_CLICKED product frame between comctl32 fault and pump.
- HWND lifetime / destruction-order UAF: **NOT_PROVEN** (no HWND value + destroy ordering in residual stacks).
- GhostText subclass appears on 172824 stack → optional reentrancy hypothesis only; **does not** authorize Cancel product fix without named defective Cancel callback.

## Gate

```
PRODUCT_DEFECT_CANCEL=NOT_PROVEN
→ no Cancel tip-source patch this candidate
T07/T08 product defects on sealed SHA remain independently PROVEN → rebuild for those only
PROMOTE=0
```

Artifacts: `stack_parse_172824.txt` · this receipt · baseline `CRASH_ORIGIN_REQUEST_A_20261108.md` (unchanged authority for live repro).
