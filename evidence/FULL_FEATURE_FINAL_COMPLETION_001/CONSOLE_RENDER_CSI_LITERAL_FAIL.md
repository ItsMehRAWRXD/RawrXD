# CONSOLE_RENDER_CSI_LITERAL_FAIL

ASOF_UTC=2026-11-09T12:55:30Z
MOTD_ACK=1
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
INVENT_PASS=0

```
CONSOLE_RENDERING=FAIL
COMMAND_EXECUTION=UNVERIFIED
ACCEPTANCE_PASS=0
COMPLETION_INCREASE=0
PRODUCT_PASS=0
CONTROLLING_TIP=CC79
A4F_IMMUTABLE=1
CROSS_SHA_PASS_INHERITANCE=0
```

## Running process capture (fail-closed, short timeout)

```
METHOD=CreateToolhelp32Snapshot+OpenProcess+QueryFullProcessImageNameW
HELPER=C:\Users\Garrett\AppData\Local\Temp\ProcCap_RawrXD.exe
TIMEOUT_MS=3000
NEEDLES=RawrXD-Win32IDE ; RawrXD
RESULT=NOT_RUNNING
CONFIRM=tasklist IMAGENAME eq RawrXD-Win32IDE.exe → no match
CONFIRM=tasklist IMAGENAME eq RawrXD-Win32IDE-Native-Ext.exe → no match
RUNNING_EXE_SHA256=NOT_RUNNING
RUNNING_EXE_PATH=N/A
MATCH=MATCH_UNKNOWN
```

No process image was available to hash. Do **not** invent a running SHA from on-disk fixtures.

## Offline fixture / build SHA matrix (measured this turn)

| Role | Path | SHA256 | Verdict |
|------|------|--------|---------|
| CC79 tip_final_integ_002 | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe` | `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` | **MATCH_CC79** |
| INTEG_004 sealed target | (expected under tip_004 slot) | `47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F` | **ABSENT** |
| tip_004 LIVE slot (this turn) | `...\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe` | `27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC` | MATCH_UNKNOWN (ONDISK_DRIFT; ≠47451; ≠CC79; ≠7504) |
| tip_005 | `...\tip_final_integ_005\RawrXD-Win32IDE-Native-Ext.exe` | `7504BAC45CDBA3DACF7A8CE30785971082C88101CC94586577771DE0C0FBAB48` | MATCH_UNKNOWN vs CC79/INTEG004 |
| G bin (stale Jul) | `G:\~dev\rawrxd\bin\RawrXD-Win32IDE.exe` | `D60C6F9A840D6EC824215BAE604EEF2561E5DE844C0F856893BE2E5AF5A0F31C` | MATCH_UNKNOWN |
| rxdn_live | `G:\~dev\rxdn_live\bin\RawrXD-Win32IDE.exe` | `896F8032199211C93FD7087616900B056B6A42E902C4390CD27CC968B107D3DA` | MATCH_UNKNOWN |

Prior mid-session tip_004 observations (drift evidence only; not controlling):
- earlier this turn: `35EFA9BAE44AD23F6007AC158E1BF0D6C297A5412C8DEF513434058C6D044351`
- then: `7504BAC45CDBA3DACF7A8CE30785971082C88101CC94586577771DE0C0FBAB48`
- now sealed above: `27E2263E…` (MTIME 2026-11-09T12:54:32Z)

```
MATCH_CC79=fixture tip_002 only (not running)
MATCH_INTEG_004=0 (47451F24 EXE ABSENT)
MATCH_REPAIR_BRANCH=0 (no built EXE proven byte-identical to F:\ HEAD)
MATCH_UNKNOWN=running + live tip_004 + G builds
```

## Source lineage — CSI / RichEdit (confirm repair branch differs)

| Tree | Branch / HEAD | `appendPowerShellOutput` | stripVt |
|------|---------------|--------------------------|---------|
| `F:\rawrxd` | `repair/menu-handler-defects` @ `b7db735b7644d4c9df57cef75a6e4c28c590dccf` | `stripVtForRichEdit(text)` then `EM_REPLACESEL` cleaned | **PRESENT** (hits=2) |
| `G:\~dev\rawrxd` | `feature/ide-agentic-product-path-20261026` @ `9edf63fed82bdf427f734591bff262282f6fe822` | UTF-8→wide → raw `EM_REPLACESEL` W | **ABSENT** (hits=0) |

`ANSIParser` remains unwired on the F:\ PowerShell panel path (strip helper is local to `Win32IDE_PowerShellPanel.cpp`, not ANSIParser). Interactive ConPTY `powershell -NoExit` startup path is unchanged as a product-behavior concern until a **running** EXE SHA proves which image painted the literal CSI.

Prior sealed narrative (“F:\ EM_REPLACESEL raw / no CSI strip”) is **stale vs current F:\ repair source**. That does **not** authorize FIX_CHOICE or ACCEPTANCE_PASS: running image was NOT_RUNNING, so lineage of the observed CSI litter is unproven.

## Disposition

```
RUNNING_EXE_SHA256=NOT_RUNNING
MATCH=MATCH_UNKNOWN
FIX_CHOICE=HELD
FIX_MAY_PROCEED=0
REASON=no running EXE SHA; source trees diverge (repair has stripVt; G feature branch raw); fixture SHAs cannot substitute for running image
CONSOLE_RENDERING=FAIL
COMMAND_EXECUTION=UNVERIFIED
ACCEPTANCE_PASS=0
COMPLETION_INCREASE=0
PROMOTE=0
CERTIFIED=0
NEXT=LAUNCH_OR_IDENTIFY_SYMPTOM_EXE → CAPTURE_RUNNING_SHA → THEN_CHOOSE_STRIP_OR_VT_OR_NONINTERACTIVE_PUMP
NO_NEW_ACCEPTANCE_PASS=1
```

## EXT_CLEANUP continue (INTEG_004 lineage only; FORCE_KILL=0 gate)

SHA capture finished early → lineage check only. **No harness re-run invented as PASS.**

```
INTEG_004_SEALED_SHA=47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F
INTEG_004_EXE_PRESENT=0
INTEG_004_EXT_CLEANUP=FAIL          # sealed receipt; FORCE_KILL=1
INTEG_004_EXTENSIONS=FAIL           # sealed; do not rewrite
LIVE_TIP004_SHA=27E2263E…           # ≠ 47451F24; cannot re-credit
INTEG_005_SUPERSEDE_SHA=7504BAC4…   # FORCE_KILL=0 EXT_CLEANUP=PASS on DIFFERENT SHA
EXTENSIONS_PASS_INTEG004=0
INVENT_EXTENSIONS_PASS=0
FORCE_KILL_REQUIRED_FOR_REVERIFY=0  # policy: only accept FORCE_KILL=0
BLOCKER=47451F24 EXE ABSENT + tip_004 slot ONDISK_DRIFT
```

Authority: `INTEG004_EXT_REVERIFY_RECEIPT.md` remains FAIL for `47451F24…`. `INTEG005_EXT_REVERIFY_RECEIPT.md` PASS does **not** inherit onto INTEG_004 / CC79 / live `27E2263E…`.
