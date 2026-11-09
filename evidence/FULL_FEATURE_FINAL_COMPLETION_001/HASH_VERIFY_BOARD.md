# HASH_VERIFY_BOARD — FULL_FEATURE_FINAL_COMPLETION_001

ASOF_UTC=2026-11-09T10:19:30Z
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0
AUTHORITY=live Get-FileHash this turn + prior seals

## Controlling tip (live this turn)

| Role | SHA-256 | Path | Notes |
|------|---------|------|-------|
| **tip_final_integ_002 (CONTROL)** | `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` | `candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe` | RelWithDebInfo; SIZE=6152704; MATCH build_tip_debug_rel\bin |
| Frozen A4F | `A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E` | prior package root | **UNTOUCHED** |

## Peer / historical (no PASS inheritance)

| Role | SHA-256 | Seal |
|------|---------|------|
| tip_final_004 (prior best EXT/chat) | `EA5D9B6979E8A60DD6899CCA23B3762CA48695234A18965534E4C1E7732442AE` | historical |
| tip_terminal_conpty_001 | `D28128AECAA7C9E0301A227A9102A8922CEF8BC4BC79635228D93FD74C195529` | peer specialty |
| tip_debug_001 (Debug CRT) | `7F8EB40703314D3315C2F277F1FABCC417C2D13C669DE7841D2E327E95673F93` | peer specialty |
| tip_final_integ_001 | `7582A0C9899E0EA587E98F6343BBF8F28364713701CA91CF58319C20D46E2F58` | superseded |
| full_feature_rc_001 | `BD529691FE18D7E2EDB77D98E4C33424FF705C0BEE263429DAD600E11F42D25E` | packaging |

## Image string / CRT probe (CC79 live)

```
CreatePseudoConsole=HIT
WaitForDebugEvent=HIT
CHAT_SEND_ATTEMPT=HIT
VCRUNTIME140D/MSVCP140D/ucrtbased=MISS
VCRUNTIME140/MSVCP140=HIT
```

## RelWithDebInfo (`build_tip_debug_rel`)

```
CMAKE_NINJA=PRESENT
Native-Ext.exe=PRESENT bin\RawrXD-Win32IDE-Native-Ext.exe
SHA256=CC79F6CD… (same as tip_final_integ_002)
debug_backend_verify.exe=PRESENT
debuggee_fixture.exe=PRESENT
```

```
FROZEN_A4F_UNTOUCHED=1
OVERWRITE_FROZEN_PACKAGE=FORBIDDEN
NO_CROSS_SHA_PASS_INHERITANCE=1
```
