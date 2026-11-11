# F41BAFB8 Request A native crash stack (fail-closed)

ASOF_UTC=2026-11-09T03:07:00Z
ACTIVE_TIP_SHA=F41BAFB874DEEA452D2BD0E8FE5EFB848D1E148E2E58192DB344B16831B33C75
PID=35440
HARNESS=REQUEST_A_SURVIVAL_RUNLOG_20261108-214423.txt
PROMOTE=0
CERTIFIED=0
T08_REOPEN=0
STOP_SPECULATIVE_UI_FIXES=1

## Artifacts sealed

| Kind | Path |
|------|------|
| Primary dump | `CANCEL/logs/RawrXD-Win32IDE-Native.exe.35440.dmp` |
| Alt dump (outer) | `CANCEL/logs/RawrXD-Win32IDE-Native.exe(1).35440.dmp` |
| Stack residual | `CANCEL/logs/stack_parse_35440.txt` |
| Stack residual alt | `CANCEL/logs/stack_parse_35440_alt.txt` |
| pdata map | `CANCEL/logs/rva_pdata_map_35440.txt` |
| disasm | `CANCEL/logs/disasm_around_119EB0.txt` |
| WER | `CANCEL/logs/WER_F41BAFB8/Report.wer` |

Parser: `POST_E59D_CANDIDATE_001/CANCEL/logs/parse_native_stack_residual.ps1`
cdb: NOT_PRESENT on this machine (Kits Debuggers absent). Residual minidump parse used instead.

## Exception context

| Field | Primary (.35440) | Alt ((1).35440) |
|-------|------------------|-----------------|
| ExceptionThreadId | 22852 | 22852 |
| ExceptionCode | `0xC0000005` AV | `0xC000041D` FATAL_USER_CALLBACK |
| ExceptionAddress | `comctl32.dll+0xBD02` | `comctl32.dll+0xBD02` |
| Info[0] | 1 (write) | 0 |
| Info[1] | `0x4AA34DE40` | 0 |
| Context.Rip | `comctl32.dll+0xBD02` | same |
| Context.Rsp | `0x8BEE52DA98` | same |
| Context.Rbp | `0xF000` | same |
| Context.Rcx | `0x4AA34DE40` | same |
| Context.Rdx | `0xFFFF` | same |

COMCTL32 variant (WER): `5.82.26100.8328` WinSxS common-controls v5.82  
TargetAppVer: `2026/11/09:02:43:44`  
Sig timestamp: `6af13360`

```
OBSERVED_FAULT_SITE=COMCTL32.dll+0xBD02
OBSERVED_FAULT_SITE_NE_PROVEN_ORIGIN=1
HYPOTHESIS_NE_PASS=1
```

## Product frames (F41 layout — not borrowed from 323A38A0)

| Stack slot | RVA | pdata range | Identity (proved) |
|------------|-----|-------------|-------------------|
| rsp+0x360 | `+0x119EB0` | `[0x119EB0..0x11A535)` | `NativeGhostTextController::editorProc` — GetProp path; `WM_TIMER`/`0x113`; `kGhostTimer=0x5247` imm at fileoff `0x119317` |
| rsp+0x480 | `+0x127AEF` | `[0x127A70..0x127B48)` | message-loop / GetMessage path (nearest pump frame) |

`.rdata`/noise RVAs (`+0x1D58xx`, `+0x2450F0`) = stack-scan residue — not ownership.

Compared to sealed 323A38A0: same COMCTL32 offset and same CallWindowProc slot pattern; product WndProc RVA shifted `0x119DF0 → 0x119EB0` with tip code growth; identity unchanged (`0x5247`).

## HWND / control context

```
MINIDUMP_HANDLE_DATA_STREAM=ABSENT (streams=3,4,5,6,7,13,15,21,22)
WER_CONTROL_HWND_LIST=ABSENT
HARNESS_MAIN_HWND=0x890AC2 (RawrXD_IDE_Window; survival runlog 214423)
HARNESS_CONTROLS_AT_SUBMIT=input=1202 send=1204 combo=1206 stop=1210 (IDs only; live HWNDs not persisted)
ACTIVE_SUBCLASS_PROC_ON_STACK=NativeGhostTextController::editorProc (+0x119EB0 @ rsp+0x360)
```

No dump-resident HWND→class map available without cdb/`!hwnd`. Ownership note is limited to: faulting callback chain still carries GhostText `editorProc` despite tip hard-detach claim.

## Ownership audit (evidence only — no patch judgment as PASS)

```
UI_THREAD=ExceptionThreadId 22852
CALLBACK_CHAIN=user32 CallWindowProc ↔ comctl32+0xBD02
LIVE_PRODUCT_WNDPROC=editorProc (+0x119EB0) STILL PRESENT ON FAULT STACK
GHOSTTEXT_DETACH_TIP=RUNTIME_INEFFECTIVE_ON_F41 (stack contradicts detach completion)
STREAMING_BUFFER_FIX=UNVERIFIED_ON_THIS_SHA (build hung / not in exercised F41 binary proof)
CHAT_RUNTIME_PRIOR=request_started without callback/partial_buffered before death
POST_SEND_TO_CRASH_S=~4.5
```

Do not treat COMCTL32+0xBD02 alone as root cause. Do not invent PASS. Do not reopen T08.

## Law

```
NOT_RUN != PASS
REQUEST_A_SURVIVES=0 (F41 exercised)
PROMOTE=0
NEXT=deterministic rebuild → Request A replay before any other gate
```
