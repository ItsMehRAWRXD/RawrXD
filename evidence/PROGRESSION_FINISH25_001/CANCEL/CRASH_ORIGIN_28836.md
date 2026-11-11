# Request A crash origin — SHA 323A38A0 / pid 28836

ASOF_UTC=2026-11-09T02:10:00Z
ACTIVE_SHA=323A38A0849EFDE08F735EF85D97009D68C4700C9670317FCC2B630E85580E37
EXE=F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe
SHA_VERIFIED=1
PROMOTE=0
CERTIFIED=0

## Exception (re-proved from this SHA's dumps)

| Field | Primary dump | Alt dump |
|-------|--------------|----------|
| File | `RawrXD-Win32IDE-Native.exe.28836.dmp` | `RawrXD-Win32IDE-Native.exe(1).28836.dmp` |
| ExceptionCode | `0xC0000005` ACCESS_VIOLATION | `0xC000041D` STATUS_FATAL_USER_CALLBACK_EXCEPTION |
| ExceptionAddress | `comctl32.dll+0xBD02` | `comctl32.dll+0xBD02` |
| Write | yes (info[0]=1) target `0x16EED0E490` | outer wrapper |
| ExceptionThreadId | 31384 | 31384 |

Parse artifacts:
- `CANCEL\logs\stack_parse_28836.txt`
- `CANCEL\logs\stack_parse_28836_alt.txt`
- `CANCEL\logs\rva_pdata_map_28836.txt`

## Product frames (this SHA layout — not assumed from older EXEs)

| RVA | pdata function | Identity |
|-----|----------------|----------|
| `+0x119DF0` | `[0x119DF0..0x11A44A)` | `NativeGhostTextController::editorProc` — GetProp `"RawrXD.GhostText"`, handles `WM_TIMER`/`0x5247` (`kGhostTimer`) |
| `+0x1275BF` | `[0x127540..0x127618)` | `runMessageLoop` after `GetMessageA` |
| `+0x1D58xx` / `+0x2450F0` | n/a | `.rdata`/`.data` stack-scan noise — ignore |

## Ownership judgment

```
CRASH_ORIGIN=comctl32.dll+0xBD02_AV_WRITE
OUTER_EXIT=0xC000041D
NEAREST_PRODUCT_WNDPROC=NativeGhostTextController::editorProc
TIMER_ID=0x5247
SEND_STACK_AMPLIFIER=SetWindowTextA_clear_under_GhostText_subclass
REQUEST_A_SURVIVES=0 (pre-fix)
CANCEL_PRODUCT_DEFECT=TIP_GHOSTTEXT_ADMISSION_LIFETIME
PROMOTE=0
```

Do not treat WinMain/message-pump frames as the faulting callback body.
Do not reopen T08. Controlling SHA 55BE19B7 untouched.
