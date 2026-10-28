# RECEIPT — WIN32IDE_STUB_GATE_003_FOLLOWUP_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
PERFECT=0
NO_INVENT_PASS=1
REBUILD_TIP=0
RELINK=NO
ASOF_UTC=2026-10-28T17:26:10Z
TIP_SHA256=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
ABSORB_GHOSTTEXT_B421=NOT_AUTHORIZED
PARENT=WIN32IDE_STUB_GATE_003
SIBLING_OPEN=6d6bc8a3 O01–O05
MOTD_ACK=1
```

## Verdict

Follow-up closed the sibling **OPEN** list with honest dispositions only.
No tip overwrite. No invent RUNTIME PASS. Text evidence only.

| ID | Closed as | RUNTIME |
|----|-----------|---------|
| O01 | REAL_WINVERIFYTRUST (not theater); tip NotSigned → verify fail-closes | Handler path NOT_RUN |
| O02 | HWND_CREATE_REAL; seal ≠ tip chat certify | NOT_RUN as chat certify |
| O03 | MESSAGEBOX_RECEIPT_REAL; seal ≠ consent policy | NOT_RUN as policy certify |
| O04 | FAIL_CLOSED/NOT_RUN on frozen tip HWND ConPTY | RUNTIME_REACHED=0 (cite 748B runtime seal) |
| O05 | INVENTORY_ONLY; ASM present; bridge omit; tip unwired | NOT_PRODUCT_WIRED |

## Evidence inputs

- Tip SHA match `TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe` = 748B210A…
- `Get-AuthenticodeSignature` → Status=NotSigned
- Tip ASCII string scan (MATRIX)
- Source: `update_signature.cpp` WinVerifyTrust; `plugin_signature.cpp` winVerifyTrustCheck; `chat_panel.cpp` CreateWindowExW; `rawrengine_command_handlers.cpp` Consent/Chat/Update/Plugin
- `CONPTY_STREAM_OWNER_RUNTIME_748B_001\SUMMARY.txt` RUNTIME_REACHED=0
- CMake GATED_OMIT LoRAKernelBridge 5721–5725

## Explicit non-claims

```
NOT_RUN != PASS
PROMOTE=0
do not absorb B421 into tip
do not rebuild tip this seal
```
