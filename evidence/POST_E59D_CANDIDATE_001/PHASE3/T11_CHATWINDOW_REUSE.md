# T11 — ChatWindow full-response acceptance (REUSE)

ASOF_UTC=2026-11-03T14:45:00Z
GATE=FINISH_25_T11
RESULT=PASS
METHOD=SHA_BOUND_REUSE
RERUN=0
CONTRADICTION=0
PROMOTE=0
CERTIFIED=0
REBUILD=HELD

```
CERT_EXE=F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
LIVE_SHA_MATCH=1
SIZE=6080512
```

## Authority (sealed, same SHA)

| Artifact | Path | Seal |
| -------- | ---- | ---- |
| SHA binding | `CHATWINDOW\HARNESS_AND_SHA_BINDING.md` | PASS · UI_RESPONSE_BYTES=3307 · MODEL=gemma3:4b |
| Runtime | `CHATWINDOW\CHATWINDOW_RUNTIME_RECEIPT.md` | TOKEN64 retry2 authoritative |
| Tokens | `TOKEN64\RECEIPT.md` | CHATWINDOW_E2E=PASS · GENERATED_TOKEN_COUNT=648 |

## Contradiction check (this turn)

- Live Get-FileHash == TARGET_SHA.
- Binding SHA_PRE=SHA_POST=TARGET_SHA.
- RESPONSE.txt present with TOKEN64_DONE; no contrary FAIL on same SHA for ChatWindow E2E.
- Historical CHATWINDOW_RUNTIME FAIL @ 11:53:51 remains superseded (documented in binding).

## Law

`NOT_RUN != PASS`. Reuse only because sealed evidence is SHA-bound to controlling candidate. No ChatWindow rerun required.
