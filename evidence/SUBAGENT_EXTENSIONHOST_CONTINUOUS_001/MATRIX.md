# MATRIX — SUBAGENT_EXTENSIONHOST_CONTINUOUS_001

```
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 NO_INVENT_PASS=1
TIP=748B210A… TIP_FREEZE_001\bin
GHOSTTEXT_ABSORB=NOT_AUTHORIZED
```

| ID | Surface | Tip RUNTIME | Disposition | Note |
|----|---------|-------------|-------------|------|
| T01 | Tip SHA match | PASS | authority | 748B210A… |
| T02 | Tip `/api/subagent` | FAIL_CLOSED | journal `success:true` fiction on tip EXE | SOURCE fix wired; tip RUNTIME of fix NOT_RUN |
| T03 | Tip `/api/agent/run` | FAIL_CLOSED | HTTP 503 `model_not_loaded` | OPEN next |
| E01 | ExtensionHostIpcBridge client | n/a product | SOURCE_WIRED + GATED_OMIT | real ConnectAsClient / WriteLogicalMessage |
| E02 | Companion no-server | FAIL_CLOSED | exit 101 | honest |
| E03 | Companion pipe roundtrip | PASS smoke | BYTES=40 exit 0 | ≠ product tip PASS |
| E04 | Product ExtensionHost in tip | NOT_RUN | GATED_OMIT | blocker B02 |
| R01 | Tip relink + new freeze | NOT_RUN | compile blockers TerminalManager + CaretAnimation | B01 |

`NOT_RUN != PASS` · companion smoke ≠ tip CERTIFIED
