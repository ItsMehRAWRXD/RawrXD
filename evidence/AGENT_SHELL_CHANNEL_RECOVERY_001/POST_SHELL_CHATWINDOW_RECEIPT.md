# POST_SHELL_CHATWINDOW_RECEIPT

ASOF_UTC=2026-11-02T14:53:32Z
CANDIDATE_SHA=CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB
SHA_MATCH=1
PARENT_SHELL=PASS
NATIVE_CMD=PASS

## Fresh same-SHA ChatWindow (after shell recovery)

| Step | Result |
|------|--------|
| OLLAMA_UP | 1 |
| LAUNCH | pid=8872 |
| CREATE_SHOW | 1 |
| PROMPT_SUBMIT | 1 |
| MODEL | COMBO_INDEX_0 (45 entries; preferred names unmatched) |
| RESPONSE_OK | 0 |
| CANCEL_OK | 0 (stop disabled) |
| CRASH | 0 |
| DISPOSITION | FAIL_CLOSED_RESPONSE_NOT_OBSERVED |

Harness exit=1 · elapsed≈134s · PROMOTE=0

Shell recovery did **not** clear ChatWindow FAIL. Product path still broken/unproven for response+cancel.
See CHATWINDOW_RESPONSE_TRACE_001 for first-missing `BACKEND_GENERATE_HTTP_COMPLETE`.
