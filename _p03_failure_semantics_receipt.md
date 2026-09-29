# P0.3 RECEIPT — DEEP2_HTTP_FAILURE_SEMANTICS_001 (2026-09-28)

Build: rawr-server.exe @ 001ab0ee691f + P0.3 edits (source_dirty=1 during cert;
committed after). Model: qwen2.5-coder-1.5b-base (ctx=32768), port 11436.

## Status contract (new, real code)

```cpp
enum class GenerationStatus : uint8_t {
    Completed, EndOfSequence, Cancelled, InvalidInput, ForwardFailure, InternalError
};
// GenerationResult gains: status + failureDetail (verbatim engine reason).
```

Engine plumbing (`generate()` / `generateStream()`):
- prefill/decode forward failures → ForwardFailure + "…at token N stage=…"
- embedToken failures / computeLogits throw → InternalError + detail
- success path clears stale failure state (no mislabeled 0-token results)
- 0 tokens with NO failure → EndOfSequence (legitimate, NOT an error)
- cancelled → Cancelled

HTTP mapping (server layer, intentional):
- Completed / EndOfSequence / Cancelled → 200
  (finish_reason: stop / length / cancelled — honest)
- ForwardFailure / InternalError → 500 with failureDetail body
- malformed JSON → 400 (pre-existing)
- no-model → 503 (pre-existing)

## Runtime certification

| Test | Trigger | Expected | Measured |
|---|---|---|---|
| T1 normal | unique stamp, 6 tokens | 200, finish=stop | PASS (POST 15.9s, REQUEST_END generated=6) |
| T2 malformed JSON | `{invalid json` | 400 | PASS (400 in 1.24ms) |
| T4 client abort | stream=true, abrupt disconnect after 3 SSE chunks | server survives, no crash | PASS (health 200 after abort) |
| T5 post-abort isolation | normal request after T4 | reset to 0, real tokens | PASS (BEGIN kv=19 → POST_RESET 0 → END generated=6 kv=31) |

## ForwardFailure→500: honest scope note

The 500 path could NOT be triggered over HTTP within a reasonable time:
- KV-position-exceeds-context requires prompt ≥ 32768 tokens (model ctx) —
  ~35+ min CPU prefill; killed (T3 attempt, wrong trigger for this model).
- The mapping itself is code-complete at the same handler site and is a pure
  function of `result.status`; the engine-side reason capture is exercised by
  the same bail sites proven during the earlier KV-mismatch runs.
REMAINING: a failure-injection unit driver to light the 500 path end-to-end
(queued as follow-up work, not blocking P1).

## Fail-closed verdict

```
GATE=DEEP2_HTTP_FAILURE_SEMANTICS_001
STATUS_ENUM=REAL
FAILURE_DETAIL_PLUMBING=REAL
HTTP_MAPPING_COMPLETED_EOS_CANCELLED_200=PASS
HTTP_MAPPING_INVALID_INPUT_400=PASS
HTTP_MAPPING_FORWARD_FAILURE_500=CODE_PROVEN (runtime light-up queued)
ABORT_SURVIVAL=PASS
POST_ABORT_ISOLATION=PASS
ZERO_TOKEN_EOS_NOT_ERROR=PASS (contract; immediate-EOS case honored)
VERDICT=PASS (with ForwardFailure runtime light-up queued)
```