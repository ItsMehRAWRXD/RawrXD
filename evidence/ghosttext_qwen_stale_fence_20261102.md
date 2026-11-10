# GhostText Qwen routing and stale-fence runtime evidence

Date: 2026-11-02

## Observed lifecycle

- GhostText route selected: `qwen3:8b`.
- Requests 5 through 10 logged `GHOSTTEXT_REQUEST_SENT`.
- Requests 5 through 9 were invalidated/cancelled before their responses arrived.
- Requests 5 through 9 later received successful responses, but each emitted `GHOSTTEXT_RENDER_DECISION ... eligible=0`.
- Request 10 received a successful response with `response_bytes=8`, then emitted `eligible=1` and `GHOSTTEXT_RENDERED`.
- Every dispatch log identified `backend=ollama` and `qwen3:8b`.

## Gate disposition

```ini
EXPLICIT_QWEN_ROUTING=PASS_OBSERVED
OLLAMA_DISPATCH=PASS_OBSERVED
STALE_RESPONSE_REJECTION=PASS_OBSERVED
LATEST_RESPONSE_RENDER=PASS_OBSERVED
REQUEST_IDENTITY_FENCE=PASS_OBSERVED
CONTROLLED_B_BEFORE_A_RACE=PASS_OBSERVED_CANDIDATE
B_RENDER_BEFORE_A=PASS_OBSERVED_CANDIDATE
A_LATE_RESPONSE_REJECTION=PASS_OBSERVED_CANDIDATE
CANDIDATE_SHA256=AC93969DC91E3B283029581DB0973FAF029FBB36342BD65C1166974E3ECBEB1C
PRODUCT_PROMOTION=NOT_AUTHORIZED
PROMOTE=0
```

The later same-run candidate receipt `F:\rawrxd\evidence\F_GATE6_QWEN_ORDERING_RUNTIME_002\FINAL_VERDICT.md` closes the previously open ordering question: request A was delayed 30 seconds, request B was delayed 50 ms, B rendered first, and A completed afterward with `eligible=0`. The candidate hash matches the current isolated executable. This closes the deterministic race gate for the candidate only; it does not certify or replace the frozen product binary.
