# Gate 6 Qwen ordering runtime proof

Candidate SHA-256: `AC93969DC91E3B283029581DB0973FAF029FBB36342BD65C1166974E3ECBEB1C`

Frozen authority SHA-256: `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145`

Environment: `RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS=30000`, `RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS=50`.

Same-run trace:

- A request ID 1 routed to `qwen3:8b`, dispatched at `04:19:42`.
- B request ID 2 routed to `qwen3:8b`, dispatched at `04:19:43` while A was pending.
- B succeeded and rendered at `04:19:43`.
- A succeeded at `04:20:12` after B rendered.
- A had `generation_current=0` and `eligible=0`; no stale render occurred.
- Native editor focus was established before typing; the focused control was `RichEdit20A`, ID `1001`.
- Test-owned process cleanup completed forcibly; no unrelated RawrXD process was terminated.

```ini
EXPLICIT_QWEN_ROUTING=PASS
OLLAMA_DISPATCH=PASS
AB_OVERLAP=PASS
DETERMINISTIC_B_BEFORE_A=PASS
B_RENDER=PASS
LATE_A_REJECTION=PASS
CANDIDATE_SHA=AC93969D...
FROZEN_AUTHORITY=UNCHANGED
PROMOTE=0
CERTIFIED=0
```
