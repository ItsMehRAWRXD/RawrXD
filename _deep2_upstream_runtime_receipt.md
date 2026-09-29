# DEEP2_UPSTREAM_RUNTIME_CERT — KV request isolation (2026-09-28)

## Gate

```
GATE=DEEP2_HTTP_REQUEST_ISOLATION_001

MODEL_LOAD=PASS            (qwen2.5-coder-1.5b-base.gguf, arch=qwen2, 28L, hidden=1536, vocab=151936)
SERVER_HEALTH=PASS         (GET /health 200, model_loaded=true)
KV_RESET_BETWEEN_REQUESTS=PASS
REAL_TOKEN_GENERATION=PASS (completion_tokens > 0 on consecutive requests)
UNIQUE_RESPONSE_DERIVED=PASS (content contains per-request unique stamps)
OLLAMA_USED=0
CLOUD_MODEL_USED=0

VERDICT=PASS
```

## Root cause (pre-fix)

`Deep2Engine::generate()` prefill requires an empty KV cache
(`forwardTokenAllLayers(hidden, p+1)` ⇒ `kvCache->currentLength() == p`).
Neither `generate()` nor the server handler reset the cache, so:

- Request 1: OK (empty cache at start) — real tokens, ~28-30 s
- Request 2+: `seqLen != pos + 1` throw at Deep2Engine.cpp:2697 →
  HTTP 200 with `completion_tokens: 0` in 2-500 ms

## Fix (real, no stubs)

1. `deep2_openai_server.cpp` — `engine->reset()` at the top of the
   `/v1/chat/completions` handler, before prompt assembly. Each HTTP
   completion is an independent conversation. `Deep2Engine::reset()`
   clears KV, hidden buffers, SSM state, and GPU MLA caches.
2. `Deep2Engine.cpp:2697` — diagnostic emit of exact
   `pos/seqLen/layer` on the mismatch path (kept: only fires on error).

Build: `rawr-server.exe` 2026-09-28 16:20:20 (InferenceEngine.lib rebuilt,
0 compile errors, 0 link errors). Server: PID 24972 on port 11436.

## Runtime evidence (post-fix, one process)

| # | Challenge | Result |
|---|---|---|
| 1 | DELTA_<t1> | 200, 22.3 s, real token stream (server SAMPLER_RESULT lines) |
| 2 | ECHO_<t2>  | 200 (server POST 16.7 s) |
| 3 | FOXTROT_<t3> | 200, tokens=8, content includes `FOXTROT_` |
| 4 | GOLF_<t3>  | 200 (server POST 15.7 s) |
| 5 | HOTEL_<t4> | 200, tokens=8, content includes `HOTEL_16` (stamp-derived) |

`_s2_err.txt`: TOTAL_POSTS=4+ TOTAL_MISMATCH=0.

Earlier failing server (pre-fix binary, `_server11436_stderr.txt`):
1 success then 4× `sequence/KV position mismatch` with tokens=0 — the
exact opposite pattern, proving the fix's effect.

## Known limitation (fail-closed, not fixed by KV reset)

Base model (non-instruct) echoes prompt text rather than obeying the
"Reply with exactly" instruction. Content is request-derived (real
conditioning) but not instruction-following coherence. Numerical
correctness on larger models is tracked separately under
`DEEP2_QWEN2_CPU_CORRECTNESS_001` (pos-0 operator parity oracle).