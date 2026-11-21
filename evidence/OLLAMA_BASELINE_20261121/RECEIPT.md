# Ollama direct generation baseline — 2026-11-21

Sprint gate: **establish a complete, non-streaming Ollama generation before adapter testing**

## Command

```powershell
$body = @{ model="qwen2.5-coder:1.5b-base"; prompt="Reply with exactly OK."
           stream=$false; options=@{ num_predict=64; temperature=0 }
           keep_alive="10m" } | ConvertTo-Json -Depth 5
Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/generate" -Method Post `
    -ContentType "application/json" -Body $body -TimeoutSec 180
```

## Observed

```
response          : "If you are not sure, please reply with OK. If you are not sure, ..."
thinking          : ""
done              : True
done_reason       : length
eval_count        : 64
prompt_eval_count : 5
load_duration     : 6,333,056,800 ns  (6.33 s)
total_duration    : 6,517,578,800 ns  (6.52 s)
```

## Interpretation

- **Ollama generation works end to end.** 64 tokens generated, `done=True`, finite
  timings, model `qwen2.5-coder:1.5b-base` warm-loaded.
- The response is repetitive because it is a **base** (not instruct) 1.1–1.5B model at
  temperature 0 — that is model capacity/decoding behaviour, not a transport defect.
- The earlier empty result from my one-liner was a **cold-load/timeout artefact**
  (`load_duration` alone is 6.3 s), not an adapter or server failure.

## What this unblocks

Adapter-specific runtime testing can now proceed against a known-good baseline:

* `OllamaBackend` `keep_alive` round-trip;
* `thinking` field extraction;
* truncation/`done_reason` classification.

## Still open

* `OLLAMA_HEALTH_PROBE` — `rawr backend status` reports ollama as `unavailable` with
  the note "not probed here", which is now demonstrably wrong while the server is
  serving. It should probe `GET /api/tags` with a bounded timeout (not a bare TCP
  connect, and not a 100 ms deadline that can false-negative under load), mapping
  200+valid → Available, refused/timeout → Unavailable, invalid → Degraded.
* Adapter runtime acceptance (above).
* Distinguishing *reachable* from *inference verified*: `/api/tags` success must not
  promote chat/stream/tool capabilities to Verified.

## Non-claims

This is server-level evidence. It does not verify `OllamaBackend` in RawrXD, nor
`rawr ask` (which routes through `InferenceClient`, not `OllamaBackend` directly).