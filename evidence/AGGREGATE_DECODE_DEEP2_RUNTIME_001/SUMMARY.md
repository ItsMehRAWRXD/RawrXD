# AGGREGATE_DECODE_DEEP2_RUNTIME_001

CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD

## Result
- `deep2_runtime_reached=1` on single + multi (streams=2)
- BACKEND=DEEP2 / BACKEND_LABEL=DEEP2_ENGINE
- No Ollama HTTP fallback; no stub tokens
- GGUF: `F:\ollamamodels\n4-tiny-oracle.gguf` (ollama n4-tiny-oracle blob hardlink)

## Exits
- BUILD_EXIT=0 (aggregate_decode_* linked to deep2_engine_lib, AGGREGATE_DECODE_USE_DEEP2=1)
- SINGLE_SMOKE_EXIT=0 GENERATED_TOKENS=8 TPS≈0.28
- MULTI_SMOKE_EXIT=0 GENERATED_TOKENS=12 STREAMS=2 ALL_SESSIONS_WORKED=1

## Exes
- `F:\rawrxd\build\bin\aggregate_decode_single_smoke.exe`
- `F:\rawrxd\build\bin\aggregate_decode_multi_smoke.exe`

## Notes
- Deep2Backend uses a decode mutex (engine not MT-safe); multi still exercises ≥2 sessions with real tokens.
- Full deep2_engine_lib tip rebuild hit unrelated KVCache churn; smokes linked against existing Release `deep2_engine_lib.lib` (`BuildProjectReferences=false`).
