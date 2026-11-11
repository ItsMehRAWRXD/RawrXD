# AGGREGATE_DECODE_E2E_001

CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD

## Exes
- `F:\rawrxd\build_aggregate_decode\bin\aggregate_decode_single_smoke.exe` exit 0
- `F:\rawrxd\build_aggregate_decode\bin\aggregate_decode_multi_smoke.exe` exit 0

## Metrics
- Single: GENERATED_TOKENS=16 AGGREGATE_DECODE_TPS_SINGLE≈39.95 BACKEND=OLLAMA_HTTP MODEL=n4-tiny-oracle:latest RUNTIME_REACHED=1
- Multi: STREAMS=4 CONCURRENT=1 GENERATED_TOKENS=48 AGGREGATE_DECODE_TPS_MULTI≈29.87 WORST_STREAM_TPS≈7.49 FAIRNESS_RATIO≈0.26 ALL_SESSIONS_WORKED=1 AGGREGATE_GE_MAX_STREAM=1

## Product API
- `AggregateDecodeSession` / `AggregateDecodeMultiSession` under `F:\rawrxd\src\deep2\aggregate_decode\`
- Deep2Engine backend source-wired (optional link); Ollama HTTP used for live E2E when Deep2 GGUF not linked
- Multi uses barrier + threads; aggregate_tps = sum(tokens)/shared_wall (not serial disguise)

## Build
MSVC 14.44.35207 via vcvarsall amd64; cmake+ninja `F:\rawrxd\build_aggregate_decode` BUILD=0
