# REVERSE: Win32 CommandLine → token generation

## Operator witness (Get-CimInstance / Get-Process)
```text
Win32_Process.CommandLine
  = which .exe owns the GPU / evidence log
  ≠ the token path itself
```
Measured contention: `build_fused_control\...\sustained_cert.exe` and
`build-ninja\...\sustained_cert.exe` both write
`evidence/K2_LIVE_DECODE_SUSTAINED_001/` and open the same R9700.
Only **build-ninja** CommandLine is authoritative for this gate.

## Real ownership chain (K2 live)
```text
CommandLine → deep2_k2_live_decode_sustained_cert.exe
  main()
    Sync(DEEP2_REAL_K2_GENERATE=1, DEEP2_K2_GPU_MLA=1, PIN=1, Q4_ONLY=0, …)
    eng.initialize + openK2ShardDirectory(Q4_K_M)
    SetPinResidentBudget(elastic hot) + K2GpuStreamCopy_Bind
    eng.generateStream(prompt, maxTokens=T, cb)
        │
        ├─ FICTION PRINT: LIVE_FORWARD=forwardTokenAllLayers
        └─ REAL: DEEP2_REAL_K2_GENERATE → runK2NativeStreamPartial(kc)
              LivePath_BeginGenerate(T)   // trampoline/cyclone/elastic
              for step in 0..T-1:
                LookupRealTokenEmbed(curToken → hidden)
                ForwardMLALayers(D=61)
                  RunMlaOnPayloads → MLAForward::Execute
                    K2MLAWeights → MLA_Gemv(Q4|Q8)   // NEVER MLA_TryGpuGemv
                      TryGpu → DispatchGEMVPacked|Quant + pin cache
                      else GetGEMV
                rmsNorm(output_norm)
                ProjectLogitsArgmax → next curToken   // ← TOKEN BIRTH
                ghostTok.push_back(curToken)          // IDs only on hot path
              DecodeToken(ghostTok[]) → generatedText // un-ghost once
        callback(lastId, fullText)  // ONE fire, not per-token stream
```

## Counters that prove the chain
| Witness | Meaning |
|---------|---------|
| `LIVE_K2_OWNERSHIP=generateStream→runK2NativeStreamPartial` | seam taken |
| `TRYGPU_ENTRY=0` / `GEMV_ENTRY=6×D×T` | MLA_Gemv authority |
| `OPS=6×D×T` | Q4+Q8 GPU (not Q4-only fiction) |
| `UP≈0 HIT=6×D×T` after warm | pins sticky |
| `ghost_ids` / `OUT>0` | tokens existed + detok |

## Measured (exclusive ninja, before W128 death)
| Window | ops | up | pinRej | ok |
|--------|-----|----|--------|-----|
| WARM 8 | 2928/2928 | warm fill | 0 | 1 |
| W32 | 11712/11712 | 0 | 0 | 1 |
| W64 | 23424/23424 | 0 | 0 | 1 |
| W128 | LIVE_SETUP ok → process exit | — | — | CRASH |

## Next best move
1. Rebuild sustained after MoEEliminate.obj is in InferenceEngine.lib (now in ninja).
2. Isolate `DEEP2_SUSTAINED_WINDOWS=128` (warm+128 only) vs full 32/64/128.
3. If isolate PASSes → cumulative LivePath/tramp state after 3 requests.
4. If isolate crashes → T=128 / policy REUSE_STEPS path itself.
5. Do not retune MLA kernel until W128 completes with OPS exact.
