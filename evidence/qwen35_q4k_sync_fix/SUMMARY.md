# Qwen3.5 Q4_K projection batching fix

## Source and build

- Source fix: `src/deep2/quant_dot_dispatch.cpp`
- Fix: Q4_K dots no longer enter the deferred quant-dot batch path; they use the synchronous upload/dispatch/readback path whose activation ownership is independently verified.
- Target: `deep2_gpu_certify`
- Build: `cmake --build build --config Release --target deep2_gpu_certify -j 6`
- Build result: PASS

## Runtime evidence

Model: `models/pdurugyan_qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2_latest.gguf`

Command:

```powershell
$env:DEEP2_Q4K_EXACT_CHECK='1'
build/bin/Release/deep2_gpu_certify.exe --model models/pdurugyan_qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2_latest.gguf --tokens 1 --dump evidence/qwen35_q4k_sync_fix/cert
```

- GPU calls: 273
- CPU fallbacks: 0
- Block 3 Q4_K GPU-vs-exact max absolute error: `0.0174969031`
- Previous batched-path error: `4.18493493`
- Final logits: still FAIL (`cos=0.9984229`, `max_abs=1.072`)
- GPU/CPU argmax: 760 / 760

The projection boundary is materially corrected, but the full-logit parity gate remains open. This evidence does not certify the complete Qwen3.5 forward path.
