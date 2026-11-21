# DeepSeek-Coder-V2 (MoE): Deep2 vs llama.cpp reference — 2026-11-21

Sprint gate: **independent reference parity on a MoE model**

## Setup

```
model   F:\rawrxd\models\deepseek-coder-v2_16b.gguf
        (llama.cpp reports arch=deepseek2, DeepSeek-Coder-V2-Lite-Instruct, vocab 102400)
tokens  100000 549 6077 280 7239 317     (llama-tokenize of "The capital of France is")
Deep2   ltt_tensor_invoke.exe --device=0 --logits-out      -> 3624 gpu_calls, 0 cpu_calls
ref     llama_dump_intermediate.exe <gguf> tokens.txt ref --no-hidden  -> 403 boundaries/pos
```

Both sides consumed the identical six token IDs at identical positions.

## Result

| pos | cosine | max_abs | rmse | Deep2 top1 | llama.cpp top1 | match |
|---|---|---|---|---|---|---|
| 0 | 0.778248916 | 19.6194 | 4.6275 | 185 | 2 | ✗ |
| 1 | 0.450456176 | 30.9990 | 6.4117 | 100001 | 21329 | ✗ |
| 2 | −0.011113099 | 30.3624 | 7.8552 | 100001 | 280 | ✗ |
| 3 | 0.206425659 | 27.4865 | 6.5799 | 473 | 254 | ✗ |
| 4 | 0.214180524 | 30.7492 | 8.4065 | 184 | 317 | ✗ |
| 5 | 0.253700014 | 29.0645 | 7.4015 | 317 | 8913 | ✗ |

**ARGMAX_MATCH 0/6.**

## Interpretation

* Deep2's **shared DeepSeek2 forward** already diverges at position 0 (cos 0.78) and is
  effectively uncorrelated from position 1 onward (cos ≈ 0 at pos2).
* This is **not** a Strata residency defect: residency ON vs OFF is bit-identical
  (`540115e9db`), so both paths execute the same wrong forward.
* Magnitude (max_abs 20–31, rmse 4.6–8.4) is far beyond fp32 accumulation noise.
* llama.cpp reports the same GGUF as `arch=deepseek2`, so the architecture is
  supported by the reference; the divergence is in Deep2's implementation.

## Caveats

* Token alignment is assumed correct (same ids, same positions, same convention).
  The first follow-up must confirm alignment by checking whether the reference's
  top-1 at pos0 (token 2) and Deep2's top-5 are plausible continuations.
* Single prompt, 6 positions, GPU vs CPU reference.
* No per-layer op trace comparison yet — the 403 reference boundaries per position
  are available under `ref/pos0..5/` for exactly that.

## Next

1. Confirm token/position alignment, then run the variant-aware op comparison
  (`first_divergence.py`) on `ref/pos0` to find the first divergent boundary
  (expect attention/MoE routing rather than embedding).
2. Compare Deep2 CPU path vs llama.cpp on the same tokens to separate
  quantised-kernel error from a structural (routing/layout) error.
3. Do not change kernels until the first divergent op is identified.