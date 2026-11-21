# Routed-expert SwiGLU fix — full acceptance — 2026-11-21

Sprint gates: **positions 0–1 parity, Strata ON/OFF bit-exactness, GPU-only execution**

## Fix

`src/deep2/runtime_graph_executor.cpp` (OpMoEExecute, routed experts):

```cpp
- const float s = 1.0f / (1.0f + std::exp(-g[j]));   // sigmoid(gate)
+ const float s = g[j] / (1.0f + std::exp(-g[j]));   // silu(gate)
```

Commit `be001dfc4e`.

## 1. Six-position reference parity (independent llama.cpp)

```
deep2_gpu_certify.exe  SHA256 04C2D9A4E2B84A2468C3D6353A4CCDC69F526B7D7D7B7C6A86E32EC3AA6AFCB3
model deepseek-coder-v2_16b.gguf (deepseek2, 27 blocks, vocab 102400)
tokens 100000 549 6077 280 7239 317

pos=0  cos=0.9998883  max_abs=0.4801  PASS
pos=1  cos=0.9972368  max_abs=1.7080  PASS
pos=2  cos=0.9973797  max_abs=1.4090  PASS
pos=3  cos=0.9992827  max_abs=0.7607  PASS
pos=4  cos=0.9990932  max_abs=0.7287  PASS
pos=5  cos=0.9985561  max_abs=0.9796  PASS
VERDICT=PASS_FULL_MODEL   CERT_STATUS=PASS_FULL_MODEL
```

Before the fix: pos0 0.7782, pos2 −0.0111, argmax 0/6.

## 2. Strata ON/OFF bit-exactness (fixed build)

```
deep2_strata_chat.exe  --prompt "The capital of France is" --max-new 6 --gpu --logits-out
  --strata   : gpu_calls=7248 cpu_calls=0, expert ledger 5616 obs / 2967 hits / 2649 misses / 0 evictions
  --no-strata: gpu_calls=7248 cpu_calls=0
BIT_IDENTICAL True   (6/6 steps)
```

## 3. GPU-only execution

```
gpu_calls=7248   cpu_calls=0   fallback=<none>   nonfinite_logits=0
```

## Status

```
POSITIONS_0_1=PASS (cos 0.9998883 / 0.9972368, argmax match)
POSITIONS_2_5=PASS
SIX_POSITION_PARITY=PASS
STRATA_ON_OFF_BIT_EXACT=PASS (fixed build)
GPU_ONLY=PASS (0 CPU fallbacks)
DEEPSEEK2_PARITY_WORKSTREAM=COMPLETE for this model and test configuration
```

## Remaining (separate workstreams)

* H11 dispatch account still unwired (`GPU Cmd Dispatches: 0` vs 8 Vulkan submissions).
* `Quant Kernel Invocations: 0` on the GEMV path — packed-quant dispatch is proven by
  `packed_quant_ok`, but the registry counter is not fed.
* IDE relink was blocked (executable missing/locked); IDE chat E2E still not certified.
* No throughput/quality certification; single prompt, 6 positions.