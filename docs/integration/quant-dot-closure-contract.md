# DEEP2_GPU_QUANT_DOT_CLOSURE_001 — closure contract + current finding

## Acceptance record (target states)

```
DEEP2_GPU_QUANT_DOT_CLOSURE_001

model_loaded              = PASS     # real GGUF, real quantized bytes
real_gguf_weights         = PASS     # packed Q4_K/Q6_K rows straight from the GGUF
forward_executor_wired    = ???      # <- current blocker, see below
gpu_quant_dot_calls       > 0
cpu_quant_dot_fallbacks   = 0
unsupported_ops_fail_loud = PASS     # unsupported type/kind rejected, never CPU-silent
reference_parity          = PASS     # GPU vs independent CPU dequant+matvec
full_logits_finite        = PASS
full_vocab_argmax_match   = PASS
```

## Current state (audited 2026-10-12, this worktree)

| Component | Present | Notes |
|---|---|---|
| Vulkan quant-dot shader (`tools/shaders/quant_dot.comp`: Q4_K/Q6_K/Q5_0/Q8_0/Q4_0) | yes | exact GGUF geometry in-file |
| Dispatch + receipts (`QuantDot::DotBlocked/DotF16/BeginBatch/EndBatch/LastReceipt/BackendCounters`, `src/deep2/quant_dot_dispatch.{hpp,cpp}`) | yes | header RAWRXD_DEEP2_GPU_QUANT_DOT_001; 4/4 shapes on two AMD GPUs, cosine 1.0 |
| Backend stats (submits, waits, upload/download bytes, device_bytes_peak, kernel/submit/wait ms) | yes | instrumentation ready for the TPS certification |
| **Forward executor calling into the dispatch** | **MISSING** | the dispatch header names its intended caller `OpLinear`; no `OpLinear` (or any `DotBlocked` caller) exists in this worktree — verified by full-tree search |

The one-forward probe harness that printed `force_cpu` is also not in this tree,
which is why the strings don't appear in-repo.

## The one edit that closes this

Add the linear-op executor in front of the existing dispatch (no kernel work):

```
// src/deep2/op_linear.{hpp,cpp}  (sketch of the contract, not a placeholder -
// the parity/legacy details live in quant_dot_dispatch.cpp and vulkan_compute.cpp)
bool OpLinear(int gguf_type, const void* wBytes, size_t wBytesCount,
              const float* x, size_t n_in, float* y, size_t n_out) {
    const auto& r = ...;
    if (gguf_type == GGML_TYPE_Q4_K || gguf_type == GGML_TYPE_Q6_K) {
        bool gpu = QuantDot::DotBlocked(kind, wBytes, wBytesCount, x, n_in, y, n_out, cpuDot, q8, q8n);
        if (!gpu && !receipt_allows_fallback) return false;      // fail loud, no silent CPU
        return gpu;
    }
    if (gguf_type == GGML_TYPE_F16) return QuantDot::DotF16(...);
    FAIL_LOUD("unsupported quant type " << gguf_type);           // reject, never CPU-dequant
    return false;
}
```

Then route the GGUF matvec path of the forward executor through `OpLinear`, and
certify with the acceptance record above (parity at matvec boundary, first layer,
then full logits, then decode TPS — measured only after parity passes).

## Kept separate

- Attention RMS 0.676284: a correct quant-dot does not fix wrong attention; the
  first-divergent-tensor hunt stays its own P0.
- Zero-logit `bigdaddyg-productivity-local`: separate P0 correctness defect.
- The 16/32-bit reversal benchmark: still unmeasured this session.
