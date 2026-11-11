# Qwen4Exp operator implementation receipt

Date: 2026-10-20  
Scope: operator contracts and isolated Vulkan probes only  
Full-model status: **NOT CERTIFIED**

## Model facts recovered from both GGUF shards

- Architecture: `qwen4exp`
- Tensors: `1224` across `2` shards
- Blocks: `48`
- Hidden size: `2560`
- QSA: `4` index heads, key width `128`, compression ratio `4`, top-k `2048`
- GDN: `16` key heads, `48` value heads, head width `128`, causal kernel `4`
- PLE: channels `10240`, kernel `4`, dilation `3`, state length `9`
- Hyperconnection: `4` streams, low rank `320`, stream width `2560`
- Sparse MoE: `512` experts, intermediate width `640`, top-k `10`
- Expert formats: routed gate/up `IQ2_S`; routed down `MXFP4`

The geometry came from `deep2_reverse_engineer.exe --manifest` over both real
shard manifests. It reported `TENSORS=1224 GEOMETRY=PASS`.

## Implemented slices

| Operator | Implementation | Evidence | Boundary |
|---|---|---|---|
| GDN | Exact CPU recurrence and 9-binding Vulkan shader | `GDN_DISPATCHES=1`, execution PASS, output/state parity PASS on AMD Radeon AI PRO R9700 | Isolated operator; not wired into `ExecuteToken` |
| PLE | Dilated causal reference with 9-sample channel history and corrected shader | Contract harness PASS; SPIR-V validation PASS | No model tensor upload/state owner in production graph |
| Hyperconnection | Four-stream sigmoid gate mix, injection combine, grouped RMS normalization | Contract harness PASS; SPIR-V validation PASS | No production graph dispatch or BF16-weight binding |
| QSA | Compressed-page score, causal visibility, deterministic top-k block selection and token expansion | Contract harness PASS; SPIR-V validation PASS | No production KV/indexer cache owner or attention output dispatch |
| Sparse MoE | Deterministic 512-way router and top-10 normalized weights | Contract harness PASS; router SPIR-V validation PASS | IQ2_S/MXFP4 expert GEMM/dequantization is explicitly rejected |

The contract harness output was:

```text
PLE_GEOMETRY=PASS state_length=9 state_elements=72
HC_GEOMETRY=PASS width=32 gate_mix=PASS combine_norm=PASS
QSA_GEOMETRY=PASS heads=4 key_dim=128 compression=4 top_k=2048 visible=4/2 selection=PASS
SPARSE_MOE_ROUTE=PASS experts=512 top_k=10 normalized=PASS
SPARSE_MOE_EXPERT_EXECUTION=FAIL_CLOSED_UNDEQUANTIZED
QWEN4EXP_OPERATOR_HARNESS=PASS
QWEN4EXP_FULL_MODEL=NOT_CERTIFIED
```

The GDN Vulkan probe output was:

```text
GDN_DEVICE=AMD Radeon AI PRO R9700
GDN_PIPELINE=PASS
GDN_DISPATCHES=1 GDN_EXECUTION=PASS
GDN_OUTPUT_PARITY=PASS max_abs=1.86265e-08 cosine=1
GDN_STATE_PARITY=PASS max_abs=1.16415e-10 cosine=1
GDN_INDEPENDENT_PARITY=PASS
QWEN4EXP_FULL_MODEL=NOT_CERTIFIED
```

## Concrete remaining blockers for a 100B-class full model

1. `src/deep2/modelgenie/universal_gguf.cpp:799-835` still emits one
   fail-closed graph blocker per Qwen4Exp primitive instead of a complete
   48-block execution plan. This is intentional until tensor ownership and
   state lifetimes are connected.
2. `src/deep2/runtime_graph_executor.cpp:768-779` rejects QSA, GDN, PLE,
   Hyperconnection, and SparseMoE during `Bind`; `ExecuteToken` begins at
   `src/deep2/runtime_graph_executor.cpp:3461` and has no production cases for
   these Qwen4Exp nodes.
3. The current GDN probe uses synthetic F32 staging buffers. It does not yet
   bind `attn_qkv`, `attn_gate`, `ssm_alpha`, `ssm_beta`, `ssm_a`, or
   `ssm_dt.bias` from the two GGUF shards.
4. PLE requires ownership of the 10240-wide n-gram table and per-request
   dilated history. The shader contract exists, but the production graph does
   not allocate or publish this state.
5. QSA requires a compressed-key page table, indexer projections, causal
   selection, and the full sparse-attention value path. The score/selection
   reference is not a substitute for the production KV cache.
6. Hyperconnection requires the four stream down/inject/up projections and
   residual ordering around both attention and MoE blocks. The current shader
   is a combine contract, not the complete low-rank projection path.
7. Routed expert execution remains blocked until `IQ2_S` gate/up and `MXFP4`
   down tensors have an independently validated dequantizer and grouped GEMM
   dispatch. The code rejects those formats rather than substituting F32.
8. Full-model certification additionally requires both shards, all `48`
   blocks, independent logits, autoregressive state continuity, zero CPU
   fallback, and a sustained generation receipt. No operator-level PASS above
   satisfies that gate.

## 100B acceptance boundary

The residency system may reserve and stream a model larger than physical VRAM,
but addressability is not execution. A 100B-class model is accepted only after
the complete two-shard graph executes with finite logits and independent
autoregressive parity. This receipt therefore records substantial operator
progress while keeping `QWEN4EXP_FULL_MODEL=NOT_CERTIFIED` and refusing to
claim 100B inference readiness.
