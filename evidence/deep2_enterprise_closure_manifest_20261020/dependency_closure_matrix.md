# Qwen4Exp dependency and interface closure matrix

This matrix is generated from the live `local-30b-backend` source and the
rerun receipts in this directory. It supersedes stale source-drop descriptions
that called the PLE or Hyperconnection shaders missing.

| Boundary | Source / artifact state | Executor state | Production evidence still required |
|---|---|---|---|
| QSA | No native shader, descriptor contract, or cache executor | **BLOCKED** in `Executor::Bind` | indexer projection, compressed-key cache, top-K causal selection, GPU parity |
| GDN | No native recurrent-state executor | **BLOCKED** in `Executor::Bind` | state allocation, gated update, convolution/cache continuity, GPU parity |
| PLE | GLSL and validated SPIR-V present; real pipeline object creates | **BLOCKED** in `Executor::Bind` and no `ExecuteToken` case | five descriptor bindings, state lifecycle, short-sequence handling, dispatch and parity |
| Hyperconnection | GLSL and validated SPIR-V present; real pipeline object creates | **BLOCKED** in `Executor::Bind` and no `ExecuteToken` case | four-stream tensor descriptors, fused synchronization, dispatch and parity |
| SparseMoE | No native top-K/grouped-GEMM executor | **BLOCKED** in `Executor::Bind` | routing, expert residency, MXFP4/IQ2 grouped GEMM, GPU parity |
| GR reference | Supplied CPU arithmetic contract preserved under `evidence/qwen4exp_gr_source_drop_20261020` | **REFERENCE_ONLY** | production Vulkan lowering, independent parity, graph integration |

## State boundary

The graph can be reverse-engineered (`1224` tensors, geometry PASS), and PLE /
Hyperconnection pipeline objects can be created on the R9700. No inference
command is submitted: the probe receipt is `DISPATCHES=0 EXECUTION=NOT_RUN`.

The execution blocker is in
[`runtime_graph_executor.cpp`](../../src/deep2/runtime_graph_executor.cpp):
`Executor::Bind` marks all five Qwen4Exp operator kinds unbound, and the
`ExecuteToken` switch has no descriptor allocation, tensor upload, command
recording, or dispatch implementation for them. Removing the bind refusal
without implementing those cases would violate the fail-closed policy.

## Required enterprise closure order

1. Implement and bind one operator with real GPU-resident descriptors and
   explicit state ownership.
2. Add independent per-operator full-logit parity and failure-path receipts.
3. Repeat for every QSA, GDN, PLE, Hyperconnection, and SparseMoE path.
4. Run complete Qwen4Exp forward and autoregressive generation with zero CPU
   fallback, then preserve the Llama regression receipt.

No operator-level or pipeline-construction PASS changes
`QWEN4EXP_FULL_MODEL=BLOCKED` in the closure manifest.
