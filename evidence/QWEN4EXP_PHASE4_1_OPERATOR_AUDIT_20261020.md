# Qwen4Exp Phase 4.1 operator audit

Date: 2026-10-20
Branch: `local-30b-backend`

## Scope

This audit checks whether the proposed Phase 4.1 implementation can safely lower PLE and Hyperconnection into existing native Vulkan primitives without changing model semantics.

## Findings

| Operator | Required semantics | Native Vulkan implementation found | Decision |
|---|---|---|---|
| PLE | Per-layer n-gram embedding plus causal short convolution | No Qwen4Exp PLE shader or executor method. Generic embedding and matmul paths do not implement the n-gram window, causal state, or tensor layout. | Remains blocked |
| Hyperconnection | Four-stream residual mix with down/inject/norm/up tensors | No fused four-stream descriptor layout or executor method. Existing residual and norm operations are scalar generic primitives and do not establish stream ordering or projection geometry. | Remains blocked |
| QSA | Indexer projection, compressed-key cache, sparse top-k attention | No native implementation | Blocked |
| GDN | Gated Delta-Net recurrent state update | Existing SSM scan is a different state machine and tensor contract | Blocked |
| SparseMoE | Top-10-of-512 routing over MXFP4/IQ2 expert matrices | Existing MoE path does not cover Qwen4Exp layouts/types | Blocked |

## Evidence

The following source searches were performed:

```text
rg "PLE|ple_|short_conv|hc_|Hyperconnection" src/deep2 tools
Get-ChildItem src/deep2/shaders
```

The shader directory contains generic residual/norm/matmul and existing model-specific kernels, but no Qwen4Exp PLE or Hyperconnection shader. The executor has no `case OpKind::Ple` or `case OpKind::Hyperconnection` execution implementation; both are rejected during bind.

The canonical Qwen4Exp tensor inventory is available at:

- `evidence/qwen4exp_tensor_dump.tsv`
- `evidence/qwen4exp_full_digest_contract_20261020/full_model_receipt.json`

Representative Hyperconnection tensors are `blk.N.hc_attn_down.weight` `[10240,320]`, `hc_attn_inject.weight` `[10240,4]`, `hc_attn_norm.weight` `[10240]`, and `hc_attn_up.weight` `[320,10240]`. These dimensions require a dedicated layout and execution contract; they cannot be treated as a normal residual add.

## Certification decision

`BLOCKED_NATIVE_GRAPH` remains the only valid result for Qwen4Exp. The expected `unsupported_ops=3` result cannot be claimed because neither PLE nor Hyperconnection has a verified native implementation yet. Full-model execution remains `NOT_RUN` and certification remains `NOT_CERTIFIED`.

## Required next implementation

1. Define the PLE state/layout contract from an independent reference implementation.
2. Add a dedicated Vulkan PLE shader and descriptor layout, with causal-window parity tests.
3. Define Hyperconnection stream ordering and projection geometry from an independent reference.
4. Add a fused Vulkan Hyperconnection pipeline and full-layer parity tests.
5. Only after those tests pass, lower the graph nodes and rerun the two-shard full-model certifier.
