# Qwen4Exp operator contract rerun

Date: 2026-10-20
Branch: `local-30b-backend`

This receipt records the first native graph-contract rerun after promoting the
five Qwen4Exp architecture primitives to explicit graph and executor kinds.
The change is structural plumbing only; it does not claim that an executor
exists where no Vulkan implementation has been linked.

## Changes exercised

- `QSA` — indexer projection, compressed-key cache, top-k sparse attention
- `GDN` — gated delta-net recurrent state update
- `PLE` — per-layer n-gram embedding and short convolution
- `Hyperconnection` — four-stream residual mix/down/up
- `SparseMoE` — top-k expert routing and grouped MXFP4/IQ2 GEMM

Each primitive now retains its identity in `Universal::Op`, lowers to a named
`RuntimeGraph::OpKind`, and is rejected by `Executor::Bind` as an unbound
native backend. No primitive is aliased to generic attention, Mamba, or MoE.

## Build evidence

```text
cmake --build F:\rawrxd\build --config Release --target deep2_gpu_certify deep2_shard_probe -- /m:1 /v:minimal
exit=0

cmake --build F:\rawrxd\build --config Release --target deep2_engine_lib -- /m:1 /v:minimal
exit=0
```

## Full-model certifier rerun

Command used the canonical first Qwen4Exp shard with the existing two-shard
loader. Digest was deferred for this contract pass so the result isolates graph
admission; the full digest remains a separate integrity prerequisite.

```text
DEEP2_INGEST_SKIP_DIGEST=1
deep2_gpu_certify.exe --model Qwen3.8-Flash-Next-AD-IQ1_M-M64-00001-of-00002.gguf --tokens 248044 --dump qwen4exp_contract_qsa_gdn_ple_hc_moe_20261020
exit=1
CERT_STATUS=BLOCKED_NATIVE_GRAPH
CERTIFICATION_STATUS=NOT_CERTIFIED
```

The certifier reopened the complete model inventory:

```text
architecture=qwen4exp
shard_count=2
mapped_bytes=84930920928
tensor_count=1224
resolved_tensors=1224
unmapped_tensors=0
unsupported_ops=5
execution_status=NOT_RUN
gpu_calls=0
cpu_calls=0
```

The exact fail-closed reason is:

```text
QSA: indexer sparse attention and compressed-key cache executor is not bound;
GDN: gated delta-net recurrent state executor is not bound;
PLE: per-layer n-gram embedding and short-convolution executor is not bound;
HYPERCONNECTION: four-stream mix/down/up residual executor is not bound;
SPARSE_MOE: top-10-of-512 MXFP4/IQ2 expert grouped GEMM executor is not bound
```

Receipt: `evidence/qwen4exp_contract_qsa_gdn_ple_hc_moe_20261020/full_model_receipt.json`.

## Certification disposition

`NOT_RUN != PASS`. Qwen4Exp remains `NOT_CERTIFIED`. The graph now carries
architecture-specific operator identities, but full-model certification still
requires real GPU executors, complete forward execution, independent reference
parity, autoregressive generation, and sustained-runtime evidence for all five
primitives.

The Llama 3.2 Q2_K `FULL_MODEL_CERTIFIED` receipt remains valid only for that
model and is not altered by this Qwen4Exp result.
