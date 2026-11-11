# Deep2 Qwen4Exp reverse-engineered operator contract

Tensors: 1224

| Operator | Total tensors | Primary block tensors | Auxiliary/global tensors | Contract geometry | Native executable |
|---|---:|---:|---:|---|---|
| QSA | 48 | 48 | 0 | indexer tensors, top-k compressed-key attention | NO |
| GDN | 252 | 216 | 36 | selective gated delta state; ssm_a=[48] | NO |
| PLE | 7 | 6 | 1 | causal conv=[4,10240] | NO |
| HYPERCONNECTION | 387 | 384 | 3 | down=[10240,320], inject=[10240,4], up=[320,10240] | NO |
| SPARSE_MOE | 144 | 144 | 0 | gate=[2560,640,512], 512 experts | NO |

Ownership reconciliation: GDN 216+36, PLE 6+1, HYPERCONNECTION 384+3; tensor names remain unique across both shards.

Geometry checks: PASS
Certification: NOT_CERTIFIED (native Vulkan lowering and parity are still required)

## The blocker ledger

An operator is executable only when a lowering artifact exists AND that artifact has been executed on a device and reproduced a reference. A compiled shader is not an executable operator, and an operator that has never run is not an executed one.

| Operator | Requirement | Covered by existing primitives | Missing | Artifact | Device execution | Next executable slice |
|---|---|---|---|---|---|---|
| QSA | indexer q/k projections and norms, a compressed-key cache, and a sparse attention over the top-k compressed keys | OP_GEMV_F32 (the indexer projections), OP_RMSNORM (the indexer norms) | the indexer scoring and its top-k selection, and the compressed-key attention itself | `qsa_score.comp` | PASS | the compressed-key attention itself, which the scoring does not cover |
| GDN | a gated delta-net recurrent state: a state matrix, a gated decay, and a per-step state update | OP_GEMV_F32 (the projections around the state) | the recurrent state update and the gated normalisation | `gdn.comp` | NOT RUN | the selective state update, which is a scan and not a projection |
| PLE | a per-layer n-gram embedding and a causal depthwise short convolution, with the window carried between dispatches | OP_RMSNORM (the norms around it) | the depthwise short convolution, which is not a projection | `ple.comp` | PASS | the n-gram embedding and the key and value projections around it |
| HYPERCONNECTION | a four-stream mix: a down projection, a per-stream silu, an up projection and a sigmoid-gated mean; and a combine of the residual with the block output, grouped RMS normalised | OP_GEMV_F32 (the down and up projections), OP_RESIDUAL (the combine addition), and the grouped RMSNorm (which is lowered and executed) | the per-stream silu mean and the sigmoid-gated mean | `hc_combine.comp` | PASS | the mix path: the down projection, the per-stream silu, the up projection and the gated mean |
| SPARSE_MOE | a router over the experts, a top-k selection, and a grouped expert projection with the results accumulated back into the hidden state | OP_SWIGLU (the expert activation), and the packed GEMV for one expert's projection | the top-k over the router logits, the grouped expert dispatch, and the MXFP4 and IQ2 formats the experts are stored in | `moe_router.comp` | PASS | the top-k over the router logits, which the router itself does not do, and then the grouped expert dispatch |

Executed lowerings: 4 of 5
Ledger: FAIL
Certification: NOT_CERTIFIED (no operator is bound into the runtime graph, and the model is still fail-closed)

## The lowered primitives

| Primitive | Purpose | Artifact | Device execution |
|---|---|---|---|
| grouped RMSNorm | the per-stream normalisation the hyperconnection mix needs, and the normalisation the combine path performs | `grouped_rmsnorm.comp` | PASS |
| hyperconnection combine | the residual combine of the block output with the injection, and the grouped normalisation that follows it | `hc_combine.comp` | PASS |
| PLE depthwise short convolution | the causal depthwise convolution, with the window carried between dispatches | `ple.comp` | PASS |
| MoE router | the hidden state turned into one logit per expert, which is the first part of the sparse MoE operator and does not depend on the format the experts are stored in | `moe_router.comp` | PASS |
| QSA indexer scoring | the indexer scoring against the compressed-key cache, through a page table and over the visible compressed keys only | `qsa_score.comp` | PASS |

Executed primitives: 5 of 5
