# Qwen4Exp concrete blocker audit

This register is deliberately fail-closed. It records what is present in the
repository, what is actually executed, and the evidence required to remove
each blocker. No row is a model certification.

| ID | Severity | Status | Boundary | Evidence | Closure |
|---|---|---|---|---|---|
| QWEN-B01 | CRITICAL | BLOCKED | Executor::Bind admission | src/deep2/runtime_graph_executor.cpp:768-772 sets qwen4exp_unbound for QSA, GDN, PLE, Hyperconnection, and SparseMoE. The preserved full-model receipt reports unsupported_ops=5. | Bind only after all five graph nodes have real lowerings. |
| QWEN-B02 | CRITICAL | BLOCKED | Executor::ExecuteToken lowering | The switch beginning at src/deep2/runtime_graph_executor.cpp:3461 has no Qwen4Exp cases; unsupported operations fall through to unhandled op. | Add tensor handles, descriptors, command recording, completion, and state publication for every Qwen4Exp OpKind. |
| QWEN-B03 | CRITICAL | NOT_RUN | Physical command submission | pipeline_probe_rerun.txt records PLE_PIPELINE=PASS HC_PIPELINE=PASS GDN_PIPELINE=PASS, but also DISPATCHES=0 EXECUTION=NOT_RUN. | Submit real model buffers through the production executor, fence them, and record nonzero dispatches plus numerical output. |
| QWEN-B04 | CRITICAL | BLOCKED | QSA lowering and KV cache | operator_contract.json records native_execution.QSA=false; no QSA shader/pipeline artifact exists in this closure set. | Implement indexer projections, compressed-key scoring, causal top-K selection, rotary positions, KV updates, and long-context continuity. |
| QWEN-B05 | CRITICAL | BLOCKED | SparseMoE lowering and residency | operator_contract.json records native_execution.SparseMoE=false; the dependency matrix records no native grouped-GEMM executor. | Implement deterministic top-10-of-512 routing, shared/routed scaling, MXFP4/IQ2 grouped GEMM, residency, and GPU parity. |
| QWEN-B06 | HIGH | COMPONENT_DISPATCH_PASS | GDN production dispatch | gdn_component_probe.txt records one real R9700 dispatch, finite output, independent output/state parity, and exit 0. This is isolated and does not execute through ExecuteToken. | Bind the verified GDN descriptors and state lifecycle into the Qwen4Exp Executor graph, then repeat parity through ExecuteToken. |
| QWEN-B07 | HIGH | NOT_RUN | PLE and Hyperconnection dispatch | Their pipelines are created successfully, but the same probe reports DISPATCHES=0; no ExecuteToken cases exist. | Allocate real buffers, dispatch, compare to independent references, and wire state/lifecycle into the executor. |
| QWEN-B08 | HIGH | REFERENCE_ONLY | Gated Residual production path | QWEN4EXP_FAIL_CLOSED_INVENTORY.md says the source drop is isolated CPU arithmetic-contract testing only. | Implement GR read/write/combine in production GPU execution and prove independent parity with zero CPU fallback. |
| QWEN-B09 | CRITICAL | NOT_RUN | Full-model independent parity | The preserved receipt has execution_status=NOT_RUN, gpu_calls=0, and cpu_calls=0. | Execute all layers, experts, and recurrent/cache paths for the complete two-shard model and compare full logits/checkpoints to an independent oracle. |
| QWEN-B10 | CRITICAL | BLOCKED | Autoregressive generation and certification | The receipt is BLOCKED_NATIVE_GRAPH with certification_status=NOT_CERTIFIED. | After B01-B09 close, run deterministic multi-token generation, cache continuity, repeated output, and issue a full-model certificate only on reproducible PASS evidence. |
| QWEN-B11 | HIGH | RECONCILIATION_REQUIRED | Tensor-role ownership | native_contract_rerun.md reports GDN/PLE/HC counts 252/7/387; canonical operator_contract.json records 216/6/384. | Reconcile the classifier against the canonical 1,224-descriptor manifest and make one ownership map drive binding. |
| QWEN-B12 | CRITICAL | BLOCKED | Shard manifest parseability | Both qwen4exp_manifest_shard*.json files contain unescaped Windows paths; PowerShell ConvertFrom-Json fails with Bad JSON escape sequence: \O. Receipt: shard_manifest_json_validation.txt. | Regenerate or normalize both manifests with valid JSON escaping, validate independently, then rerun ownership reconciliation. |

## Current boundary

The immediate execution boundary is B01 + B02. Removing the fail-closed
check without implementing the missing ExecuteToken cases would turn a
proven blocker into silent graph corruption, so it is intentionally not
removed.

## Current certification

    QWEN4EXP_FULL_MODEL=BLOCKED
    FULL_MODEL_EXECUTION=NOT_RUN
    CERTIFICATION=NOT_CERTIFIED

