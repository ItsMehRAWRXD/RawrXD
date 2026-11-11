# Qwen4Exp live blocker audit — 2026-10-20

This receipt records the current source and hardware boundary after a real build,
three contract tests, the operator GPU probe, and a physical Vulkan enumeration.
It is an audit receipt; it does not certify Qwen4Exp.

## Evidence run

- `deep2_engine_lib` Release build: PASS.
- `deep2_enterprise_manifest` Release build: PASS.
- CTest: `deep2_gdn_reference_contract`, `deep2_qwen4exp_operator_contract`, and `deep2_qwen4exp_operator_gpu_probe`: 3/3 PASS.
- Operator probe: PLE, Hyperconnection, QSA score, and MoE router GPU probes PASS on the R9700; expert IQ2/MXFP4 GEMM remains `FAIL_CLOSED_UNDEQUANTIZED`.
- Vulkan enumeration: 5 physical devices; R9700 and integrated AMD are present, RX 7800 XT is absent.
- Windows PnP: RX 7800 XT reports `CM_PROB_FAILED_ADD` (Code 31). No reset was attempted by this audit.

## Source-to-runtime boundary

`universal_gguf.cpp::BuildGraph` emits five architecture-specific nodes with no
operands: QSA, GDN, PLE, Hyperconnection, and SparseMoE. `runtime_graph_executor.cpp::Bind`
maps those nodes and rejects them fail-closed. `Executor::ExecuteToken` has no
production lowering cases for those five kinds. Therefore the first executable
Qwen4Exp graph is not constructed and full-model execution remains blocked.

## Blocker disposition

| Boundary | Current disposition | Concrete reason |
|---|---|---|
| Executor admission | BLOCKED | Bind rejects all five Qwen4Exp operator kinds. |
| ExecuteToken lowering | BLOCKED | No descriptor/state/dispatch cases for those kinds. |
| Physical command submission | NOT_RUN | No Qwen graph reaches submission. |
| QSA | COMPONENT_PASS_ONLY | Isolated score shader passes; graph integration absent. |
| GDN | COMPONENT_PASS_ONLY | Reference/isolated probe passes; recurrent state is not in ExecuteToken. |
| PLE | COMPONENT_PASS_ONLY | Isolated shader passes; token/history state is not in ExecuteToken. |
| Hyperconnection | COMPONENT_PASS_ONLY | Isolated combine shader passes; four-stream graph state is absent. |
| SparseMoE | BLOCKED | Router probe passes; IQ2_S/MXFP4 expert GEMM is explicitly fail-closed. |
| Gated Residual | REFERENCE_ONLY | CPU arithmetic contract exists; production dispatch/full-graph proof absent. |
| Full-model parity | NOT_RUN | No complete Qwen forward reaches logits. |
| RX 7800 XT admission | BLOCKED | Vulkan absent; Windows Code 31 (`CM_PROB_FAILED_ADD`). |

## Certification

```ini
QWEN4EXP_FULL_MODEL_EXECUTION=NOT_RUN
QWEN4EXP_CERTIFICATION=NOT_CERTIFIED
OPEN_BLOCKERS=11
```

A future closure must construct the complete graph from actual tensor handles,
wire each operator's persistent state and residency identity, submit real GPU
work, and pass independent full-logit plus autoregressive parity. Component
receipts and shader compilation cannot close this boundary.
