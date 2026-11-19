# Deep2 + IDE acceptance gates (fail-closed)

Source baseline: 5a8e7569598a6dc3bbc1ea2a8ce7e0a811061924.
This is a **source audit**, not a runtime certification. Every gate requires
receipts from the same source commit and exact executable SHA. No cross-SHA PASS.

| Gate | Source boundary | Acceptance evidence |
| --- | --- | --- |
| LTT single/multi-token | tools/ltt_tensor_invoke.cpp | Nonempty finite logits for every token, expected token count, exit 0 |
| LTT numerical correctness | src/deep2/runtime_graph_executor.hpp | Exact-token same-model llama.cpp reference, full logits per position, documented tolerances |
| Quantization parity | src/deep2/runtime_graph_executor.hpp | Q4_K/Q8_K and other advertised formats checked against CPU reference on same tensors |
| Attention/FFN parity | src/deep2/runtime_graph_executor.hpp | First divergent operator isolated; all tested positions meet tolerance |
| Architecture coverage | src/deep2/runtime_graph_executor.hpp | Explicit per-model supported/unsupported matrix, unsupported fails closed |
| Cancellation | ExecutionContext.cancel | Before, during and after dispatch; no partial success or leaked reservations |
| Memory admission | ExecutionContext.memory_admission | Concurrent budget contention and atomic reservation/release receipts |
| Request isolation | ExecutionContext | Parallel distinct prompts and cancellation; no cross-request KV or logits contamination |
| GPU lifecycle | Vulkan compute runtime | Repeated bind/execute/destroy; stable allocation and device memory after teardown |
| Dual GPU | SetBlockVulkanDevice | Per-device work receipts, reference parity, no hidden CPU fallback |
| Model resolution | Universal GGUF ingest / blob resolver | Missing/truncated blobs fail before execution; exact artifact SHA |
| Embedded IDE inference | src/agentic/Deep2Backend.cpp | IDE chat invokes native in-process executor with HTTP server stopped |
| Backend selection | src/agentic/InferenceBackend.h | Explicit local-only routing; no silent backend/model switching |
| Streaming / chat | src/agentic/InferenceBackend.h | Correct token order, stop semantics, cancellation and UI completion |
| Tool calling | src/agentic/InferenceBackend.h | Real tool call parsed, authorized, executed, and result returned to model |
| FIM / ghost text | src/agentic/InferenceBackend.h | Real document cursor context, generated edit, accept/reject and undo |
| Terminal / Output / Problems | IDE UI | Real command, diagnostics, navigation and cancellation verified in GUI |
| Editor / project / Git | IDE UI | Open-edit-save-reopen, project indexing, diff and safe commit workflow |
| Debugger / engine | IDE + Sunshine integration | Launch, breakpoint, step, inspect, stop and actual engine build/run |
| Agentic coding | Agent orchestrator | Real read/edit/build/test/retry loop with bounded permissions |
| Performance | Inference backends | Model-specific prefill/decode TPS, latency, memory and concurrency |
| Release | Packaging/CI | Clean machine dependencies, smoke, rollback and SHA-linked receipts |

## Observed source gaps

1. `Deep2Backend::DefaultConfig()` selects HTTP port 11436 and `Initialize()` calls `CheckHealth()`. This is not an in-process IDE backend.
2. `ltt_tensor_invoke.cpp` originally printed `LTT_TOKEN_PASS` for nonfinite logits and indexed empty logits; corrected in this audit branch.
3. The LTT harness's `synchronization_ready` and `memory_admission` callbacks always return true. Its successful execution does not establish contention handling.
4. `--cancel-before` tests only pre-dispatch cancellation; no mid-dispatch cancellation receipt exists in the inspected harness.
5. Full-logit capture stores a little-endian uint64 count followed by FP32 logits for each token. A comparator must parse those headers.
6. The inspected source alone does not prove GUI, Sunshine, agentic, or release end-to-end behavior.

## Promotion rule

Keep `PROMOTE=0 CERTIFIED=0 RELEASE=HELD` until all release-required
gates pass with executable SHA, source SHA, model artifact SHA, exact commands,
exit codes, and durable receipts. Distinguish unsupported model architectures
from defects in architectures advertised as supported.
