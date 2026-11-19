# Qwen4Exp graph binding audit

## Result

The first production integration boundary is the universal GGUF graph builder, not the Vulkan GDN implementation.

`src/deep2/modelgenie/universal_gguf.cpp` currently emits `Universal::Op::Gdn` as an unsupported graph blocker for `ArchKind::Qwen4Exp`, with the detail `gated delta-net recurrent state executor is not bound`. The runtime executor already contains `Executor::OpGdn` and a `VulkanCompute::DispatchGdn` call, but binding fails before `ExecuteToken` can reach that operation when the Qwen4Exp graph also contains its other unimplemented architectural nodes.

## Verification

- Source SHA: `e3e0531ed7d361799c746e71b9c0ffd2b34e7dc4`
- Candidate artifact: `F:\rawrxd\models\bigdaddygnative_latest.gguf`
- Ollama model source reported by `ollama show bigdaddygnative:latest --modelfile`: `F:\OllamaModels\blobs\sha256-d39f8ddb7e54a04ea9dd83a5b1d01e4c88c12e4e2eedba85381a7ef1e341929a`
- Existing production GDN entry point: `src/deep2/runtime_graph_executor.cpp`, `Executor::OpGdn`
- Existing GPU entry point: `VulkanCompute::DispatchGdn`
- Current graph behavior: Qwen4Exp architecture emits GDN/QSA/PLE/hyperconnection/sparse-MoE blockers and fails closed during binding.

## Disposition

No source change was made because removing only the GDN blocker would allow binding to proceed into other unsupported Qwen4Exp operators and would not create a valid production graph. A real fix requires the model's complete tensor-role mapping and implementation of the preceding architectural nodes or an explicitly supported partial graph contract.

```ini
GDN_GPU_OPERATOR=PASS
GDN_EXECUTOR_ENTRY=EXISTS_BUT_UNREACHABLE_FOR_QWEN4EXP_BIND
QWEN4EXP_GRAPH_BINDING=BLOCKED
FULL_MODEL_INFERENCE=NOT_RUN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
