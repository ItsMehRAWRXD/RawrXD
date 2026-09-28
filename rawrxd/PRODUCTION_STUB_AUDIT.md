# RawrXD Production Stub / Backend Compatibility Audit

This audit targets the active production and inference surfaces wired by the main CMake tree, with emphasis on throughput violations, backend compatibility gaps, and any stubbed or simulated implementation paths that are being treated as real production authority.

## Scope audited

- [rawrxd/CMakeLists.txt](rawrxd/CMakeLists.txt)
- [CMakeLists.txt](CMakeLists.txt)
- representative runtime sources under [rawrxd/src](rawrxd/src)
- Deep2 and model runtime sources under [rawrxd/src/deep2](rawrxd/src/deep2)

## Executive summary

The production targets are not fully cleanly wired to the actual local backend. Several files included in core product targets are clear stub or mock implementations, and some runtime targets still link the headless stub entry path while the real Deep2 engine exists as a separate canonical runtime.

This is a compatibility and authority issue, not just a cleanliness issue.

## Major findings

### 1) Core `rawrxd` target includes stubbed agent output files

The active CLI target in [rawrxd/CMakeLists.txt](rawrxd/CMakeLists.txt#L245-L354) directly includes the following files:

- [rawrxd/src/agent_history.cpp](rawrxd/src/agent_history.cpp)
- [rawrxd/src/agent_policy.cpp](rawrxd/src/agent_policy.cpp)
- [rawrxd/src/agent_explainability.cpp](rawrxd/src/agent_explainability.cpp)

These files are not runtime implementations; they are auto-generated stub placeholders.

Evidence:

- [rawrxd/src/agent_history.cpp](rawrxd/src/agent_history.cpp#L1-L2) contains `// Auto-generated stub`
- [rawrxd/src/agent_policy.cpp](rawrxd/src/agent_policy.cpp#L1-L2) contains `// Auto-generated stub`
- [rawrxd/src/agent_explainability.cpp](rawrxd/src/agent_explainability.cpp#L1-L2) contains `// Auto-generated stub`

This makes the product target look active while still carrying a stubbed agent surface. That is a direct simulation/integration violation.

### 2) `rawrxd` target still carries a mocked Vulkan GEMM dispatcher

The main rawrxd target also includes [rawrxd/src/backend/VulkanGemmDispatcher.cpp](rawrxd/src/backend/VulkanGemmDispatcher.cpp), which contains a mock success path:

- [rawrxd/src/backend/VulkanGemmDispatcher.cpp](rawrxd/src/backend/VulkanGemmDispatcher.cpp#L175-L187) explicitly says `// Mock mode: simulate success`

This is a compatibility and backend-authority problem: the code path is marked as a mock and still appears as a real backend implementation in production. For model streaming and GPU path compliance, that is not acceptable in a canonical production target.

### 3) Standalone inference target is wired to an actual stub entry point

The inference engine source list in [rawrxd/CMakeLists.txt](rawrxd/CMakeLists.txt#L4230-L4409) includes:

- [rawrxd/src/inference/inference_standalone_main.cpp](rawrxd/src/inference/inference_standalone_main.cpp)

This file is a direct stub:

- [rawrxd/src/inference/inference_standalone_main.cpp](rawrxd/src/inference/inference_standalone_main.cpp#L1-L2) contains `// STUB: src/inference/inference_standalone_main.cpp`

The same is true for the executable target definition later in the file:

- [rawrxd/CMakeLists.txt](rawrxd/CMakeLists.txt#L4670-L4708)

That means the standalone inference target is still configured against a file that is intentionally stubbed and not a real model loader/streamer entry.

### 4) Bounded agent loop is stubbed but still part of the agentic stack

The agent path includes [rawrxd/src/agentic/BoundedAgentLoop.cpp](rawrxd/src/agentic/BoundedAgentLoop.cpp), which contains:

- [rawrxd/src/agentic/BoundedAgentLoop.cpp](rawrxd/src/agentic/BoundedAgentLoop.cpp#L1-L18) with `// Stub: no real model invocation yet`

This file is also present in the main target list in [rawrxd/CMakeLists.txt](rawrxd/CMakeLists.txt#L2304-L2305) and again in the inference engine source set at [rawrxd/CMakeLists.txt](rawrxd/CMakeLists.txt#L4540-L4543).

This is a strong sign that the agentic/autonomous path is still being assembled against no-op logic, which directly violates the expected end-to-end authority path.

### 5) The real authority path exists, but the stubbed path is still being compiled in the same target set

The real canonical Deep2 runtime is present in the same CMake tree and is the actual production path to preserve:

- [rawrxd/src/deep2/Deep2Engine.cpp](rawrxd/src/deep2/Deep2Engine.cpp)
- [rawrxd/src/deep2/Tokenizer.cpp](rawrxd/src/deep2/Tokenizer.cpp)
- [rawrxd/src/deep2/Sampler.cpp](rawrxd/src/deep2/Sampler.cpp)
- [rawrxd/src/deep2/trailforge/TrailForge.cpp](rawrxd/src/deep2/trailforge/TrailForge.cpp)

Those are the files that need to remain authoritative. The problem is not that they are absent; the issue is that the build still includes mock/stub paths in the same active production and inference surfaces.

## Production-risk statement

This means the build tree can look authoritative while silently composing:

- stubbed agent outputs,
- mock Vulkan backend semantics,
- no-op autonomous loops,
- standalone inference entry points that do not actually load/stream models.

That is exactly the kind of backend compatibility and TPS drift that eventually looks like real local inference while being a simulated scaffolding layer.

## Corrective direction

The fix is not to delete the whole IDE scaffold. The fix is to re-establish the authority chain:

1. Keep the real Deep2 runtime and GGUF model path as the only canonical production authority.
2. Remove mock/stub files from active `rawrxd` and `InferenceEngine` target lists.
3. Keep gate/benchmark/cert/test executables separate from the live production runtime.
4. Treat the real runtime path as:
   - load GGUF/model metadata,
   - resolve architecture and tokens,
   - stream generation,
   - emit decode outputs,
   - attach telemetry and authority checks,
   - and never silently fall back to simulation.
5. Keep each backend or scheduler under a pass/fail gate rather than letting a mock mode silently succeed.

## Controlled implementation note

The current tree already contains the real authority path and has also accumulated a large bundle of scaffold/stub files. The safest production contract is:

- keep Deep2 runtime sources active,
- isolate mock/simulated code behind test-only or gate-only targets,
- never include files with `// Auto-generated stub`, `// STUB:`, or `Mock mode: simulate success` in the live product builds.

## Audit verdict

The project is not yet cleanly production-authoritative. It has the correct real model/runtime files, but the active build surfaces still carry stubbed and mocked implementation files in core targets. That is the compatibility and TPS-violation risk that needs to be resolved before treating the stack as a real local high-end inference engine.
