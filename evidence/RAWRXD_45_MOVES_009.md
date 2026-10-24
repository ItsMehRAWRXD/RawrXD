# RAWRXD Batch 009 — 45-gate end-to-end audit, no-deps, dual GPU

Status terms: **fixed** = source committed; **configured** = workflow source committed; **pending** = no execution receipt. No 100% certification.

## 01–15: build, dependency and CI closure
01 [fixed] total GPU resident-byte cap in REAP bridge
02 [fixed] fail-closed GPU eviction without idle callback
03 [fixed] device residency byte accounting
04 [fixed] cap overflow-safe comparison
05 [fixed] projection bridge smoke asserts resident bytes
06 [fixed] projection bridge smoke asserts unsafe eviction rejection
07 [fixed] projection bridge smoke tests cap rejection
08 [fixed] projection bridge smoke tests idle-gated forget
09 [fixed] source no-deps inventory script
10 [configured] JSON no-deps audit artifact in CI
11 [configured] native IDE x64 GitHub Actions build
12 [pending] observe native IDE build success
13 [pending] observe actual executable launch
14 [pending] eliminate CLI external JSON link
15 [pending] certify native executable dependency closure

## 16–30: Deep2 ROM / two AMD GPUs
16 [configured] self-hosted runner R9700 device check
17 [configured] self-hosted runner RX7800XT device check
18 [configured] Vulkan device enumeration
19 [configured] MSVC smoke tests on self-hosted GPU PC
20 [pending] verify runner online
21 [pending] compile production Vulkan kernels
22 [pending] GPU0 numerical output parity
23 [pending] GPU1 numerical output parity
24 [pending] concurrent dual-GPU dispatch
25 [pending] GPU buffer fence lifetime tests
26 [pending] historical native 1.5-bit codec integration
27 [pending] full GGUF multi-shard MoE correctness
28 [pending] multi-token generation
29 [pending] per-token storage/H2D bandwidth evidence
30 [pending] sustained 150 TPS benchmark

## 31–45: complete IDE parity and user workflows
31 [source] native Win32 editor
32 [source] native GhostText
33 [source] native PowerShell
34 [source] LSP framing
35 [pending] LSP process/initialize/diagnostics/completion
36 [pending] physical GhostText accept/dismiss
37 [pending] PowerShell output/cancellation
38 [pending] debugger breakpoint and expressions
39 [pending] browser rendering and navigation
40 [pending] agent edit→compile→test
41 [pending] failed test rollback
42 [pending] snapshot restore after restart
43 [pending] extension compatibility
44 [pending] reproducible top-25 AI IDE comparison
45 [pending] 100% release certification

## Critical integration gaps found
- Existing REAP bridge reads packed slices into CPU memory; not proven zero-copy or native 1.5-bit streaming.
- ProjectionBridge now caps *reported* device residency and rejects unsafe eviction, but the upload callback retains ownership; on upload-success/budget-failure it must free any just-created allocation itself. No production GPU allocator is wired.
- `RawrXD-CLI-V2` links `nlohmann_json::nlohmann_json` in root CMake; requires actual dependency removal or explicit classification before claiming no-deps.
- Native LSP framing is not a complete LSP client.
- Windows-hosted GitHub Actions can compile, but only a labeled self-hosted machine can prove the specific R9700 + RX7800XT behavior.
- The GitHub connector currently does not expose a generic Actions dispatch method; writing workflow YAML alone is not a completed test. Check Actions UI for actual run state.
- GitHub documentation: manual `workflow_dispatch` requires the workflow file on the default branch; this experimental feature-branch workflow can still run on matching push events if Actions policy allows.
- A feature list is not evidence of 100% parity across 25 products.
