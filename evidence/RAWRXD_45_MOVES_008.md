# RAWRXD BATCH 008 — 15 + 15 + 15 end-to-end closure audit

**Interpretation:** These are 45 concrete audit/acceptance gates. Only marked changes are implemented. No 100% parity or green CI is claimed.

## Batch 1: Native IDE and no-deps — 15 gates
01 [done] Identify canonical development branch.
02 [done] Inspect CMake native IDE target.
03 [done] Inspect CMake CLI target.
04 [done] Inspect CMake Qt optional switch.
05 [done] Add real native IDE GitHub Actions build target.
06 [configured] Upload native IDE executable if produced.
07 [pending] Observe CI configure PASS.
08 [pending] Observe CI native IDE link PASS.
09 [pending] Execute native IDE process launch smoke.
10 [pending] Verify editor window and input.
11 [pending] Verify native PowerShell output/cancel.
12 [pending] Verify native LSP initialize and diagnostics.
13 [pending] Verify GhostText accept/dismiss.
14 [pending] Verify debugger and browser native surfaces.
15 [pending] Remove/replace all external dependencies in certified no-deps path.

**Concrete gap:** `RawrXD-CLI-V2` currently links `nlohmann_json::nlohmann_json` in root CMake. This violates the strict no-new-deps/no-vendored-JSON target if it is required at runtime/build. Do not remove without auditing all include and link usage; replace with existing `json_mini` only after feature and parser parity tests.

## Batch 2: GPU and ROM — 15 gates
16 [done] Inspect dual-GPU admission workflow.
17 [done] Reject iGPU as a second discrete GPU.
18 [done] Require both R9700 and RX 7800 XT by name.
19 [configured] Check Vulkan enumeration.
20 [configured] Compile six native smoke tests on GPU host.
21 [pending] Confirm registered self-hosted runner is online.
22 [pending] Validate Vulkan device IDs, queues and capabilities.
23 [pending] Build Deep2 Vulkan target.
24 [pending] Run GPU0 one-token forward.
25 [pending] Run GPU1 one-token forward.
26 [pending] Run dual-GPU forward.
27 [pending] Verify packed quant kernels numerically.
28 [pending] Verify ROM native 1.5-bit codec.
29 [pending] Verify 11-shard MoE and multi-token generation.
30 [pending] Benchmark reproducible end-to-end TPS.

## Batch 3: IDE full product parity — 15 gates
31 [done] Locate Qt LSP client source.
32 [done] Locate native LSP framing source.
33 [done] Locate native GhostText source.
34 [done] Locate Qt GhostText overlay.
35 [done] Locate native PowerShell source.
36 [done] Locate native snapshot engine.
37 [pending] IDE → gateway → inference response.
38 [pending] IDE → agent → multi-file edit.
39 [pending] Agent → compiler → test → verification.
40 [pending] Failed test → snapshot rollback.
41 [pending] Browser navigation and rendering.
42 [pending] Debugger breakpoints/expressions.
43 [pending] Extension host compatibility.
44 [pending] 25-product feature-by-feature reproducible evidence.
45 [pending] Full 100% completeness gate with signed receipts.

## GitHub Actions execution limits
The GitHub connector in this session can commit workflow files and query PR-associated workflow runs and commit statuses, but it does not expose a general workflow dispatch API. Push-triggered workflows should be evaluated on the Actions UI; a missing connector result is not evidence of failure or success. The dual-GPU workflow needs a registered matching self-hosted runner, not merely source authorization.

## Recommended next actual implementation order
1. Get a native IDE executable build receipt; fix compiler/linker errors.
2. Add a headless IDE startup/IPC smoke, then physical UI automation.
3. Replace remaining Qt and third-party link dependencies in the actual daily-driver target, not unrelated code.
4. Integrate live LSP/PowerShell/GhostText/agent rollback.
5. Validate real dual-GPU Deep2 with immutable GGUF shards and per-layer parity.
6. Certify top-25 product comparisons from observed tests.
