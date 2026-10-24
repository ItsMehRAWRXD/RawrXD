# Batch 010: 45 end-to-end IDE acceptance gates

**Implemented in this batch:** all-three-projection preflight, no partial read/execution on insufficient budget, regression assertion, PR CI path-filter coverage. **Not yet verified:** a passing hosted CI run or hardware test. This is an acceptance ledger, not 45 completed fixes.

## A — 15 native build/CI gates
01 [done] Confirm development branch.
02 [done] Inspect native IDE workflow.
03 [done] Inspect native LSP smoke workflow.
04 [done] Inspect REAP projection smoke.
05 [done] Include native LSP changes in PR CI triggers.
06 [done] Include source audit changes in PR CI triggers.
07 [done] Include workflow changes in PR CI triggers.
08 [configured] GCC smoke.
09 [configured] MSVC smoke.
10 [configured] Native headless build.
11 [configured] Native IDE executable build.
12 [configured] Audit artifact upload.
13 [pending] Observe Actions run and full logs.
14 [pending] Fix failing compiler/linker errors.
15 [pending] Certify IDE launch with captured receipt.

## B — 15 ROM/dual-GPU gates
16 [done] Audit REAP partial-execution defect.
17 [done] Preflight Gate/Up/Down registration before work.
18 [done] Preflight aggregate packed residency before work.
19 [done] Use overflow-safe residency arithmetic.
20 [done] Reject impossible expert before read/upload/execute.
21 [done] Add regression asserting zero reads on insufficient budget.
22 [done] Add regression asserting zero executions on insufficient budget.
23 [configured] Explicit R9700 and RX7800XT self-hosted admission.
24 [pending] Register GPU runner.
25 [pending] Build Vulkan kernel and run device-specific probes.
26 [pending] GPU fence and ownership release.
27 [pending] True native 1.5-bit codec integration.
28 [pending] Multi-shard MoE routing parity.
29 [pending] Multi-token GPU numerical parity.
30 [pending] Reproducible sustained TPS target.

## C — 15 full IDE feature parity gates
31 [source] Native editor.
32 [source] Native GhostText.
33 [source] Native PowerShell panel.
34 [source] Native LSP framing.
35 [source] Snapshot engine.
36 [pending] Native LSP process/JSON-RPC lifecycle.
37 [pending] Physical GhostText acceptance.
38 [pending] PowerShell output/cancellation.
39 [pending] Browser rendering/navigation.
40 [pending] Debugger expressions/breakpoints.
41 [pending] Agent multi-file edits.
42 [pending] Agent build/test/rollback E2E.
43 [pending] Qt and third-party runtime dependency elimination.
44 [pending] 25 AI IDE feature-by-feature comparisons.
45 [pending] 100% completeness and parity certification.

## Outstanding technical hazards
- Preflight checks packed bytes; upload callbacks can return a larger device allocation than packed size. A later upload can still fail after prior uploads. No device allocation rollback callback is present; caller must manage allocated GPU resources.
- The bridge executes Gate/Up/Down in sequence and is not wired to the production Deep2 forward path. Full model parity is not established.
- GPU idle check is an injected callback, not yet a real Vulkan fence.
- GitHub connector workflow-run query only covers PR-triggered runs; empty results are inconclusive for push-triggered workflows.
- Qt6 optional in CMake does not imply all features are converted. CLI still references nlohmann_json.
- No source-only matrix establishes product parity without live acceptance tests.
