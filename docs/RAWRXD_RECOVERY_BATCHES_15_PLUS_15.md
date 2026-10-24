# RawrXD — two 15-item recovery batches

Canonical Windows evidence source: `F:\rawrxd`, branch `local-30b-backend`,
HEAD `4cdbf7f963cc0f4f3f032aa7d3819ecdfef4957d` (reported 2026-10-24).
This integration branch is **not** the active Windows checkout. Do not certify
with old Nemotron Q6_K probe output. Preserve working Ollama behavior.

## Batch 1 — correctness and CLI admission (15 gates)
1. [x] Add first-failing-layer witness in `forwardTokenAllLayers` (source committed; runtime unverified).
2. [ ] Capture full SHA-256 of current CLI and IDE binaries.
3. [ ] Verify branch/HEAD and clean-build receipt in the same test invocation.
4. [ ] Record exact GGUF path and full model SHA-256.
5. [ ] Separate prefill failure from decode failure in receipt.
6. [ ] Verify decode token ID and Q6_K embedding norm at each step.
7. [ ] Record first-layer input checksum before forward.
8. [ ] Record first-layer output checksum after forward.
9. [ ] Record last-layer output checksum and post-norm checksum.
10. [ ] Verify KV cache length before and after advance.
11. [ ] Compare greedy tokens against trusted same-GGUF reference.
12. [ ] Repair CLI getVersion stdout/JSON separation and test.
13. [ ] Bound `rawr models` latency; report timeout phase.
14. [ ] Run `rawr doctor`, `rawr models`, `rawr run` with Ollama live.
15. [ ] Attach Windows build, exit codes, and current-binary receipts.

## Batch 2 — GPU and enterprise path (15 gates)
16. [ ] Record Vulkan physical-device IDs and selected backend.
17. [ ] Record production Vulkan enablement at model admission.
18. [ ] Record per-tensor GPU eligibility and rejection reason.
19. [ ] Verify actual GPU weight upload and residency.
20. [ ] Record first successful Vulkan kernel dispatch.
21. [ ] Verify nonzero GPU layer submissions.
22. [ ] Verify nonzero Q6_K packed operations or explicit fallback.
23. [ ] Verify zero unintended CPU fallback with strict GPU policy.
24. [ ] Match GPU and CPU greedy token outputs.
25. [ ] Measure single-GPU TPS on fixed prompt and model.
26. [ ] Measure dual-GPU TPS and dispatch distribution.
27. [ ] Audit LSP initialize/completion/diagnostic/restart.
28. [ ] Audit GhostText insert/cancel/undo and debugger step/variables.
29. [ ] Run C++20/MASM differential compile/link/execute suite.
30. [ ] Run Windows CI, snapshot rollback, security and release gates.

**Completion rule:** Only check a gate after its source, test command, exit code
and artifacts are available. A source commit alone is not runtime certification.
