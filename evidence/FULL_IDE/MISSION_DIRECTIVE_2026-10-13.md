# RAWRXD / DEEP2 — AUTONOMOUS END-TO-END COMPLETION DIRECTIVE

## Mission

Complete the entire RawrXD IDE, Deep2 inference engine, native GPU compute runtime, ROM streamer, Model Genie, compiler/linker/build system, Piranha/HexMag Swarm, and agentic engineering environment from their **current verified state to production-ready completion**.

**Do not stop at Gate 20 if the IDE is still incomplete. Gate 20 is a certification milestone, not permission to leave unfinished features.**

Work autonomously in dependency order until every required component is implemented, integrated, tested, and documented.

## 1. Establish the authoritative starting point

Repository: `F:\rawrxd`

1. Inspect HEAD, origin, working-tree changes, worktrees, branches, and current builds.
2. Read the existing gate ledgers, certification evidence, CI scripts, and architecture specifications.
3. Determine which gates are genuinely PASS, PARTIAL, BLOCKED, or NOT STARTED.
4. Preserve previously certified work. Re-run relevant tests after changes.
5. Do not invent missing gate definitions. Reconcile the existing ledger with the proposed 20-gate roadmap before execution.
6. Treat reported results as historical evidence until reproducible against the current source.
7. Preserve all GGUFs, model weights, Git history, user files, and protected directories.
8. Never delete or reset uncommitted work without establishing ownership and preserving it.

Initial reported state:
- Gate 1: PASS — quantization parity.
- Gate 2: OPEN — primitive implementation provenance.
- Gate 3: PASS — GGUF tensor geometry.
- Gate 4: PASS — native CPU/GPU dispatch certification.
- Gate 5: OPEN — independent multi-position reference parity.
- Gates 6–20: reconcile with actual repository ledger; do not assume completion.
- Strata S06: PASS — INT8 KV, 24/24 token identity, 71.88% memory reduction.
- Strata S07: OPEN — speculation measured, zero accepted draft tokens.
- RX 7800 XT: native Vulkan single-device execution demonstrated.
- Multi-GPU concurrent execution: not yet certified.

## 2. Execute the gates in dependency order

Use the repository's authoritative gate specifications. Where the proposed roadmap applies, follow:

- Gate 2: Primitive provenance and implementation audit.
- Gate 5: Multi-position CPU/GPU/reference parity.
- Gate 6: KV-cache, state, and context correctness.
- Gate 7: Dense, MLA, MoE, SSM, and hybrid architecture execution.
- Gate 8: Native GPU, quantization, and ROM streaming.
- Gate 9: Agentic IDE end-to-end tool execution.
- Gate 10: Concurrent multi-GPU orchestration.
- Gate 11: DeepSeek 671B native model execution.
- Gate 12: Performance certification, including the 150 TPS target.
- Gate 13: Million-token context certification.
- Gate 14: ROM reconstruction integrity and precision parity.
- Gate 15: Piranha/HexMag multi-agent scalability.
- Gate 16: Native compiler, linker, builder, debugger, and test execution.
- Gate 17: Complete IDE feature integration.
- Gate 18: Security, tool authorization, and execution-receipt integrity.
- Gate 19: Endurance, cancellation, crash recovery, and device-loss recovery.
- Gate 20: Clean-checkout production release certification.

Do not treat this proposed numbering as overriding an existing authoritative gate ledger.

## 3. Autonomous execution loop

For every gate:

1. Read its acceptance contract.
2. Identify missing functionality from real source and executable evidence.
3. Build a dependency graph of the required repairs.
4. Implement complete production functionality — no placeholders, simulated results, or fabricated receipts.
5. Compile and link the real targets.
6. Run actual tests using real models, hardware, and tools.
7. Diagnose failures from the earliest reproducible divergence.
8. Fix the root cause rather than bypassing the failing assertion.
9. Re-run the affected regression battery.
10. Capture commands, exit codes, timing, logs, and numerical evidence.
11. Mark PASS only when every acceptance requirement is satisfied.
12. Commit verified changes with focused commit messages.
13. Push to the authorized remote only after confirming the intended branch and preserving unrelated work.
14. Advance automatically to the next unblocked gate.

If a gate is blocked by an independent task, continue other safe, dependency-independent work. Record the blocker and return when its prerequisites are resolved.

Do not repeatedly ask for approval for ordinary authorized source edits, builds, tests, or non-destructive Git operations.

Never fabricate completion when an external dependency, missing hardware, permissions, or unattainable performance requirement prevents certification.

## 4. Complete the IDE beyond the gates

Audit every existing menu item, command handler, UI surface, and advertised feature.

Finish and integrate:

- Native Win32 IDE windowing, editor, tabs, workspace, file explorer, and session restoration.
- Syntax highlighting, completion, diagnostics, navigation, search, refactoring, and debugging.
- Integrated terminal, PowerShell, build tasks, test runner, and output panels.
- Native compiler, assembler, linker, build orchestration, and executable launching.
- Git operations, branch management, diff viewing, conflict handling, and source control.
- Deep2 local inference, model loading, selection, generation, streaming, and cancellation.
- Native Vulkan/custom GPU compute, device selection, multi-GPU scheduling, and memory management.
- Model Genie architecture recognition, tensor binding, and supported model execution.
- ROM streaming, quantized reconstruction, expert caching, KV management, and long-context operation.
- Agentic chat, tool calling, plan/edit/build/test/retry loops, and verifiable tool receipts.
- Piranha/HexMag agent spawning, worker scheduling, coordination, cancellation, and result merging.
- Browser navigation, page interaction, local tool authority, and controlled external integrations.
- Settings persistence, crash recovery, error reporting, diagnostics, and accessibility.
- Installation, packaging, upgrade handling, offline deployment, and release documentation.

Every advertised feature must be functional or explicitly documented as unsupported. No dead menu actions, fake completion messages, or success without executed work.

## 5. Piranha Swarm execution

Use parallel agents for independent workstreams only.

Assign explicit file ownership, branch/worktree boundaries, and acceptance contracts.

Recommended workstreams:
- Inference numerical correctness.
- GPU compute and streaming.
- Model architectures and Model Genie.
- IDE and compiler/toolchain.
- Agent orchestration and security.
- CI, testing, documentation, and release.

Workers must report real changes, build results, test evidence, and blockers.

The orchestrator should perform only coordination, dependency resolution, verification, and integration. Keep its context focused.

Do not merge worker branches without checking provenance, unique commits, conflicts, and regression results.

## 6. Strict certification rules

A gate cannot PASS from:
- Source code existing.
- A successful compile without linking.
- A successful link without execution.
- Finite logits without reference correctness.
- Matching argmax without the required numerical evidence.
- GPU initialization without actual GPU dispatch.
- Simulated tool calls or model outputs.
- A commit message claiming success.
- A benchmark whose measurements omit material overhead.
- A test skipped because required hardware is unavailable.

Every PASS must have an executable, reproducible evidence chain.

Performance acceptance must use measured end-to-end workloads and distinguish prefill, decode, model loading, cache effects, and device synchronization.

The 150 TPS requirement remains a mandatory stated performance target. If physically or technically unachievable for a specific model/hardware configuration, report the measured limit and blocker rather than inventing success.

## 7. Progress ledger

Maintain:

`F:\rawrxd\evidence\FULL_IDE_COMPLETION_LEDGER.md`

For every gate and feature, record:

- Status.
- Responsible agent.
- Source files modified.
- Implementation completed.
- Build command and exit code.
- Test command and exit code.
- Numerical or functional acceptance results.
- Evidence paths.
- Commit hash.
- Remaining blocker.
- Next dependency.

Keep a separate list of discovered defects and unfinished features. New defects must not disappear from the ledger merely because their original gate passes.

## 8. Completion criteria

The project is complete only when:

1. All authoritative gates pass.
2. All required IDE features are implemented and tested.
3. All supported inference architectures execute correctly.
4. GPU and streaming paths have genuine execution evidence.
5. Agentic engineering workflows complete real tasks with authentic receipts.
6. Compiler, linker, debugger, terminal, Git, and workspace functions operate end-to-end.
7. Automated regression tests pass from a clean checkout.
8. No known release-blocking defects remain.
9. A complete distributable IDE can be installed, launched, used, and uninstalled.
10. The release has verifiable build artifacts, source provenance, and documentation.

If any criterion remains unmet, report the project as incomplete and continue all available safe work.

## 9. Operating directive

BEGIN NOW.

Discover the actual current state, select the earliest unmet prerequisite, implement it, test it, certify it, and advance.

Continue through the entire dependency graph without stopping after each gate.

Do not substitute planning, documentation, or simulated output for implementation.

Do not stop because one worker fails. Reassign or isolate the work and continue.

Do not claim completion without evidence.

The final deliverable is a fully functioning, independently reproducible RawrXD IDE and native Deep2 engineering platform — not merely 20 green gate labels.