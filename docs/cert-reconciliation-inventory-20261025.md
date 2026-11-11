# Certification-Branch Reconciliation Inventory (2026-10-25)

Branch: `integration/cert-reconciliation-20261025` (created from `origin/main` @ `033a8acb`, no merges performed).
Policy: preserve every source branch; create integration candidates only; do NOT merge unverified code into `main`.

## Canonical baseline
- `origin/main` @ `033a8acb55d46d2fc22a84428e81f3167a0c3897` (2026-10-18) — authoritative release baseline. Deep2/REAP/MASM absent from tree.

## Candidate recovery branches (Oct 24–25 wave)

| Branch | Tip | Date | vs main (behind/ahead) | Track |
|---|---|---|---|---|
| origin/audit/deep2-build-recovery-20261024 | 414967f5 | 2026-10-24 | 11 / 377 | Deep2 build recovery |
| origin/audit/fused-gemv-recovery-20261024 | fa503b4a | 2026-10-24 | 11 / 490 | Fused host GEMV |
| origin/audit/native-linker-cert-20261024 | 717593ff | 2026-10-24 | 11 / 362 | Native linker cert |
| origin/feature/reap-unified-controls-20261025 | 1454559f | 2026-10-25 | 11 / 357 | REAP unified controls |
| origin/fix/reap-cli-json-and-size-20261025 | a843277b | 2026-10-25 | 11 / 444 | REAP CLI JSON/size |
| origin/fix/deep2-multimodel-safety-20261025 | 5c128adf | 2026-10-25 | 11 / 478 | Deep2 multi-model safety |
| origin/feature/reap-size-integration | e705d3c2 | 2026-10-25 | 11 / 432 | REAP size + Vulkan |
| origin/feature/deep2-local-adapter | bd84b74e | 2026-10-23 | 3183 / 1 | Deep2 OpenAI adapter |
| origin/feature/pure-masm-ide-integration | 04ff3219 | 2025-12-30 | 3183 / 32 | MASM IDE |
| origin/feature/tool-ecosystem-unblock-autonomy | 1b8360cf | 2026-04-20 | 132 / 566 | Agentic tool ecosystem |
| origin/cert/deep2-parity-probe-001 | 01f740ca | 2026-09-01 | 3183 / 1 | Deep2 parity probe |
| origin/preservation/source-baseline-20261021 | 7d5106b3 | 2026-10-24 | 11 / 355 | Source preservation baseline |

## Recommended integration order (candidates, not merges)
1. `origin/preservation/source-baseline-20261021` — establish preserved baseline reference.
2. `origin/audit/native-linker-cert-20261024` — linker certification evidence.
3. `origin/audit/deep2-build-recovery-20261024` + `origin/audit/fused-gemv-recovery-20261024` — Deep2 build + GEMV.
4. `origin/fix/deep2-multimodel-safety-20261025` — Deep2 safety.
5. `origin/feature/reap-size-integration` + `origin/feature/reap-unified-controls-20261025` + `origin/fix/reap-cli-json-and-size-20261025` — REAP.
6. `origin/feature/deep2-local-adapter` — adapter (high divergence: 3183 behind).
7. `origin/feature/pure-masm-ide-integration` — MASM (high divergence).
8. `origin/feature/tool-ecosystem-unblock-autonomy` — agentic tools.
9. `origin/cert/deep2-parity-probe-001` — parity probe.

## Acceptance criteria before promotion to main
- Successful MSVC build of integration candidate.
- Relevant regression tests pass.
- Deep2 inference verification.
- Agentic tool-execution tests.
- Documented rollback point (tag on main).

## Status
No code merged. Inventory only. Integration candidate branch created; next step is cherry-pick/merge-tree analysis per branch in isolated worktree.