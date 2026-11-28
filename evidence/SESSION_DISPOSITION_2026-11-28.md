# Session disposition — 2026-11-27/28 (integration/combined-2026-11-25)

Authoritative record of all work completed and verified this session. All commits are LOCAL
(pushed=0). Each item is backed by a receipt under `evidence/`.

## 1. Agent-controller hardening (headless CLI + production)
Controller: `tools/rawr_agent.cpp` (headless), `src/agent/agent_controller.cpp` (production).
| Fix | Commit | Deterministic test |
|-----|--------|--------------------|
| Per-provider tool-channel profile (deepseek=text, others=native) | 63cb5b4f88 | `--self-test-channel` 9/9 |
| Text-channel parser hardening (first KNOWN tool object) | fdb335a0d9 | `--self-test-parse` 7/7 |
| Edit convergence feedback (return current content on miss) | 2adc93898b | `--self-test-edit` 5/5 |
| GUI-run short-circuit (skip 20 s block) | fd6b2ddee9 | `--self-test-guirun` 5/5 |
| Deterministic model-free E2E pipeline (real MSVC build) | f4556f5cdb | `--self-test-pipeline` PASS |
| VerifyFunctional launch retry + flaky-test root-cause fix | f113d98292 | pipeline 4/4 stable |
| Production controller tests (happy/no-progress/reject/staleness) | 4daf93accb, 5a2391e278 | 8/8 |

Receipts: `evidence/HEADLESS_AGENT_20261126/*` (WORKSTREAM_DISPOSITION.md is the index).

## 2. Build integrity (WORKPACKAGES Package 6)
`CMakeLists.txt`: new `RAWRXD_REQUIRE_PRODUCT_DEPS` (default ON) makes a product built without a
required dependency a hard configure error (opt-out preserved).
| Change | Commit |
|--------|--------|
| Fail-closed Deep2 (IDE, -Ext, CLI x2) | e8d9989e62, 22938ab9bc |
| Generalize option + production_hardening fail-closed | 06ade141cd |
Verification: default configure OK; deep2-off FATAL; opt-out OK; product dep compiles+links (exit 0).
Receipt: `evidence/BUILD_INTEGRITY_PACKAGE6.md`. gpu_compute transitively covered via deep2 PUBLIC link.

## 3. LSP Content-Length parser (Package 3)
`src/win32app/lsp_content_length_test.cpp` builds and passes 16/16 (gap "not regression-tested" closed).
Commit fb76891c3d. Receipt: `evidence/PACKAGE3_LSP_CONTENT_LENGTH.md`.

## 4. Reliability (fresh evidence, hardened controller)
gpt-oss:20b PASS; 1/4 within budget — model-compliance-bound (peer afa3ddabc4: variance 0–3/3).
Commit 2110d84e8b. Receipt: `evidence/HEADLESS_AGENT_20261126/reliability_hardened_controller.md`.

## Certification state
```
CERTIFIED=0  RELEASE=HELD  PROMOTE=0  PUSHED=0
Agent controllers : FUNCTIONALLY_VERIFIED (deterministic + live)
Build integrity   : CONFIGURE + BUILD VERIFIED
LSP parser        : FUNCTIONALLY_VERIFIED (16/16)
```

## Remaining (external — needs user decision)
1. Push the branch (withheld; explicit authorization required).
2. Reliability >25% — model-compliance work, not controller code.
3. Full monolith build + GPU acceptance + Packages 4/7/9/10 — heavy MSVC+Vulkan/hardware env.
4. Certification of the 58 backlog tasks — requires the above.