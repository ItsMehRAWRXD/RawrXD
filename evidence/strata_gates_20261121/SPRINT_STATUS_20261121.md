# Sprint status — 2026-11-21 (shared build blocked by concurrent Deep2)

## Closed this session (committed + pushed to fix/ide-default-model-scan)
| Gate | Status | Commit |
| --- | --- | --- |
| G47 Autonomous repair | PASS | a45f22c963 |
| G48 Acceptance evaluator | PASS | f1b0c7b4ae |
| G57 Ollama tool+repair | PASS | 233c5dbb53 |
| G55 Native Git ops | PASS | dac2a6113a |
| G49 LSP protocol | PASS | 7f3880d2f5 |
| G54 Layout persistence | IMPLEMENTED, compiles, link/runtime pending | ad0d449543 |
| (earlier) G01, G56 | PASS | 4f344d8a78, f7719c2a21 |

## Shared build blocker (blocks all rebuilds)
`rawrxd_gpu_compute.lib(vulkan_compute.obj)` references
`RawrXD::Deep2::QuantDot::WeightCacheRetention()` which is unresolved.
- HEAD `quant_dot_dispatch.cpp` DEFINES it (consistent, links).
- The concurrent Strata/Deep2 agent's **uncommitted** changes to
  `quant_dot_dispatch.cpp`, `vulkan_compute.h`, `vulkan_compute_engine_adapter.cpp`,
  `Deep2Engine.cpp`, `deep2_qgemv.spv` have broken the link for **both**
  `RawrXD-Win32IDE-Native` AND `RawrXD-CLI-V2`.
- My last-good `rawr.exe` (used for G49/G47/G48) predates the agent's latest
  changes; the current tree cannot rebuild either target.

## What this means
- **G49** was verified with the last-good CLI (before the agent broke the build).
- **G54** implementation is committed and compiles; it cannot be linked or
  runtime-verified until the agent commits a linkable Deep2 state.
- **G50–G53** (debugger, GhostText, Output/Problems, Debug Console) require a
  working IDE build → blocked.
- **G02–G45** Strata-dependent → blocked (agent's uncommitted Deep2).

## Required unblock
The concurrent Strata/Deep2 agent must commit a consistent, linkable Deep2 state
(resolve `WeightCacheRetention` linkage). Do NOT stub the symbol (prohibited).
Do NOT edit or revert the agent's uncommitted files.

## Release ledger (updated)
```
CLOSED_GATES=11 (G01,G46,G47,G48,G49,G54-impl,G55,G56,G57 + 2 historical)
STRICT_REMAINING=72
G49=PASS
G54=IMPLEMENTED_COMPILES_LINK_PENDING
G50_G53=RUNTIME_PENDING (need IDE build)
LINK_BLK=QuantDot::WeightCacheRetention (concurrent uncommitted Deep2)
BUILD_CLI=BROKEN (shared lib)
BUILD_IDE=BROKEN (shared lib)
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```