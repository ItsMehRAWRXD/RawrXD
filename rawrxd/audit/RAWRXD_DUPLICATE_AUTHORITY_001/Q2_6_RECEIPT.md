# Q2.6 — Duplicate Authority Classification Receipt

Authority: `RAWRXD_DUPLICATE_AUTHORITY_001`
Date: 2026-10-01
Gate: `rawrxd/tools/q2_6_duplicate_authority_gate.ps1` (static, pre-build)
Scope: `rawrxd/src` + `src`, 3205 code files, 7 parsed targets

```
DUPLICATE_FQN_TOTAL                          = 18
UNCLASSIFIED                                 = 0
LIVE_DUPLICATE_DEFECTS                       = 0
CANONICAL_TARGET_ENTRYPOINT_COLLISIONS       = 0
Q2_6_FAIL                                    = 0
VERDICT                                      = PASS
```

Build state after this pass (both targets compile, link, and were smoke-run):

```
rawr_monolith.exe     1178624 bytes
deep2_benchmark.exe    858112 bytes
```

---

## Classification method

Reachability is derived from a real include graph plus target membership, not
substring search. The earlier substring approach is what produced the false
"nothing depends on the stale ledger" conclusion (`LedgerEvent` does not contain
`EventLedger`).

For each FQN with more than one definition:

| Class | Meaning |
|---|---|
| `LIVE_DUPLICATE_DEFECT` | both definitions reachable by one target — a real ODR hazard |
| `MUTUALLY_EXCLUSIVE` | both reached, but never by a single target |
| `BUILD_VARIANT` | exactly one definition is reached |
| `DEAD_QUARANTINE` | no definition is reached by any target |

## Results

```
CLASS_DEAD_QUARANTINE  = 17
CLASS_BUILD_VARIANT   = 1
CLASS_LIVE_DUPLICATE  = 0
```

### The one BUILD_VARIANT

`Deep2::VulkanCompute` — five headers, one class name:

```
rawrxd/src/deep2/vulkan_compute.h
rawrxd/src/deep2/vulkan_compute_patched.h
rawrxd/src/deep2/vulkan_compute_batch10.h
rawrxd/src/deep2/vulkan_compute_batch10_utf8.h
rawrxd/src/deep2/vulkan_compute_from_batch10.h
targets: deep2_benchmark, rawr_monolith      shared: none
```

Both targets reach it, but never two headers in the same target. These are
successive patch generations of one header, only one of which is included per
translation unit. Not a defect; it is unmerged history and should be collapsed
to one canonical header when that area is next touched.

### The 17 DEAD_QUARANTINE

Grouped by cause:

- **Case-variant pairs in one directory** (Windows hides the collision):
  `GGUFAdapter` (`gguf_adapter.hpp` / `GGUFAdapter.hpp`),
  `UnifiedModelLoader` (`unified_model_loader.hpp` / `UnifiedModelLoader.hpp`),
  `RawrXD::GGUFLoader` (`rawrxd/src/core/gguf_loader.h` /
  `rawrxd/src/gguf_loader.hpp`), `AST::ASTGraphEngine`.
- **Split type/stub pairs**: `AlexaStyleAssistant`, `SiriStyleAssistant`,
  `HybridAssistant`, `CodebaseContextAnalyzer`,
  `VoiceAssistantCommandDispatcher` — all from
  `core/voice_assistant_stubs.hpp` + `core/voice_assistant_types.hpp`.
- **Two agent headers declaring the same backend interfaces**:
  `rawrxd::IModelBackend` and `rawrxd::LocalModelBackend`, both in
  `agent/AgentCore.h` and `agent/ResponseCodedAgent.h`. This one is worth
  noting: it is the same shape as the seven-tool-registry duplication, at
  interface level. Neither is built today.
- **Same-name headers in different directories**:
  `rawrxd::ForwardDepthGuard` and `rawrxd::HeapScratchArena` across
  `deep2/Deep2StackGuard.h` and `deep2/expert_cache/Deep2StackGuard.h`.
  Each FQN is defined in only ONE of the two files; they are not duplicates of
  each other. The first scanner draft falsely paired them.
- **Stale generations**: `LocalReasoningEngine`, `NativeSpeed::NativeSpeedLayer`,
  `RawrCodex::DifferentialValidator`, `TRES::TRESSystem`.

None is reachable from any target. None is a build risk today. They are
cleanup debt, and Q3's `backingSources` requirement should refuse to cite any
of them as evidence.

---

## Defect fixed in this pass: entry-point collision

`deep2_benchmark` could never link:

```
RealGGUFParity.cpp:483      int main(
deep2_benchmark_main.cpp:25 int main(
LNK2005 / LNK1169
```

`RealGGUFParity.cpp` is `RAWRXD_REAL_GGUF_PARITY_001`, a deliberate standalone
E2E parity harness. It already has its own executable target
(`rawrxd/CMakeLists.txt` -> `rawrxd_real_gguf_parity`). The root
`CMakeLists.txt` was additionally listing it as a source of `deep2_benchmark`.

Removed from `deep2_benchmark`. `deep2_benchmark` now builds and links
(858112 bytes). This was the same failure family as EventLedger — duplicate
authority inside a build that configures and compiles cleanly — at entry-point
scope, and it is now gated by
`CANONICAL_TARGET_ENTRYPOINT_COLLISIONS`.

---

## Two defects in the gate itself, found and fixed before trusting output

Recorded because a gate that reports zero for the wrong reason is worse than no
gate.

1. **Basename-keyed include resolution.** The first draft keyed includers by
   bare filename, conflating the two distinct `Deep2StackGuard.h` files and
   reporting two unrelated FQNs as mutual duplicates. Fixed to path-qualified IDs.
2. **Guessed candidate directories.** The second draft resolved a bare
   `#include` by trying five hardcoded directories. That silently dropped
   resolution from 1540 to 679 headers and flipped `Deep2::VulkanCompute` from
   `BUILD_VARIANT` (both targets) to `DEAD_QUARANTINE` — a false all-clear.
   Replaced with a full basename index over every header on disk. Resolution
   recovered to 1012, and the result is now the one reported above.

An earlier `-SimpleMatch` combined with a pre-escaped regex produced the same
class of false zero in the Q2.5 gate.

---

## New finding: 6 ambiguous bare includes

The corrected resolver surfaced headers that share a basename across
directories where the including file's own directory holds no match, so
resolution depends on the include path:

```
Deep2StackGuard.h            deep2/  vs  deep2/expert_cache/
GpuCacheResidencyAuthority.h compute/ vs  gpu/
HotpathWorkEliminator.h      compute/ vs  perf/
HUD.hpp                      sunshine/instagib/ vs sunshine/neonsiege/
RepositoryIntelligence.hpp   repo/  vs  repository/
ToolRegistry.h               agentic/ vs core/
```

`ToolRegistry.h` is the significant one: `agentic/ToolRegistry.h` and
`core/ToolRegistry.h` are two of the competing tool authorities already
identified. Whichever one a given translation unit receives depends on include
order, which is exactly the mechanism that would let Q3 certify a receipt
against the wrong registry.

These are reported, not remediated, in this pass. Conservative handling is
applied: an ambiguous include is attributed to ALL candidates, so
reachability is over- rather than under-reported.

---

## Not done in this pass

- Q3 literal-PASS purge. No receipt site was touched.
- B3 continuation wiring. `rawr_agent.cpp:327` still resets per step.
- The 17 `DEAD_QUARANTINE` headers were classified, not deleted. Deletion is
  deferred so that a future `backingSources` citation failing to resolve is
  visible as a broken reference rather than a missing file.
- `Win32EventBridge` and `Win32IDE_AgenticBridge` remain compiled but
  unreachable.
- remote64 untouched: `FAIL`, `step=21`, next `dumpbin /disasm aead.obj`.
