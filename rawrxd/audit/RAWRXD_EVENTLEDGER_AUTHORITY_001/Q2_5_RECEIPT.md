# Q2.5 — Build Recovery + EventLedger Authority Receipt

Authority: `RAWRXD_EVENTLEDGER_AUTHORITY_001`
Date: 2026-10-01
Gate script: `rawrxd/tools/q2_5_build_authority_gate.ps1`
Build tree: `F:\~dev\build_q2check` (Ninja, Release, MSVC 14.44.35207, Vulkan 1.4.357.0)

---

## Result

```
rawr_monolith:  BUILD=PASS  LINK=PASS  BINARY=1178624 bytes  SMOKE=PASS
Q2_5_FAIL=0    VERDICT=PASS
```

The canonical agent target now compiles, links, and executes. It did not
before this pass.

---

## Defect class A — duplicate authority (FIXED)

`rawrxd::continuous::EventLedger` was defined **twice** in the same
namespace:

| Header | `append` signature | Semantics | In build |
|---|---|---|---|
| `EventLedger.hpp` | `append(uint64_t runId, const Event&)` | per-run durable, tagged `RAWRXD_CONTINUOUS_STREAM_REALITY_001` | win32ide_strict only |
| `ContinuousEventLedger.hpp` | `append(const LedgerEvent&)` | flat global sequence, different event type | root target |

Every individual translation unit compiled. The build silently carried both
authorities.

**Repairs**

1. `ContinuousExecution.hpp` — removed `final` from the forward declaration
   `class ToolRegistry final;` (illegal, C3197). `final` belongs on the
   definition.
2. `ContinuousExecution.hpp` — removed `#include "ContinuousEventLedger.hpp"`.
   `EventLedger` is used only as a pointer in that header, so the forward
   declaration suffices and the stale include was the ODR source.
3. `ContinuousExecution.cpp` — added `#include "EventLedger.hpp"` so
   `Session::emit`'s `ledger_->append(id_, ev)` resolves to the canonical type.
4. `Win32ContinuousBridge.hpp` — repointed the stale include at `EventLedger.hpp`.
5. `Win32ContinuousBridge.cpp` — ported to the canonical API. The
   hand-rolled `LedgerEvent` construction and its 8-case
   `EventKind -> LedgerEventKind` switch were deleted; the canonical ledger
   takes the native `Event`. That switch had **no `default`**, so any future
   `EventKind` would have silently produced an uninitialized kind.
6. `Win32EventBridge::replaySince` — signature changed to
   `(uint64_t runId, uint64_t fromSequence, HWND target)`. The canonical
   ledger is per-run; the retired flat ledger was global, which is why the
   run id was absent. `Win32EventBridge` has zero callers, so nothing broke.
7. Root `CMakeLists.txt` — `ContinuousEventLedger.cpp` replaced by
   `EventLedger.cpp`.
8. Stale pair moved to `rawrxd/src/deep2/streaming/quarantine/*.QUARANTINED`.

## Defect class B — compile-clean but unlinkable (FIXED)

`rawr_monolith` compiled all 36 Deep2 objects, then failed at link with 20
`LNK2019`s. Symbols referenced by `Deep2Engine.cpp`,
`Deep2Engine_SsVkDecodeBind.cpp` and `Deep2Engine_GpuForward.cpp` were
defined in TUs listed **only** in the sibling `deep2_benchmark` target.

Added to `rawr_monolith`: `Beaconism.cpp`, `GpuScheduler.cpp`,
`TimeReverseDigest.cpp`, `ModelRegistry.cpp`, `Deep2PredictiveRouter.cpp`,
`streaming/EventLedger.cpp`, and the four `lavapath/DualStick*` TUs.

A compile-clean target that cannot link is not a passing target.

## Smoke

```
no-arg        -> usage text, exit 1
agent --help  -> "[RAWR] Loading model: agent"
                "[RAWR] Failed to load GGUF model"   (stderr, no hang)
```

The binary executes, and fails **honestly** when no model is available. No
fabricated PASS, no hang.

---

## Gate results

```
DUPLICATE_FQN_DEFINITIONS_SCANNED        = 1058
DUPLICATE_FQN_DEFINITIONS_FOUND          = 16
rawrxd::continuous::EventLedger          = absent from the duplicate list
CANONICAL_LEDGER_PRESENT                 = True
STALE_LEDGER_IN_SOURCE_TREE              = 0
STALE_LEDGER_QUARANTINED                 = True
FORWARD_DECL_FINAL_VIOLATIONS            = 0
STALE_LEDGER_BUILD_REFS                  = 0
LINK_DEFINING_TUS_LISTED_IN_BOTH_TARGETS = 8 of 8
RAWR_MONOLITH_BINARY_PRESENT             = True
Q2_5_FAIL                                = 0
```

The gate also caught its own bug during authoring: a
`Select-String -SimpleMatch` combined with a pre-escaped regex pattern
searched for literal backslashes and silently matched nothing, reporting all
8 TUs as absent when 4 were present. Fixed before the result was trusted.

---

## Open findings NOT closed by this pass

### 16 duplicate fully-qualified class definitions tree-wide

The new duplicate-FQN scan found the EventLedger pattern is not unique:

```
RawrCodex::DifferentialValidator <- RawrCodex_Multi_Structured.hpp, RawrCodex_Multi_v2.hpp
Deep2::VulkanCompute            <- vulkan_compute.h, vulkan_compute_patched.h, +3 variants
rawrxd::IModelBackend           <- AgentCore.h, ResponseCodedAgent.h
rawrxd::LocalModelBackend       <- AgentCore.h, ResponseCodedAgent.h
RawrXD::GGUFLoader              <- gguf_loader.h, gguf_loader.hpp
AST::ASTGraphEngine             <- ast_graph_engine.h, ast_graph_engine.hpp
TRES::TRESSystem                <- tres_stabilization_layer.hpp, tres_stabilization_system.hpp
+ 9 more (voice_assistant, native_speed_layer, local_reasoning_engine, ...)
```

**Not all are defects.** Several are benign header variants where only one is
ever included (`vulkan_compute_patched.h` vs `vulkan_compute.h`). Others look
real (`rawrxd::IModelBackend` declared in two agent headers). The gate reports
the census; it does not yet classify which are live duplicates. That
classification is Q3 work.

### `deep2_benchmark` has a pre-existing duplicate entry point

```
RealGGUFParity.cpp:483      int main(
deep2_benchmark_main.cpp:25 int main(
LNK2005: main already defined
LNK1169: multiply defined symbols
```

`RealGGUFParity.cpp` is a standalone gate that carries its own `main()` and is
also listed as a source in the `deep2_benchmark` executable. Both files are
pre-existing and untouched by this pass. This is a **third** instance of the
same family: duplicate authority inside a build that configures and compiles
successfully. `deep2_benchmark` is not required for the canonical agent path
and remains unbuilt.

---

## What this did NOT do

- No Q3 work. No literal-PASS sites were touched.
- No agent-loop or continuation change. `continuous::Session` still resets per
  step via `rawr_agent.cpp:327`; B3 is untouched.
- `Win32EventBridge` remains compiled-but-unreachable (zero callers), the same
  class of problem as the fake `Win32IDE_AgenticBridge` echo.
- remote64 untouched: `FAIL`, `step=21`, next action
  `dumpbin /disasm aead.obj`.
