# RAWRXD_DEEP2_VIRTUAL_MODEL_ADDRESS_SPACE_001

## Scope
This is a source overlay onto the **existing** `src/deep2/vwa/` architecture, not a replacement engine or separate cache. Its source files replace the corresponding files under `src/deep2/vwa/`. No generated file is edited, and the retired `vwa/Vwa.hpp` umbrella is deliberately not used.

### Implemented
- `VwaTypes.hpp`: `VirtualTensor` extends the existing `VirtualTensorRef` and keeps sparse packed resident ranges, IR hints, pin/in-flight state, tier, and GPU hint.
- `VwaSpace.hpp`: preserves ROM identity and stores sparse tensor state; duplicate registration fails.
- `VwaIrResidency.hpp`: compiles the **typed** `OperationIR::input()`/`weight()` operands into the next-use reference index. Zero-based ModelGenie IDs map to one-based VWA IDs. Next-use is circular over the token's IR.
- `VwaScheduler.hpp`, `_Lease.cpp`, `_Fulfill.cpp`: exact-range staging + device allocation; range-budget enforcement; per-op lease and release; next-use eviction; opportunistic IR lookahead prefetch; mandatory expert top-k, not all experts.
- `VwaCoalesce.hpp`: fixes erroneous coalescing across distinct tensor identities.
- `VwaGeneratedBridge.hpp`: translates compiler-local GGML type ordinals to canonical ggml IDs, mounts 377 ROM descriptors with checked data-start offset and uses `ExpertBank` to plan selected expert slices.
- `ChooseGpuPlacement`: overflow-checked cost model `(missingWeights + activations + synchronization + transferPenalty)` for two bandwidth domains. **Planner only** until linked to a real GPU allocation/copy/queue backend.

### Critical scope limits
- No production CUDA/Vulkan GPU allocator or dual-device queue integration is included; existing `DmaStage` is a host-heap copy and remains so. A host-copy buffer MUST NOT be represented as GPU residency.
- Deep2's production forward execution loop is not wired here. Call the scheduler on the authoritative `kExecutionIRTable` op loop after router top-k is known. `PrepareOp` returns exact packed buffers and `ReleaseOp` must run after kernel consumption. Kernel-side packed-Q4_K/Q6_K arithmetic and tile-awareness must be proven independently.
- `PrefetchAhead` is currently synchronous/advisory. True disk/GPU async overlap and fence-safe eviction require the existing residency transport to implement actual in-flight operations.
- No live 9.65 GB GGUF was available in this environment. No live token, 150 TPS, GPU parity, or production cross-token working-set claim is certified.
- The standalone smoke test uses a small ROM fixture with canonical Q4_K block geometry and the current VWA memory/copy backend; metadata-only test requires the actual generated headers from the user's checkout.
- Generated residency bounds remain policy **inputs**, not guaranteed achievable physical placements. The test's logical>physical gate uses its configured residency budget, not real system RAM/VRAM.
- The hard gates `FULL_TENSOR_F32_MATERIALIZATIONS_PER_TOKEN=0` and `PACKED_WEIGHT_RESIDENCY=1` are proven for the tested VWA path only. Production whole-token gates remain HOLD.

### Apply to repo (PowerShell)
From the user's actual branch containing `src/deep2/vwa/`, back up the six existing files before overwriting. Do NOT attempt to apply to `main` if `src/deep2/vwa/` is missing there. Run `./apply.ps1 -RepositoryRoot F:\rawrxd` from this source-drop folder; it first checks exact baseline Git blob SHAs and refuses dirty targets. Or back up and copy these `.hpp/.cpp` files to the matching paths (including the new `VwaIrResidency.hpp` and `VwaGeneratedBridge.hpp`). Preserve `VwaDma.hpp`, `VwaPhysical.hpp`, `VwaExpert.hpp`, `VwaBlockMath.hpp` and generated headers unchanged.

### Windows test commands
From project root in the VS2022 x64 Native Tools prompt, after copying source:

```bat
cl /nologo /std:c++17 /EHsc /W4 /WX /Isrc\deep2 tests\vwa_virtual_model_address_space_001.cpp src\deep2\vwa\VwaScheduler_Lease.cpp src\deep2\vwa\VwaScheduler_Fulfill.cpp /Fe:vwa_virtual_model_address_space_001.exe
vwa_virtual_model_address_space_001.exe

cl /nologo /std:c++17 /EHsc /W4 /WX /Isrc\deep2 /Isrc\deep2\modelgenie /Igenerated\DeepSeek-V2-Lite-Chat tests\vwa_generated_metadata_001.cpp src\deep2\vwa\VwaScheduler_Lease.cpp src\deep2\vwa\VwaScheduler_Fulfill.cpp /Fe:vwa_generated_metadata_001.exe
vwa_generated_metadata_001.exe
```

### Op-loop integration API
```cpp
// After generator metadata is validated and GGUF backend is mounted:
Deep2::vwa::VwaScheduler scheduler(vwaSpace);
scheduler.SetBudget(actualBudget);
scheduler.BindIR(RawrXD::Deep2::Generated::kExecutionIRTable, 300);

// In the authoritative execution loop, AFTER selecting top-k experts:
std::vector<Deep2::vwa::OpLease> held;
if (!scheduler.PrepareOp(opIndex, selectedExpertRanges.data(),
                         selectedExpertRanges.size(), held)) return false;
// Dispatch op using held[].packedData and held[].range. For GPU buffers,
// device handles + offsets need backend-specific binding, not CPU pointer math.
const bool ok = DispatchCurrentOp(held);
const bool released = scheduler.ReleaseOp(held);
if (!ok || !released) return false;
scheduler.PrefetchAhead(opIndex, /*lookahead*/2);
```
The above is an integration **contract**, not a claim that `DispatchCurrentOp` or production wiring was added by this drop.

### Gate truth table
| Gate | Result |
| --- | --- |
| IR index / circular future reference | Component test PASS |
| Selective expert range packing | Component test PASS |
| No full-tensor F32 expansion inside tested VWA path | Component test PASS |
| Logical bytes exceed configured resident budget | Component test PASS |
| Validated generated 377/300 source integration | Needs native metadata test |
| Physical R9700 / RX7800XT residency + queue fences | HOLD |
| Live tokenizer-to-token / numeric parity | HOLD |
| Whole-engine 0 F32 materializations/token | HOLD |
| Full acceptance promotion | HOLD |

`VERDICT=VWA_COMPONENT_PASS_RUNTIME_HOLD` means there is working VWA source and a passing standalone test, **not** that the complete user acceptance gate passed.
