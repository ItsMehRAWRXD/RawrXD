# K2-G01…G05 — Host native GEMV + 61-layer generation

`PROMOTE=0` · `CERTIFIED=0` · `TIP_CLIMB=HOLD`

## Controlling defect (G01)

`kn` in `gate GEMV failed type=12 kn=0000000000000000` is `GEMVKernelFn*` from
`QuantKernelRegistry::GetGEMV(12)`. Null because the K2 `INDEX_AND_ADDRESS`
early-return skipped `QuantKernelRegistry::Initialize()`.

Secondary: with `DUALSTICK_ARM=0` / `DualStickVc==nullptr`, stick worklist always
failed; host expert path added in `K2NativeMoEFfn_Place.cpp`.

## Fixes landed

1. `Deep2Engine.cpp` — Initialize QuantKernelRegistry on K2 INDEX success path.
2. `K2NativeMoEFfn_Expert.cpp` — lazy Initialize in `HostGemv` if table empty.
3. `K2NativeMoEFfn_Place.cpp` — host GEMV when DualStick VC unbound.
4. `K2MoEWeights.hpp/.cpp` — `kMaxExperts=16` + clamp for REAP top-k.

## Executable

- SHA-256: `C864180B1C7A68565F592EC6641389DCBF2DB29C68776DF1AFA3117443F22A73`
- Prior failing SHA: `BB67FB29D78097FB7A87AD40B9D69715B1D2E02632BAB65DF3706D6CFC81F3AE`

## Evidence

| Fixture | Result |
| --- | --- |
| `RAWRXD_K2_LAYERS=2` `--max-tokens 2` | EXIT=0; HOST_GEMV_EXPERT=16; GENERATED_TOKENS=2; CLEAN_EXIT |
| Full 61L `--reap 30GB/8` `--max-tokens 8` | EXIT=0; LAYER_COUNT=61; GENERATED_TOKENS=8; experts_executed=3840 parity=1; HOST_GEMV_EXPERT=3840; ACTIVE_RUNTIME_ROUTER_RESIDENCY; CLEAN_EXIT; ~135s |

Artifacts: `g03_layers2.*`, `g05_full61_t8.*`, `g05_full61_t8.json`

## Gate dispositions (this SHA only)

| Gate | Disposition |
| --- | --- |
| K2-G01 locate kn | PASS — null GEMVKernelFn, INDEX skip Initialize |
| K2-G02 acquisition | PASS — slices bounds_ok; host ReadExpertSlice + GEMV |
| K2-G03 host GEMV repair | PASS — registry init; Q4_K GetGEMV(12) non-null match=1 |
| K2-G04 layer exec | PARTIAL — 61 layers + MoE parity=1; **no independent numerical reference yet** |
| K2-G05 native gen | PASS (functional tokens) — 8 tokens, receipt generation_completed=true; **text quality / parity NOT certified** |
| GPU / DualStick | NOT_TESTED — `VK_ICD=BLOCKED WHY=R1_HOST_FLOOR` `DUALSTICK_ARM=0` |
| REAP residency stress | PARTIAL — working_set applied; eviction/reload pressure not separately exercised |
| PROMOTE | 0 |

## Output note

Receipt output for 8-token fixture was non-English / reserved-token heavy. Treat as
**TOKEN_SURVIVED ≠ NUMERICAL_PASS**. Independent reference parity remains OPEN.
