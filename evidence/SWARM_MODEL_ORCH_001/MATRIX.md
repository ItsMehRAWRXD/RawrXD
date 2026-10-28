# MATRIX — SWARM_MODEL_ORCH_001

```
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 PERFECT=0
TIP_SHA_HOLD=866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F
ASOF_UTC=2026-10-28T09:55:00Z
NO_INVENT_MET=1
LOCAL_ONLY=1
RELINK=N
```

Statuses: `MET` | `OPEN` | `HELD` | `BLOCKED` | `SOURCE_WIRED`  
Rule: cite required; SOURCE_WIRED ≠ RUNTIME_REACHED ≠ PASS.

| ID | Gate | Status | Cite / note |
|----|------|--------|-------------|
| M01 | Files exist locally | **MET** | `src/win32app/Win32IDE_SubAgent.cpp` · `Win32IDE_SwarmModelSelector.{h,cpp}` |
| M02 | CMake / ninja product link list | **MET** | CMakeLists WIN32IDE_SOURCES; `_tmp_ninja_linked_srcs.txt` L842–843 |
| M03 | Tip map attribution pre-fix | **MET** | `build_win32ide_link001/bin/RawrXD-Win32IDE.map` — `enumerateSwarmModelCandidates` + SubAgent objs |
| M04 | Tip EXE on-disk this seal | **HELD** | EXE absent under link001/bin; SHA hold via provenance / LIVE_TETRAD |
| M05 | S-002 N=1..16 + maxParallel≤N | **SOURCE_WIRED** | `resolveSwarmModelOrchPlan` + `onSubAgentSwarm`; RUNTIME NOT_RUN |
| M06 | S-003 multi-root GGUF + optional local tags | **SOURCE_WIRED** | `enumerateSwarmModelCandidates`; LOCAL_ONLY_NO_OLLAMA skips tags; no cloud |
| M07 | Fail-closed empty inventory | **SOURCE_WIRED** | empty → Warning return; no fake models |
| M08 | Tip post-fix binary | **OPEN** | RELINK=N; tip still pre-fix behavior until climb |
| M09 | RUNTIME_REACHED / E2E swarm | **OPEN** | NOT_RUN |
| M10 | PROMOTE | **HELD** | PROMOTE=0 |

## Env contract (product-honest)

| Var | Role |
|-----|------|
| `RAWRXD_SWARM_N` | Task/model count 1..16 (default 4, capped by inventory) |
| `RAWRXD_SWARM_MAX_PARALLEL` | Parallelism 1..N |
| `RAWRXD_SWARM_SEQUENTIAL=1` | Force maxParallel=1 |
| `RAWRXD_SWARM_MODEL_DIR` / `RAWRXD_MODELS` / `RAWRXD_MODELS_PATH` | GGUF roots (`;` lists) |
| `LOCAL_ONLY_NO_OLLAMA` | Skip local Ollama tag append |

## Closure matrix cross-cite

`WIN32IDE_CLOSURE_MATRIX_001` S-002 / S-003 → cite this seal for SOURCE_WIRED; tip A03 remains HELD on any future SHA.
