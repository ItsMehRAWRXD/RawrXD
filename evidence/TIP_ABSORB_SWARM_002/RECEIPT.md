# RECEIPT — TIP_ABSORB_SWARM_002

```
ASOF_UTC=2026-10-28T10:10:00Z
WORKSPACE=G:\~dev\rawrxd
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
NO_INVENT_PASS=1 LOCAL_ONLY=1
```

## Verdict

**ABSORB=PASS** — SWARM_MODEL_ORCH_001 Selector + HttpTags + SubAgent rebuilt and linked.
New tip EXE SHA minted. Prior `C4FC9AE9…` / `866E9D1B…` seals **not** rewritten.

## Sealed EXE

| Field | Value |
|------|------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331649536 |
| SHA256 | `6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2` |
| Prior tip | `C4FC9AE9A6EAC016A78B0C1BB1690B9C47A46A4B47FC51B1B807E10E14EDC43B` (`TIP_ABSORB_RELINK_001`) |

## Confirm

| Item | Status |
|------|--------|
| CMake reconfigure (HttpTags → build.ninja) | YES · EXIT=0 |
| `Win32IDE_SwarmModelSelector.cpp.obj` rebuilt | YES · 06:09:29 |
| `Win32IDE_SwarmOllamaHttpTags.cpp.obj` present | YES · 06:09:29 · **LINKED** |
| `Win32IDE_SubAgent.cpp.obj` rebuilt | YES · 06:09:44 |
| Map `appendLocalOllamaHttpTags` | YES · HttpTags.obj |
| Map `resolveSwarmModelOrchPlan` | YES · Selector.obj |
| CMAKE_BUILD_EXIT | 0 · -j2 |

## Held / non-claims

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
RUNTIME_REACHED=NOT_THIS_SEAL
G07_MET=0  (Ollama SWARM_16 9/16 ≠ tip product swarm GUI MET)
PRODUCT triad = LIVE_TETRAD / TOKEN64 / MULTI_FAMILY on 6832F439… only
```

## Seal paths

- `evidence/TIP_ABSORB_SWARM_002/LAW.txt`
- `evidence/TIP_ABSORB_SWARM_002/RECEIPT.md`
- `evidence/TIP_ABSORB_SWARM_002/sha.txt`
- `evidence/TIP_ABSORB_SWARM_002/obj_sha.txt`
- `evidence/TIP_ABSORB_SWARM_002/BUNDLE_SHA256.txt`
