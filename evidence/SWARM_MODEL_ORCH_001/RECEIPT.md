# RECEIPT — SWARM_MODEL_ORCH_001

```
ASOF_UTC=2026-10-28T09:55:00Z
WORKSPACE=G:\~dev\rawrxd
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
NO_INVENT_PASS=1 LOCAL_ONLY=1
```

## Verdict

S-002 / S-003 **SOURCE_WIRED** on product path (multi-root inventory + N=1..16 orch).
**RELINK=N**. Tip seals on `866E9D1B…` **not** invalidated. `RUNTIME_REACHED=NOT_RUN`.

## Confirm

| Item | Status |
|------|--------|
| `Win32IDE_SubAgent.cpp` exists | YES |
| `Win32IDE_SwarmModelSelector.cpp/.h` exists | YES |
| CMake WIN32IDE_SOURCES | YES (~5794 / ~5800) |
| Tip map objs (pre-fix) | YES — both `.cpp.obj` in `RawrXD-Win32IDE.map` |
| Tip EXE SHA hold | `866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F` |
| Post-fix linked into tip EXE | NO (prefer no relink) |

## Fix paths

- `src/win32app/Win32IDE_SwarmModelSelector.h`
- `src/win32app/Win32IDE_SwarmModelSelector.cpp`
- `src/win32app/Win32IDE_SwarmOllamaHttpTags.cpp` (local `/api/tags`)
- `src/win32app/Win32IDE_SubAgent.cpp` (`onSubAgentSwarm` + cancel)
- Cross-runtime: `evidence/SWARM_16_SMALL_HI_AUDIT_001` (Ollama; tip EXE=0)

## Relink

```
RELINK=N
NEW_SHA=(none)
TIP_SEALS_INVALIDATED=N
NOTE=Relink required for RUNTIME_REACHED of F1–F3; would mint new SHA and
  HELD re-run LIVE_TETRAD / TOKEN64 / MULTI_FAMILY tip covers
```

## Held

`PROMOTE=0` · `TIP_CLIMB=HOLD` · `CERTIFIED=0` · no cloud backends invented

## Seal paths

- `evidence/SWARM_MODEL_ORCH_001/LAW.txt`
- `evidence/SWARM_MODEL_ORCH_001/RECEIPT.md`
- `evidence/SWARM_MODEL_ORCH_001/MATRIX.md`
