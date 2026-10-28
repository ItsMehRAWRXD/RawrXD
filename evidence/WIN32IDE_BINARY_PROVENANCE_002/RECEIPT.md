# RECEIPT — WIN32IDE_BINARY_PROVENANCE_002

```
STATUS=HISTORICAL
SUPERSEDED_BY=WIN32IDE_BINARY_PROVENANCE_003
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
NO_REBUILD=1
NO_RELINK=1
NO_INVENT_PASS=1
FAIL_CLOSED=1
WORKSPACE=G:\~dev\rawrxd
MOTD_ACK=1
ASOF_UTC=2026-10-28T10:13:58Z
TIP_TARGET=C4FC9AE9A6EAC016A78B0C1BB1690B9C47A46A4B47FC51B1B807E10E14EDC43B
LIVE_EXE=6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2
```


## Verdict

| Gate | Result |
|------|--------|
| Tip target C4FC9AE9… on-disk | **MISMATCH** → `FAIL_CLOSED=EXE_SHA_CHANGED` |
| Full A01 bundle for C4FC9AE9… | **INCOMPLETE** |
| A01 disposition | **OPEN** |
| Rebuild/relink this mission | **NOT DONE** (sibling `TIP_ABSORB_SWARM_002` owns later link) |
| SWARM HttpTags on tip C4FC9AE9… | **GAP** (not absorbed; do not invent linked) |
| PROMOTE | **0** |

## Tip target (sealed cite only)

| Field | Value |
|-------|-------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331646464 |
| SHA256 | `C4FC9AE9A6EAC016A78B0C1BB1690B9C47A46A4B47FC51B1B807E10E14EDC43B` |
| Cite | `TIP_ABSORB_RELINK_001` |
| Prior tip | `866E9D1B…` via `WIN32IDE_BINARY_PROVENANCE_001` |

## Live disk (observe — stop gate)

| Field | Value |
|-------|-------|
| Size | 331649536 |
| SHA256 | `6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2` |
| MTIME_UTC | 2026-10-28T10:09:59Z |
| Cite | `TIP_ABSORB_SWARM_002/logs/post_exe_sha.txt` |
| SHA_MATCH tip | **0** |

## Absorbed objs (TIP_ABSORB_RELINK_001 cite)

| TU | Obj SHA256 |
|----|------------|
| ToolActionStatus | `F034F7DCAA9FA872…388BD9` |
| rawrengine_command_handlers | `8C29048D77E493D5…3D57AC` |
| AgenticComposerUX | `5653CA085CD6A059…BB2CC6` |
| command_handlers_comprehensive | `C2928C8FA0389C1F…994076` |

Live obj hashes still matched these values at observe; **not** claimed as C4FC9AE9 map attribution (EXE/map superseded).

## Camellia / Watchdog

Objs still present with prior SHAs (`49CE60B7…` / `74D03180…` / `8A0244FD…`). Live map hits exist only on **6832F439…** map — not sealed as C4FC9AE9 map.

## SWARM HttpTags

| Scope | Disposition |
|-------|-------------|
| Tip C4FC9AE9… | **GAP** — `TIP_ABSORB_RELINK_001` `SWARM_MODEL_ORCH_001=ABSENT` |
| Live 6832F439… | Obj PRESENT + map hits — sibling `TIP_ABSORB_SWARM_002` only |

## Explicit non-claims

```
A01 != MET for C4FC9AE9
LIVE map/PDB != C4FC9AE9 provenance
HttpTags != linked into C4FC9AE9
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
```

## Artifacts

- `evidence/WIN32IDE_BINARY_PROVENANCE_002/LAW.txt`
- `evidence/WIN32IDE_BINARY_PROVENANCE_002/RECEIPT.md`
- `evidence/WIN32IDE_BINARY_PROVENANCE_002/objs.txt`
- `evidence/WIN32IDE_BINARY_PROVENANCE_002/live_observe.txt`
- `evidence/WIN32IDE_BINARY_PROVENANCE_002/BUNDLE_SHA256.txt`
